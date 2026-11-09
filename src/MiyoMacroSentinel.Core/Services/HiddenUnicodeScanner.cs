using System.Globalization;
using System.Text;
using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Core.Services;

public sealed class HiddenUnicodeScanner
{
    private static readonly Dictionary<int, (string Name, string Explanation)> SuspiciousCharacters = new()
    {
        [0x200B] = ("Zero-width space", "Can hide text boundaries or split indicators."),
        [0x200C] = ("Zero-width non-joiner", "Can visually alter text without obvious display."),
        [0x200D] = ("Zero-width joiner", "Can join characters invisibly and confuse reviewers."),
        [0x2060] = ("Word joiner", "Can hide separation between suspicious tokens."),
        [0x202E] = ("Right-to-left override", "Can reverse the visible order of file extensions or URLs."),
        [0x202D] = ("Left-to-right override", "Can alter visual ordering in mixed-direction text."),
        [0x2066] = ("Left-to-right isolate", "Can hide bidirectional text manipulation."),
        [0x2067] = ("Right-to-left isolate", "Can hide bidirectional text manipulation."),
        [0x2068] = ("First strong isolate", "Can hide bidirectional text manipulation."),
        [0x2069] = ("Pop directional isolate", "Can hide bidirectional text manipulation."),
        [0x00A0] = ("Non-breaking space", "Can disguise spacing in names, formulas, or links."),
        [0x00AD] = ("Soft hyphen", "Can hide or split suspicious words.")
    };

    public List<HiddenCharacterFinding> Scan(string text, string location, int maxFindings = 200)
    {
        var findings = new List<HiddenCharacterFinding>();
        if (string.IsNullOrEmpty(text))
        {
            return findings;
        }

        for (var index = 0; index < text.Length && findings.Count < maxFindings; index++)
        {
            var codePoint = char.ConvertToUtf32(text, index);
            var charLength = char.IsSurrogatePair(text, index) ? 2 : 1;
            if (charLength == 2)
            {
                index++;
            }

            if (!IsSuspicious(codePoint, out var name, out var explanation))
            {
                continue;
            }

            findings.Add(new HiddenCharacterFinding
            {
                CharacterName = name,
                CodePoint = "U+" + codePoint.ToString("X4", CultureInfo.InvariantCulture),
                Position = index - (charLength - 1),
                ContextBefore = EvidenceSanitizer.Truncate(GetContext(text, index - charLength, -1), 80),
                ContextAfter = EvidenceSanitizer.Truncate(GetContext(text, index + 1, 1), 80),
                Location = location,
                Explanation = explanation,
                SuggestedNormalizedText = EvidenceSanitizer.Truncate(RemoveSuspiciousUnicode(text), 160)
            });
        }

        if (ContainsMixedScriptConfusable(text) && findings.Count < maxFindings)
        {
            findings.Add(new HiddenCharacterFinding
            {
                CharacterName = "Mixed script confusable text",
                CodePoint = "mixed-script",
                Position = 0,
                Location = location,
                ContextBefore = "",
                ContextAfter = EvidenceSanitizer.Truncate(text, 120),
                Explanation = "Mixed Latin/Cyrillic/Greek characters can be used in homoglyph phishing.",
                SuggestedNormalizedText = EvidenceSanitizer.Truncate(RemoveSuspiciousUnicode(text), 160)
            });
        }

        return findings;
    }

    public static bool ContainsSuspiciousUnicode(string text)
    {
        if (string.IsNullOrEmpty(text))
        {
            return false;
        }

        for (var index = 0; index < text.Length; index++)
        {
            var codePoint = char.ConvertToUtf32(text, index);
            if (char.IsSurrogatePair(text, index))
            {
                index++;
            }

            if (IsSuspicious(codePoint, out _, out _))
            {
                return true;
            }
        }

        return ContainsMixedScriptConfusable(text);
    }

    public static string RemoveSuspiciousUnicode(string text)
    {
        var builder = new StringBuilder(text.Length);
        foreach (var rune in text.EnumerateRunes())
        {
            if (!IsSuspicious(rune.Value, out _, out _))
            {
                builder.Append(rune);
            }
        }

        return builder.ToString().Normalize(NormalizationForm.FormKC);
    }

    private static bool IsSuspicious(int codePoint, out string name, out string explanation)
    {
        if (SuspiciousCharacters.TryGetValue(codePoint, out var known))
        {
            name = known.Name;
            explanation = known.Explanation;
            return true;
        }

        if (codePoint is >= 0x0000 and <= 0x001F and not 0x0009 and not 0x000A and not 0x000D)
        {
            name = "Control character";
            explanation = "Control characters can hide data or confuse parsers.";
            return true;
        }

        if (codePoint == 0x007F)
        {
            name = "DEL control character";
            explanation = "DEL is non-printing and can confuse text processing.";
            return true;
        }

        name = "";
        explanation = "";
        return false;
    }

    private static string GetContext(string text, int start, int direction)
    {
        if (direction < 0)
        {
            var safeStart = Math.Max(0, start - 24);
            var length = Math.Max(0, start - safeStart + 1);
            return length == 0 ? "" : text.Substring(safeStart, length);
        }

        if (start >= text.Length)
        {
            return "";
        }

        var safeLength = Math.Min(24, text.Length - start);
        return text.Substring(start, safeLength);
    }

    private static bool ContainsMixedScriptConfusable(string text)
    {
        var hasLatin = false;
        var hasCyrillic = false;
        var hasGreek = false;

        foreach (var ch in text)
        {
            if (ch is >= 'A' and <= 'Z' or >= 'a' and <= 'z')
            {
                hasLatin = true;
            }
            else if (ch is >= '\u0400' and <= '\u04FF')
            {
                hasCyrillic = true;
            }
            else if (ch is >= '\u0370' and <= '\u03FF')
            {
                hasGreek = true;
            }
        }

        return hasLatin && (hasCyrillic || hasGreek);
    }
}
