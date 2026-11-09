using System.Net;
using System.Text;
using System.Text.RegularExpressions;
using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Core.Services;

public sealed partial class StaticDecoder
{
    public List<DecodedArtifact> Analyze(string text, string location, AnalysisOptions options)
    {
        var artifacts = new List<DecodedArtifact>();
        if (string.IsNullOrWhiteSpace(text))
        {
            return artifacts;
        }

        DecodePowerShellEncodedCommand(text, location, options, artifacts);
        DecodeBase64(text, location, options, artifacts);
        DecodeHex(text, location, options, artifacts);
        DecodeUrlHtmlAndUnicodeEscapes(text, location, options, artifacts);
        DecodeVbaChr(text, location, options, artifacts);
        DecodeStrReverse(text, location, options, artifacts);
        DecodeStringConcatenation(text, location, options, artifacts);

        return artifacts.Take(80).ToList();
    }

    public string? DecodePowerShellEncodedCommand(string encoded)
    {
        try
        {
            var bytes = Convert.FromBase64String(encoded);
            return Encoding.Unicode.GetString(bytes);
        }
        catch
        {
            return null;
        }
    }

    public string? TryDecodeBase64(string encoded)
    {
        try
        {
            var bytes = Convert.FromBase64String(PadBase64(encoded));
            var text = LooksUtf16(bytes) ? Encoding.Unicode.GetString(bytes) : Encoding.UTF8.GetString(bytes);
            return IsMostlyPrintable(text) ? text : null;
        }
        catch
        {
            return null;
        }
    }

    private static void DecodePowerShellEncodedCommand(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        foreach (Match match in EncodedCommandRegex().Matches(text))
        {
            var encoded = match.Groups[1].Value;
            var decoded = new StaticDecoder().DecodePowerShellEncodedCommand(encoded);
            AddArtifact(artifacts, "PowerShell EncodedCommand UTF-16LE", encoded, decoded, location, options);
        }
    }

    private static void DecodeBase64(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        foreach (Match match in Base64Regex().Matches(text))
        {
            var decoded = new StaticDecoder().TryDecodeBase64(match.Value);
            AddArtifact(artifacts, "Base64", match.Value, decoded, location, options);
        }
    }

    private static void DecodeHex(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        foreach (Match match in HexBlobRegex().Matches(text))
        {
            try
            {
                var hex = match.Value.Replace("0x", "", StringComparison.OrdinalIgnoreCase).Replace("\\x", "", StringComparison.OrdinalIgnoreCase);
                if (hex.Length % 2 != 0)
                {
                    continue;
                }

                var bytes = Convert.FromHexString(hex);
                var decoded = Encoding.UTF8.GetString(bytes);
                AddArtifact(artifacts, "Hex", match.Value, IsMostlyPrintable(decoded) ? decoded : null, location, options);
            }
            catch
            {
                // Invalid hex blobs are ignored; decoded content is never executed.
            }
        }
    }

    private static void DecodeUrlHtmlAndUnicodeEscapes(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        if (text.Contains('%', StringComparison.Ordinal))
        {
            AddArtifact(artifacts, "URL decode", EvidenceSanitizer.Truncate(text, 180), Uri.UnescapeDataString(text), location, options);
        }

        if (text.Contains('&', StringComparison.Ordinal))
        {
            AddArtifact(artifacts, "HTML entity decode", EvidenceSanitizer.Truncate(text, 180), WebUtility.HtmlDecode(text), location, options);
        }

        if (text.Contains("\\u", StringComparison.OrdinalIgnoreCase))
        {
            var decoded = UnicodeEscapeRegex().Replace(text, match => ((char)Convert.ToInt32(match.Groups[1].Value, 16)).ToString());
            AddArtifact(artifacts, "Unicode escape", EvidenceSanitizer.Truncate(text, 180), decoded, location, options);
        }
    }

    private static void DecodeVbaChr(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        foreach (Match match in VbaChrSequenceRegex().Matches(text))
        {
            var builder = new StringBuilder();
            foreach (Match number in VbaChrNumberRegex().Matches(match.Value))
            {
                if (int.TryParse(number.Groups[1].Value, out var codePoint) && codePoint is >= 0 and <= 0x10FFFF)
                {
                    builder.Append(char.ConvertFromUtf32(codePoint));
                }
            }

            AddArtifact(artifacts, "VBA Chr/ChrW reconstruction", match.Value, builder.ToString(), location, options);
        }
    }

    private static void DecodeStrReverse(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        foreach (Match match in StrReverseRegex().Matches(text))
        {
            var value = match.Groups[1].Value;
            var chars = value.ToCharArray();
            Array.Reverse(chars);
            AddArtifact(artifacts, "VBA StrReverse", match.Value, new string(chars), location, options);
        }
    }

    private static void DecodeStringConcatenation(string text, string location, AnalysisOptions options, List<DecodedArtifact> artifacts)
    {
        foreach (Match match in StringConcatRegex().Matches(text))
        {
            var values = QuotedStringRegex().Matches(match.Value).Select(m => m.Groups[1].Value);
            AddArtifact(artifacts, "Simple string concatenation", match.Value, string.Concat(values), location, options);
        }
    }

    private static void AddArtifact(List<DecodedArtifact> artifacts, string decoder, string source, string? decoded, string location, AnalysisOptions options)
    {
        if (string.IsNullOrWhiteSpace(decoded) || decoded == source || !IsMostlyPrintable(decoded))
        {
            return;
        }

        var maxChars = Math.Max(128, options.MaxDecodedStringBytes / 2);
        var truncated = decoded.Length > maxChars;
        artifacts.Add(new DecodedArtifact
        {
            Decoder = decoder,
            SourceSnippet = EvidenceSanitizer.Truncate(source, 180),
            DecodedText = EvidenceSanitizer.Truncate(decoded, Math.Min(maxChars, 2000)),
            Location = location,
            Truncated = truncated
        });
    }

    private static string PadBase64(string value)
    {
        var remainder = value.Length % 4;
        return remainder == 0 ? value : value.PadRight(value.Length + (4 - remainder), '=');
    }

    private static bool LooksUtf16(byte[] bytes) => bytes.Length > 4 && bytes.Where((_, i) => i % 2 == 1).Take(20).Count(b => b == 0) > 8;

    private static bool IsMostlyPrintable(string text)
    {
        if (string.IsNullOrWhiteSpace(text))
        {
            return false;
        }

        var sample = text.Take(512).ToArray();
        var printable = sample.Count(ch => !char.IsControl(ch) || ch is '\r' or '\n' or '\t');
        return printable / (double)sample.Length > 0.85;
    }

    [GeneratedRegex(@"(?i)(?:-enc|-encodedcommand)\s+([A-Za-z0-9+/=]{8,})", RegexOptions.Compiled)]
    private static partial Regex EncodedCommandRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.Compiled)]
    private static partial Regex Base64Regex();

    [GeneratedRegex(@"(?i)(?:0x|\\x)?(?:[0-9a-f]{2}){20,}", RegexOptions.Compiled)]
    private static partial Regex HexBlobRegex();

    [GeneratedRegex(@"\\u([0-9a-fA-F]{4})", RegexOptions.Compiled)]
    private static partial Regex UnicodeEscapeRegex();

    [GeneratedRegex(@"(?i)(?:ChrW?\(\s*\d+\s*\)\s*&\s*)+ChrW?\(\s*\d+\s*\)", RegexOptions.Compiled)]
    private static partial Regex VbaChrSequenceRegex();

    [GeneratedRegex(@"(?i)ChrW?\(\s*(\d+)\s*\)", RegexOptions.Compiled)]
    private static partial Regex VbaChrNumberRegex();

    [GeneratedRegex(@"(?i)StrReverse\(\s*""([^""]{3,240})""\s*\)", RegexOptions.Compiled)]
    private static partial Regex StrReverseRegex();

    [GeneratedRegex(@"""[^""]{1,120}""(?:\s*&\s*""[^""]{1,120}""){1,10}", RegexOptions.Compiled)]
    private static partial Regex StringConcatRegex();

    [GeneratedRegex(@"""([^""]*)""", RegexOptions.Compiled)]
    private static partial Regex QuotedStringRegex();
}
