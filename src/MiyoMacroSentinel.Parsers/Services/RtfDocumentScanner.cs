using System.Text.RegularExpressions;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed partial class RtfDocumentScanner
{
    public async Task<ParserScanResult> ScanAsync(string filePath, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var result = new ParserScanResult();
        var text = await TextExtraction.ReadTextPrefixAsync(filePath, (int)Math.Min(options.MaxFileSizeBytes, 10 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
        result.TextArtifacts.Add(text);

        AddIfMatch(result, text, ObjDataRegex(), "RTF embedded object data", Severity.High, "RTF objdata can contain embedded OLE or binary payloads.", 25);
        AddIfMatch(result, text, ExternalLinkRegex(), "RTF external link", Severity.Medium, "RTF content references an external URL.", 10);
        AddIfMatch(result, text, ControlWordRegex(), "Suspicious RTF control word", Severity.Medium, "RTF contains control words commonly associated with embedded objects.", 15);
        AddIfMatch(result, text, LongHexRegex(), "Long RTF hex blob", Severity.Medium, "Long hex blobs can contain embedded binary content.", 20);

        if (!text.StartsWith(@"{\rtf", StringComparison.OrdinalIgnoreCase))
        {
            result.Corrupted = true;
            result.Findings.Add(new Finding
            {
                Title = "Malformed RTF structure",
                Severity = Severity.Low,
                Location = "RTF",
                Evidence = "Missing RTF header",
                Explanation = "The file extension or magic bytes suggest RTF, but the structure looks malformed.",
                Recommendation = "Request a clean file from the sender.",
                ScoreImpact = 10
            });
        }

        return result;
    }

    private static void AddIfMatch(ParserScanResult result, string text, Regex regex, string title, Severity severity, string explanation, int score)
    {
        var match = regex.Match(text);
        if (!match.Success)
        {
            return;
        }

        result.Findings.Add(new Finding
        {
            Title = title,
            Severity = severity,
            Location = "RTF",
            Evidence = EvidenceSanitizer.Truncate(match.Value),
            Explanation = explanation,
            Recommendation = "Analyze the RTF in an isolated environment if business use is required.",
            ScoreImpact = score
        });
    }

    [GeneratedRegex(@"(?i)\\objdata", RegexOptions.Compiled)]
    private static partial Regex ObjDataRegex();

    [GeneratedRegex(@"(?i)https?://[^\s{}\\]+", RegexOptions.Compiled)]
    private static partial Regex ExternalLinkRegex();

    [GeneratedRegex(@"(?i)\\(?:object|objclass|objw|objh|datastore|result)", RegexOptions.Compiled)]
    private static partial Regex ControlWordRegex();

    [GeneratedRegex(@"(?i)(?:[0-9a-f]{2}\s*){256,}", RegexOptions.Compiled)]
    private static partial Regex LongHexRegex();
}
