using System.Text.RegularExpressions;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed partial class PdfDocumentScanner
{
    public async Task<ParserScanResult> ScanAsync(string filePath, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var result = new ParserScanResult();
        var bytes = await TextExtraction.ReadBytesPrefixAsync(filePath, (int)Math.Min(options.MaxFileSizeBytes, 20 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
        var text = TextExtraction.DecodeBestEffort(bytes);
        result.TextArtifacts.Add(text);

        AddIfContains(result, text, "/JavaScript", "Suspicious PDF JavaScript", Severity.High, "PDF JavaScript can execute in vulnerable or permissive PDF readers.", 25);
        AddIfContains(result, text, "/JS", "Suspicious PDF JavaScript shorthand", Severity.High, "PDF JS action indicator detected.", 25);
        AddIfContains(result, text, "/OpenAction", "PDF OpenAction", Severity.High, "OpenAction can trigger behavior when the PDF is opened.", 25);
        AddIfContains(result, text, "/Launch", "PDF Launch action", Severity.High, "Launch actions can attempt to open external files or commands.", 30);
        AddIfContains(result, text, "/EmbeddedFile", "PDF embedded file", Severity.Medium, "PDF contains an embedded file stream.", 20);
        AddIfContains(result, text, "/AcroForm", "PDF AcroForm", Severity.Low, "Interactive forms can contain actions or scripts.", 5);
        AddIfContains(result, text, "/XFA", "PDF XFA form", Severity.Medium, "XFA forms have a history of security-sensitive behavior.", 10);
        AddIfContains(result, text, "/URI", "PDF external URI", Severity.Medium, "PDF references external URI actions.", 10);
        AddIfContains(result, text, "/ObjStm", "PDF object streams", Severity.Low, "Object streams can make manual PDF analysis harder.", 5);

        if (HighEntropyRegex().IsMatch(text))
        {
            result.Findings.Add(new Finding
            {
                Title = "High entropy PDF stream indicator",
                Severity = Severity.Medium,
                Location = "PDF",
                Evidence = "stream data",
                Explanation = "High entropy streams can indicate compression, encryption, or embedded binary content.",
                Recommendation = "Review with a dedicated PDF analysis tool if other findings are present.",
                ScoreImpact = 10
            });
        }

        if (text.Contains("MZ", StringComparison.Ordinal) || text.Contains("TVqQAAMAAAAEAAAA", StringComparison.Ordinal))
        {
            result.Findings.Add(new Finding
            {
                Title = "Embedded executable-like content in PDF",
                Severity = Severity.Critical,
                Location = "PDF",
                Evidence = "MZ/PE marker",
                Explanation = "The PDF contains bytes or text resembling an executable header.",
                Recommendation = "Do not open; escalate for controlled analysis.",
                ScoreImpact = 40
            });
        }

        return result;
    }

    private static void AddIfContains(ParserScanResult result, string text, string indicator, string title, Severity severity, string explanation, int score)
    {
        if (!text.Contains(indicator, StringComparison.OrdinalIgnoreCase))
        {
            return;
        }

        result.Findings.Add(new Finding
        {
            Title = title,
            Severity = severity,
            Location = "PDF",
            Evidence = indicator,
            Explanation = explanation,
            Recommendation = "Open only in a hardened PDF reader after analyst review.",
            ScoreImpact = score
        });
    }

    [GeneratedRegex(@"stream[\s\S]{0,40}[A-Za-z0-9+/]{120,}={0,2}", RegexOptions.Compiled)]
    private static partial Regex HighEntropyRegex();
}
