using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed class OleDocumentScanner
{
    private readonly MacroAnalyzer _macroAnalyzer = new();

    public async Task<ParserScanResult> ScanAsync(string filePath, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var result = new ParserScanResult();
        var bytes = await TextExtraction.ReadBytesPrefixAsync(filePath, (int)Math.Min(options.MaxFileSizeBytes, 20 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
        var strings = TextExtraction.ExtractAsciiAndUnicodeStrings(bytes);
        result.TextArtifacts.Add(strings);

        if (strings.Contains("VBA", StringComparison.OrdinalIgnoreCase) ||
            strings.Contains("_VBA_PROJECT", StringComparison.OrdinalIgnoreCase) ||
            strings.Contains("Attribut VB_", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(new Finding
            {
                Title = "OLE VBA storage indicators",
                Severity = Severity.High,
                Location = "OLE streams",
                Evidence = "VBA/_VBA_PROJECT",
                Explanation = "The legacy Office compound file contains VBA storage indicators.",
                Recommendation = "Do not enable macros unless the sender and macro purpose are verified.",
                ScoreImpact = 20
            });

            var macro = _macroAnalyzer.Analyze(strings, "OLE macro strings");
            result.MacroAnalysis = macro.Summary;
            result.Findings.AddRange(macro.Findings);
        }

        if (strings.Contains("Package", StringComparison.OrdinalIgnoreCase) || strings.Contains("Ole10Native", StringComparison.OrdinalIgnoreCase))
        {
            result.EmbeddedObjects.Add(new EmbeddedObjectInfo
            {
                Name = "Ole10Native/Package",
                Location = "OLE streams",
                ObjectType = "Embedded OLE object",
                ExecutableLike = strings.Contains(".exe", StringComparison.OrdinalIgnoreCase)
            });
            result.Findings.Add(new Finding
            {
                Title = "Embedded OLE object indicator",
                Severity = Severity.Medium,
                Location = "OLE streams",
                Evidence = "Ole10Native/Package",
                Explanation = "Legacy Office files can embed object packages or executable-like content.",
                Recommendation = "Extract embedded objects only inside a controlled analysis environment.",
                ScoreImpact = 20
            });
        }

        if (strings.Contains("EncryptedPackage", StringComparison.OrdinalIgnoreCase))
        {
            result.PasswordProtected = true;
            result.Findings.Add(new Finding
            {
                Title = "Encrypted or protected OLE document",
                Severity = Severity.Low,
                Location = "OLE streams",
                Evidence = "EncryptedPackage",
                Explanation = "Protected content cannot be fully inspected without credentials.",
                Recommendation = "Request a clean unprotected sample if business use is expected.",
                ScoreImpact = 10
            });
        }

        if (options.OleToolsEnabled)
        {
            result.Findings.Add(new Finding
            {
                Title = "oletools sidecar not configured",
                Severity = Severity.Info,
                Location = "OLE parser",
                Explanation = "Built-in static OLE string inspection ran. Optional oletools integration is available when a sidecar engine is installed.",
                Recommendation = "Install oletools in engines/oletools for deeper macro extraction.",
                ScoreImpact = 0
            });
        }

        return result;
    }
}
