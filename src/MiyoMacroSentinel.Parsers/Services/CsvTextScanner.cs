using System.Text.RegularExpressions;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed partial class CsvTextScanner
{
    public async Task<ParserScanResult> ScanAsync(string filePath, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var result = new ParserScanResult();
        var text = await TextExtraction.ReadTextPrefixAsync(filePath, (int)Math.Min(options.MaxFileSizeBytes, 10 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
        result.TextArtifacts.Add(text);

        if (Path.GetExtension(filePath).Equals(".csv", StringComparison.OrdinalIgnoreCase))
        {
            ScanCsvFormulaInjection(text, result);
        }

        if (SuspiciousCommandRegex().IsMatch(text))
        {
            result.Findings.Add(new Finding
            {
                Title = "Suspicious command text",
                Severity = Severity.Medium,
                Location = Path.GetFileName(filePath),
                Evidence = EvidenceSanitizer.Truncate(SuspiciousCommandRegex().Match(text).Value),
                Explanation = "Text content references command execution tooling.",
                Recommendation = "Review context before copying or executing any command.",
                ScoreImpact = 15
            });
        }

        return result;
    }

    private static void ScanCsvFormulaInjection(string text, ParserScanResult result)
    {
        using var reader = new StringReader(text);
        var row = 0;
        while (reader.ReadLine() is { } line)
        {
            row++;
            var columns = ParseCsvLine(line);
            for (var column = 0; column < columns.Count; column++)
            {
                var cell = columns[column].TrimStart();
                if (cell.Length == 0 || cell[0] is not ('=' or '+' or '-' or '@'))
                {
                    continue;
                }

                var severity = RiskyFormulaRegex().IsMatch(cell) ? Severity.High : Severity.Medium;
                result.Findings.Add(new Finding
                {
                    Title = "CSV formula injection",
                    Severity = severity,
                    Location = $"CSV row {row}, column {column + 1}",
                    Evidence = EvidenceSanitizer.Truncate(cell),
                    Explanation = "Spreadsheet apps may evaluate cells beginning with =, +, -, or @ as formulas.",
                    Recommendation = "Open CSV in a safe viewer or neutralize leading formula characters before import.",
                    ScoreImpact = severity == Severity.High ? 25 : 20
                });
            }
        }
    }

    private static List<string> ParseCsvLine(string line)
    {
        var values = new List<string>();
        var current = new System.Text.StringBuilder();
        var inQuotes = false;
        for (var index = 0; index < line.Length; index++)
        {
            var ch = line[index];
            if (ch == '"' && index + 1 < line.Length && line[index + 1] == '"')
            {
                current.Append('"');
                index++;
                continue;
            }

            if (ch == '"')
            {
                inQuotes = !inQuotes;
                continue;
            }

            if (ch == ',' && !inQuotes)
            {
                values.Add(current.ToString());
                current.Clear();
                continue;
            }

            current.Append(ch);
        }

        values.Add(current.ToString());
        return values;
    }

    [GeneratedRegex(@"(?i)\b(?:HYPERLINK|WEBSERVICE|cmd|powershell|DDE|http://|https://|ftp://)\b", RegexOptions.Compiled)]
    private static partial Regex RiskyFormulaRegex();

    [GeneratedRegex(@"(?i)\b(?:powershell|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|schtasks)\b", RegexOptions.Compiled)]
    private static partial Regex SuspiciousCommandRegex();
}
