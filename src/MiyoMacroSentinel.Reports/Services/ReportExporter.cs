using System.Globalization;
using System.Text;
using System.Text.Json;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Reports.Services;

public sealed class ReportExporter
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };

    public async Task<string> ExportJsonAsync(ScanResult result, string outputFolder, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(outputFolder);
        var path = Path.Combine(outputFolder, BuildSafeReportName(result, ".json"));
        var json = JsonSerializer.Serialize(result, JsonOptions);
        await File.WriteAllTextAsync(path, json, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        result.ReportPaths.Add(path);
        return path;
    }

    public async Task<string> ExportHtmlAsync(ScanResult result, string outputFolder, string language = "vi", CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(outputFolder);
        var path = Path.Combine(outputFolder, BuildSafeReportName(result, ".html"));
        var html = BuildHtml(result, language);
        await File.WriteAllTextAsync(path, html, Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        result.ReportPaths.Add(path);
        return path;
    }

    public async Task<string> ExportIocCsvAsync(ScanResult result, string outputFolder, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(outputFolder);
        var path = Path.Combine(outputFolder, BuildSafeReportName(result, "-iocs.csv"));
        var builder = new StringBuilder();
        builder.AppendLine("Type,DisplayValue,Original,Location,Notes");
        foreach (var ioc in result.Iocs)
        {
            builder.AppendLine(string.Join(",", Csv(ioc.Type.ToString()), Csv(ioc.DisplayValue), Csv(ioc.Original), Csv(ioc.Location), Csv(ioc.Notes)));
        }

        await File.WriteAllTextAsync(path, builder.ToString(), Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        result.ReportPaths.Add(path);
        return path;
    }

    public async Task<string> ExportBatchCsvAsync(IEnumerable<ScanResult> results, string outputFolder, CancellationToken cancellationToken = default)
    {
        Directory.CreateDirectory(outputFolder);
        var path = Path.Combine(outputFolder, $"batch-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.csv");
        var builder = new StringBuilder();
        builder.AppendLine("FileName,FilePath,SHA256,FileType,ScanTime,RiskScore,RiskLevel,Findings");
        foreach (var result in results)
        {
            builder.AppendLine(string.Join(",",
                Csv(result.Triage.FileName),
                Csv(result.Triage.FilePath),
                Csv(result.Triage.Sha256),
                Csv(result.Triage.RealFileType),
                Csv(result.CompletedAt.ToString("O", CultureInfo.InvariantCulture)),
                Csv(result.RiskScore.ToString(CultureInfo.InvariantCulture)),
                Csv(result.RiskLevel.ToString()),
                Csv(string.Join("; ", result.Findings.Take(5).Select(f => f.Title)))));
        }

        await File.WriteAllTextAsync(path, builder.ToString(), Encoding.UTF8, cancellationToken).ConfigureAwait(false);
        return path;
    }

    private static string BuildHtml(ScanResult result, string language)
    {
        var vi = language.Equals("vi", StringComparison.OrdinalIgnoreCase);
        var title = vi ? "Bao cao quet an toan tai lieu" : "Document Safety Scan Report";
        var generated = vi ? "Thoi gian quet" : "Scan time";
        var recommendations = vi ? "Khuyen nghi" : "Recommendations";
        var limitations = vi ? "Gioi han" : "Limitations";
        var technical = vi ? "Chi tiet ky thuat" : "Technical Details";

        var builder = new StringBuilder();
        builder.AppendLine("<!doctype html><html lang=\"" + (vi ? "vi" : "en") + "\"><head><meta charset=\"utf-8\"><title>MiyoMacroSentinel Report</title>");
        builder.AppendLine("<style>body{font-family:Segoe UI,Arial,sans-serif;background:#0b1220;color:#e5f2ff;margin:0;padding:32px}main{max-width:1180px;margin:auto}.hero{border:1px solid #1d3b56;background:#111b2e;padding:24px;border-radius:8px}.badge{display:inline-block;padding:6px 10px;border-radius:6px;background:#123d5a;color:#67e8f9;font-weight:700}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:12px;margin:18px 0}.card{border:1px solid #1d3b56;border-radius:8px;background:#0f1a2b;padding:16px}table{width:100%;border-collapse:collapse}.table-wrap{overflow:auto}th,td{border-bottom:1px solid #1d3b56;padding:8px;text-align:left;vertical-align:top}th{color:#67e8f9}.sev-Critical{color:#ff7a90}.sev-High{color:#ffb86b}.sev-Medium{color:#facc15}.sev-Low{color:#93c5fd}.sev-Info{color:#a7f3d0}code{white-space:pre-wrap;color:#bfdbfe}</style></head><body><main>");
        builder.AppendLine("<section class=\"hero\"><h1>MiyoMacroSentinel</h1><p>" + EvidenceSanitizer.Html(title) + "</p><span class=\"badge\">" + EvidenceSanitizer.Html(result.RiskLevel.ToString()) + " / " + result.RiskScore + "</span><p>" + EvidenceSanitizer.Html(result.ExecutiveSummary) + "</p></section>");
        builder.AppendLine("<section class=\"grid\">");
        AddCard(builder, "File", result.Triage.FileName);
        AddCard(builder, "SHA256", result.Triage.Sha256);
        AddCard(builder, "Type", result.Triage.RealFileType);
        AddCard(builder, generated, result.CompletedAt.ToString("yyyy-MM-dd HH:mm:ss zzz", CultureInfo.InvariantCulture));
        builder.AppendLine("</section>");

        builder.AppendLine("<section class=\"card\"><h2>" + technical + "</h2><div class=\"table-wrap\"><table><tr><th>Finding</th><th>Severity</th><th>Evidence</th><th>Location</th><th>Explanation</th><th>Recommendation</th></tr>");
        foreach (var finding in result.Findings)
        {
            builder.Append("<tr><td>").Append(EvidenceSanitizer.Html(finding.Title)).Append("</td><td class=\"sev-").Append(finding.Severity).Append("\">")
                .Append(finding.Severity).Append("</td><td><code>").Append(EvidenceSanitizer.Html(finding.Evidence)).Append("</code></td><td>")
                .Append(EvidenceSanitizer.Html(finding.Location)).Append("</td><td>").Append(EvidenceSanitizer.Html(finding.Explanation)).Append("</td><td>")
                .Append(EvidenceSanitizer.Html(finding.Recommendation)).AppendLine("</td></tr>");
        }

        builder.AppendLine("</table></div></section>");

        builder.AppendLine("<section class=\"grid\"><div class=\"card\"><h2>IOCs</h2><ul>");
        foreach (var ioc in result.Iocs.Take(80))
        {
            builder.Append("<li><strong>").Append(ioc.Type).Append("</strong>: <code>").Append(EvidenceSanitizer.Html(ioc.DisplayValue)).AppendLine("</code></li>");
        }

        builder.AppendLine("</ul></div><div class=\"card\"><h2>Macro</h2>");
        builder.Append("<p>Exists: ").Append(result.MacroAnalysis.MacroExists ? "Yes" : "No").Append("</p><p>AutoExec: ").Append(result.MacroAnalysis.AutoExecFound ? "Yes" : "No").Append("</p><p>")
            .Append(EvidenceSanitizer.Html(result.MacroAnalysis.RiskExplanation)).AppendLine("</p></div></section>");

        builder.AppendLine("<section class=\"grid\"><div class=\"card\"><h2>" + recommendations + "</h2><ul>");
        foreach (var item in result.Recommendations)
        {
            builder.Append("<li>").Append(EvidenceSanitizer.Html(item)).AppendLine("</li>");
        }

        builder.AppendLine("</ul></div><div class=\"card\"><h2>" + limitations + "</h2><ul>");
        foreach (var item in result.Limitations)
        {
            builder.Append("<li>").Append(EvidenceSanitizer.Html(item)).AppendLine("</li>");
        }

        builder.AppendLine("</ul></div></section></main></body></html>");
        return builder.ToString();
    }

    private static void AddCard(StringBuilder builder, string label, string value)
    {
        builder.Append("<div class=\"card\"><strong>").Append(EvidenceSanitizer.Html(label)).Append("</strong><p><code>")
            .Append(EvidenceSanitizer.Html(value)).AppendLine("</code></p></div>");
    }

    private static string BuildSafeReportName(ScanResult result, string suffix)
    {
        var baseName = string.Join("_", Path.GetFileNameWithoutExtension(result.Triage.FileName).Split(Path.GetInvalidFileNameChars(), StringSplitOptions.RemoveEmptyEntries));
        if (string.IsNullOrWhiteSpace(baseName))
        {
            baseName = "scan";
        }

        var hash = string.IsNullOrWhiteSpace(result.Triage.Sha256) ? result.Id[..8] : result.Triage.Sha256[..12];
        return $"{baseName}-{DateTimeOffset.Now:yyyyMMdd-HHmmss}-{hash}{suffix}";
    }

    private static string Csv(string value)
    {
        value ??= "";
        return "\"" + value.Replace("\"", "\"\"", StringComparison.Ordinal) + "\"";
    }
}
