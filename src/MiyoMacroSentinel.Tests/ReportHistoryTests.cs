using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Reports.Services;

namespace MiyoMacroSentinel.Tests;

public sealed class ReportHistoryTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "MiyoMacroSentinelReports-" + Guid.NewGuid().ToString("N"));

    public ReportHistoryTests()
    {
        Directory.CreateDirectory(_temp);
    }

    [Fact]
    public async Task ReportExporter_CreatesJsonHtmlAndIocCsv()
    {
        var result = SampleResult();
        var exporter = new ReportExporter();

        var json = await exporter.ExportJsonAsync(result, _temp);
        var html = await exporter.ExportHtmlAsync(result, _temp, "en");
        var csv = await exporter.ExportIocCsvAsync(result, _temp);

        Assert.True(File.Exists(json));
        Assert.True(File.Exists(html));
        Assert.True(File.Exists(csv));
    }

    [Fact]
    public async Task ScanHistoryRepository_SavesAndReadsRecord()
    {
        var db = Path.Combine(_temp, "history.sqlite");
        var repository = new ScanHistoryRepository(db);
        var result = SampleResult();

        await repository.SaveAsync(result);
        var records = await repository.SearchAsync("sample");

        Assert.Single(records);
        Assert.Equal(RiskLevel.High, records[0].RiskLevel);
    }

    private static ScanResult SampleResult()
    {
        return new ScanResult
        {
            CompletedAt = DateTimeOffset.Now,
            Triage = new FileTriageResult
            {
                FileName = "sample.docm",
                FilePath = @"C:\sample.docm",
                RealFileType = "Office OpenXML",
                Sha256 = new string('A', 64)
            },
            RiskLevel = RiskLevel.High,
            RiskScore = 75,
            ExecutiveSummary = "Sample high risk file.",
            Findings =
            [
                new Finding
                {
                    Title = "Auto-execution macro detected",
                    Severity = Severity.High,
                    Evidence = "AutoOpen",
                    Location = "macro",
                    Explanation = "Runs automatically.",
                    Recommendation = "Do not enable macros.",
                    ScoreImpact = 25
                }
            ],
            Iocs =
            [
                new Ioc { Type = IocType.Url, Original = "http://example.com", DisplayValue = "hxxp://example[.]com", Location = "macro" }
            ]
        };
    }

    public void Dispose()
    {
        try
        {
            Directory.Delete(_temp, true);
        }
        catch
        {
            // Best effort test cleanup.
        }
    }
}
