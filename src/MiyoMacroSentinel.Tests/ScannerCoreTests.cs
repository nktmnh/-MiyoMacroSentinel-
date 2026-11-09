using System.IO.Compression;
using System.Text;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;
using MiyoMacroSentinel.Parsers.Services;

namespace MiyoMacroSentinel.Tests;

public sealed class ScannerCoreTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "MiyoMacroSentinelTests-" + Guid.NewGuid().ToString("N"));

    public ScannerCoreTests()
    {
        Directory.CreateDirectory(_temp);
    }

    [Fact]
    public void MagicByteDetection_DetectsPdfOleAndZip()
    {
        Assert.Equal("PDF Document", FileTriageService.DetectMagic("%PDF-1.7"u8.ToArray(), ".pdf").RealType);
        Assert.Equal("OLE Office Document", FileTriageService.DetectMagic([0xD0, 0xCF, 0x11, 0xE0, 0, 0, 0, 0], ".doc").RealType);
        Assert.Equal("Office OpenXML", FileTriageService.DetectMagic([0x50, 0x4B, 0x03, 0x04], ".docx").RealType);
    }

    [Fact]
    public async Task ExtensionMismatchDetection_FlagsFakePdfOle()
    {
        var path = Path.Combine(_temp, "invoice.pdf");
        await File.WriteAllBytesAsync(path, [0xD0, 0xCF, 0x11, 0xE0, 0, 0, 0, 0]);

        var result = await new FileTriageService().AnalyzeAsync(path, new AnalysisOptions(), null, CancellationToken.None);

        Assert.True(result.ExtensionMismatch);
        Assert.Contains(result.Warnings, warning => warning.Title == "Extension mismatch");
    }

    [Fact]
    public void HiddenUnicodeDetection_FindsBidiAndZeroWidth()
    {
        var findings = new HiddenUnicodeScanner().Scan("invoice\u202Ecod.exe\u200B", "name");

        Assert.Contains(findings, finding => finding.CodePoint == "U+202E");
        Assert.Contains(findings, finding => finding.CodePoint == "U+200B");
    }

    [Fact]
    public void IocExtractor_ExtractsAndDefangsIndicators()
    {
        var iocs = new IocExtractor().Extract("Contact a@b.com then visit http://example.com/a and run powershell -enc AAAA", "body");

        Assert.Contains(iocs, i => i.Type == IocType.Email);
        Assert.Contains(iocs, i => i.Type == IocType.Url && i.DisplayValue.Contains("hxxp://", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(iocs, i => i.Type == IocType.Command);
    }

    [Fact]
    public void RiskScoring_MapsMacroAndCommandToHighRisk()
    {
        var result = new ScanResult
        {
            Triage = new FileTriageResult { FileName = "sample.docm" },
            Findings =
            [
                new Finding { Title = "Macro exists", Severity = Severity.Medium, ScoreImpact = 20 },
                new Finding { Title = "AutoExec", Severity = Severity.High, ScoreImpact = 25 },
                new Finding { Title = "PowerShell", Severity = Severity.High, ScoreImpact = 30 }
            ]
        };

        new RiskScoringEngine().Score(result);

        Assert.Equal(RiskLevel.High, result.RiskLevel);
        Assert.InRange(result.RiskScore, 61, 80);
    }

    [Fact]
    public void StaticDecoder_DecodesBase64AndPowerShellEncodedCommand()
    {
        var decoder = new StaticDecoder();
        var encodedText = Convert.ToBase64String(Encoding.UTF8.GetBytes("powershell test"));
        var encodedCommand = Convert.ToBase64String(Encoding.Unicode.GetBytes("Write-Host hello"));

        Assert.Equal("powershell test", decoder.TryDecodeBase64(encodedText));
        Assert.Equal("Write-Host hello", decoder.DecodePowerShellEncodedCommand(encodedCommand));
    }

    [Fact]
    public async Task CsvFormulaInjectionDetection_FlagsRiskyCell()
    {
        var path = Path.Combine(_temp, "formula.csv");
        await File.WriteAllTextAsync(path, "name,formula\nbob,=HYPERLINK(\"http://example.com\")");

        var result = await new CsvTextScanner().ScanAsync(path, new AnalysisOptions(), CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.Title == "CSV formula injection");
    }

    [Fact]
    public async Task ArchiveZipSlipPrevention_BlocksTraversalEntry()
    {
        var path = Path.Combine(_temp, "slip.zip");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("../evil.txt");
            await using var stream = entry.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("evil"));
        }

        var result = await new ArchiveScanner().ScanAsync(path, new AnalysisOptions { YaraEnabled = false }, 0, null, CancellationToken.None);

        Assert.Contains(result.Findings, finding => finding.Title == "Archive zip-slip path blocked");
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
