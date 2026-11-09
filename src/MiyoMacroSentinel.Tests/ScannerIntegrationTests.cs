using System.IO.Compression;
using System.Text;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Parsers.Services;

namespace MiyoMacroSentinel.Tests;

public sealed class ScannerIntegrationTests : IDisposable
{
    private readonly string _temp = Path.Combine(Path.GetTempPath(), "MiyoMacroSentinelIntegration-" + Guid.NewGuid().ToString("N"));
    private readonly DocumentScanService _scanner = new();
    private readonly AnalysisOptions _options;

    public ScannerIntegrationTests()
    {
        Directory.CreateDirectory(_temp);
        _options = new AnalysisOptions
        {
            YaraEnabled = false,
            TemporaryFolderPath = Path.Combine(_temp, "temp"),
            ArchiveRecursionDepth = 2
        };
    }

    [Fact]
    public async Task ScanCleanDocx_CompletesWithoutMacro()
    {
        var path = Path.Combine(_temp, "clean.docx");
        CreateOpenXml(path, "word/document.xml", "<w:document xmlns:w=\"w\"><w:body><w:p>Hello</w:p></w:body></w:document>");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Equal("Office OpenXML", result.Triage.RealFileType);
        Assert.False(result.MacroAnalysis.MacroExists);
        Assert.True(result.RiskLevel is RiskLevel.Clean or RiskLevel.Low);
    }

    [Fact]
    public async Task ScanDocmMacro_DetectsAutoExecAndPowerShell()
    {
        var path = Path.Combine(_temp, "macro.docm");
        CreateOpenXml(path, "word/vbaProject.bin", "Sub AutoOpen()\nCreateObject(\"WScript.Shell\").Run \"powershell -enc AAAA\"\nEnd Sub");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.True(result.MacroAnalysis.MacroExists);
        Assert.True(result.MacroAnalysis.AutoExecFound);
        Assert.True(result.RiskLevel is RiskLevel.High or RiskLevel.Critical);
    }

    [Fact]
    public async Task ScanXlsxWithoutMacro_RemainsLowRisk()
    {
        var path = Path.Combine(_temp, "sheet.xlsx");
        CreateOpenXml(path, "xl/workbook.xml", "<workbook><sheet name=\"Sheet1\" /></workbook>");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.False(result.MacroAnalysis.MacroExists);
        Assert.True(result.RiskScore <= 20);
    }

    [Fact]
    public async Task ScanXlsmWithMacroIndicators_FindsMacroKeywords()
    {
        var path = Path.Combine(_temp, "sheet.xlsm");
        CreateOpenXml(path, "xl/vbaProject.bin", "Private Sub Workbook_Open()\nShell \"cmd.exe /c calc\"\nEnd Sub");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Contains(result.Findings, finding => finding.Title.Contains("Auto-execution", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(result.Findings, finding => finding.Title.Contains("execution keyword", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task ScanPdfWithJavaScriptIndicator_FlagsHighRisk()
    {
        var path = Path.Combine(_temp, "script.pdf");
        await File.WriteAllTextAsync(path, "%PDF-1.7\n1 0 obj << /OpenAction << /S /JavaScript /JS (app.alert(1)) >> >>");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Contains(result.Findings, finding => finding.Title.Contains("JavaScript", StringComparison.OrdinalIgnoreCase));
        Assert.True(result.RiskLevel is RiskLevel.Medium or RiskLevel.High or RiskLevel.Critical);
    }

    [Fact]
    public async Task ScanTxtWithHiddenUnicode_FindsHiddenCharacter()
    {
        var path = Path.Combine(_temp, "hidden.txt");
        await File.WriteAllTextAsync(path, "pay\u200Bload http://example.com");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.NotEmpty(result.HiddenCharacters);
        Assert.Contains(result.Iocs, ioc => ioc.Type == IocType.Url);
    }

    [Fact]
    public async Task ScanCsvFormulaInjection_FlagsFormula()
    {
        var path = Path.Combine(_temp, "danger.csv");
        await File.WriteAllTextAsync(path, "user,formula\nalice,=WEBSERVICE(\"http://example.com\")");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Contains(result.Findings, finding => finding.Title == "CSV formula injection");
    }

    [Fact]
    public async Task ScanZipContainingSuspiciousDocument_FlagsNestedFile()
    {
        var path = Path.Combine(_temp, "nested.zip");
        using (var archive = ZipFile.Open(path, ZipArchiveMode.Create))
        {
            var entry = archive.CreateEntry("payload.csv");
            await using var stream = entry.Open();
            await stream.WriteAsync(Encoding.UTF8.GetBytes("a,b\nx,=HYPERLINK(\"http://example.com\")"));
        }

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Contains(result.Findings, finding => finding.Title == "Suspicious nested file in archive");
    }

    [Fact]
    public async Task ScanCorruptedZip_DoesNotCrash()
    {
        var path = Path.Combine(_temp, "corrupted.zip");
        await File.WriteAllBytesAsync(path, [0x50, 0x4B, 0x03, 0x04, 0x01, 0x02]);

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Contains(result.Findings, finding => finding.Title.Contains("Corrupted", StringComparison.OrdinalIgnoreCase) || finding.Title.Contains("Malformed", StringComparison.OrdinalIgnoreCase) || finding.Title == "Scan error");
    }

    [Fact]
    public async Task MissingYaraEngine_IsGracefulFinding()
    {
        var path = Path.Combine(_temp, "plain.txt");
        await File.WriteAllTextAsync(path, "hello");

        var result = await _scanner.ScanAsync(path, new AnalysisOptions { YaraEnabled = true, YaraExecutablePath = Path.Combine(_temp, "missing-yara.exe") });

        Assert.Contains(result.Findings, finding => finding.Title == "YARA engine unavailable");
    }

    [Fact]
    public async Task CancelScanMidway_ReturnsCancelledResult()
    {
        var path = Path.Combine(_temp, "cancel.txt");
        await File.WriteAllTextAsync(path, new string('A', 100_000));
        using var cts = new CancellationTokenSource();
        cts.Cancel();

        var result = await _scanner.ScanAsync(path, _options, cancellationToken: cts.Token);

        Assert.Contains(result.Findings, finding => finding.Title == "Scan cancelled");
    }

    [Fact]
    public async Task UnicodeFilename_DoesNotCrashAndFlagsUnicode()
    {
        var path = Path.Combine(_temp, "invoice\u202Ecod.exe.txt");
        await File.WriteAllTextAsync(path, "hello");

        var result = await _scanner.ScanAsync(path, _options);

        Assert.Contains(result.Findings, finding => finding.Title == "Unicode trick in file name");
    }

    private static void CreateOpenXml(string path, string mainEntry, string mainContent)
    {
        using var archive = ZipFile.Open(path, ZipArchiveMode.Create);
        WriteEntry(archive, "[Content_Types].xml", "<Types xmlns=\"http://schemas.openxmlformats.org/package/2006/content-types\"><Default Extension=\"xml\" ContentType=\"application/xml\" /></Types>");
        WriteEntry(archive, "_rels/.rels", "<Relationships xmlns=\"http://schemas.openxmlformats.org/package/2006/relationships\"></Relationships>");
        WriteEntry(archive, mainEntry, mainContent);
    }

    private static void WriteEntry(ZipArchive archive, string name, string content)
    {
        var entry = archive.CreateEntry(name);
        using var stream = entry.Open();
        using var writer = new StreamWriter(stream, Encoding.UTF8);
        writer.Write(content);
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
