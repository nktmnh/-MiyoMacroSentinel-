using System.Text.Json;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;
using MiyoMacroSentinel.Parsers.Services;
using MiyoMacroSentinel.Reports.Services;
using MiyoMacroSentinel.Rules.Services;

const string Version = "0.1.0";

try
{
    if (args.Length == 0 || args[0] is "-h" or "--help")
    {
        PrintHelp();
        return 0;
    }

    if (args[0].Equals("version", StringComparison.OrdinalIgnoreCase))
    {
        Console.WriteLine($"MiyoMacroSentinel {Version}");
        return 0;
    }

    if (args[0].Equals("rules", StringComparison.OrdinalIgnoreCase) && args.ElementAtOrDefault(1)?.Equals("validate", StringComparison.OrdinalIgnoreCase) == true)
    {
        var errors = await new YaraService().ValidateRulesAsync(new AnalysisOptions(), CancellationToken.None).ConfigureAwait(false);
        if (errors.Count == 0)
        {
            Console.WriteLine("Rules validated.");
            return 0;
        }

        foreach (var error in errors)
        {
            Console.Error.WriteLine(error);
        }

        return 3;
    }

    if (!args[0].Equals("scan", StringComparison.OrdinalIgnoreCase) || args.Length < 2)
    {
        PrintHelp();
        return 3;
    }

    var target = args[1];
    var recursive = args.Contains("--recursive", StringComparer.OrdinalIgnoreCase);
    var jsonPath = GetOptionValue(args, "--json");
    var csvPath = GetOptionValue(args, "--csv");
    var reportFolder = Path.Combine(Environment.CurrentDirectory, "reports");
    Directory.CreateDirectory(reportFolder);

    var scanner = new DocumentScanService();
    var exporter = new ReportExporter();
    var options = new AnalysisOptions { ReportOutputFolder = reportFolder };

    if (File.Exists(target))
    {
        var result = await scanner.ScanAsync(target, options, ConsoleProgress(), CancellationToken.None).ConfigureAwait(false);
        if (!string.IsNullOrWhiteSpace(jsonPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(jsonPath)) ?? Environment.CurrentDirectory);
            await File.WriteAllTextAsync(jsonPath, JsonSerializer.Serialize(result, new JsonSerializerOptions { WriteIndented = true })).ConfigureAwait(false);
            result.ReportPaths.Add(Path.GetFullPath(jsonPath));
        }
        else
        {
            await exporter.ExportJsonAsync(result, reportFolder).ConfigureAwait(false);
        }

        await exporter.ExportHtmlAsync(result, reportFolder, "en").ConfigureAwait(false);
        Console.WriteLine($"{result.Triage.FileName}: {result.RiskLevel} ({result.RiskScore})");
        return ExitCodeFor(result.RiskLevel);
    }

    if (Directory.Exists(target))
    {
        var files = Directory.EnumerateFiles(target, "*.*", recursive ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly).ToList();
        var results = new List<ScanResult>();
        foreach (var file in files)
        {
            var result = await scanner.ScanAsync(file, options, ConsoleProgress(), CancellationToken.None).ConfigureAwait(false);
            await exporter.ExportJsonAsync(result, reportFolder).ConfigureAwait(false);
            await exporter.ExportHtmlAsync(result, reportFolder, "en").ConfigureAwait(false);
            results.Add(result);
            Console.WriteLine($"{result.Triage.FileName}: {result.RiskLevel} ({result.RiskScore})");
        }

        if (!string.IsNullOrWhiteSpace(csvPath))
        {
            Directory.CreateDirectory(Path.GetDirectoryName(Path.GetFullPath(csvPath)) ?? Environment.CurrentDirectory);
            var tempCsv = await exporter.ExportBatchCsvAsync(results, Path.GetDirectoryName(Path.GetFullPath(csvPath)) ?? Environment.CurrentDirectory).ConfigureAwait(false);
            File.Copy(tempCsv, csvPath, true);
        }

        return results.Count == 0 ? 0 : results.Max(r => ExitCodeFor(r.RiskLevel));
    }

    Console.Error.WriteLine("Target file or folder not found.");
    return 3;
}
catch (Exception ex)
{
    Console.Error.WriteLine($"Scan error: {ex.Message}");
    return 3;
}

static string? GetOptionValue(string[] values, string option)
{
    for (var index = 0; index < values.Length - 1; index++)
    {
        if (values[index].Equals(option, StringComparison.OrdinalIgnoreCase))
        {
            return values[index + 1];
        }
    }

    return null;
}

static IProgress<ScanProgress> ConsoleProgress() => new Progress<ScanProgress>(progress =>
{
    if (progress.Stage is ScanStage.Completed or ScanStage.Failed or ScanStage.Cancelled)
    {
        Console.Error.WriteLine($"{progress.Stage}: {progress.Message}");
    }
});

static int ExitCodeFor(RiskLevel level) => level switch
{
    RiskLevel.Clean or RiskLevel.Low => 0,
    RiskLevel.Medium => 1,
    RiskLevel.High or RiskLevel.Critical => 2,
    _ => 3
};

static void PrintHelp()
{
    Console.WriteLine(
        """
        MiyoMacroSentinel CLI

        Commands:
          miyomacro scan "file.docm"
          miyomacro scan "file.docm" --json report.json
          miyomacro scan "folder" --recursive --csv results.csv
          miyomacro rules validate
          miyomacro version

        Exit codes:
          0 Clean/Low
          1 Suspicious/Medium
          2 High/Critical
          3 Scan error
        """);
}
