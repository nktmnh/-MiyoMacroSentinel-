using System.Diagnostics;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Rules.Services;

public sealed class YaraService
{
    private readonly SafeLogger _logger;

    public YaraService(SafeLogger? logger = null)
    {
        _logger = logger ?? new SafeLogger();
    }

    public async Task<(List<YaraMatchInfo> Matches, List<Finding> Findings)> ScanAsync(string filePath, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var matches = new List<YaraMatchInfo>();
        var findings = new List<Finding>();

        if (!options.YaraEnabled)
        {
            findings.Add(new Finding
            {
                Title = "YARA disabled",
                Severity = Severity.Info,
                Location = "YARA",
                Explanation = "YARA scanning is disabled in settings.",
                Recommendation = "Enable YARA and provide yara.exe for local rule matching.",
                ScoreImpact = 0
            });
            return (matches, findings);
        }

        var yaraPath = ResolveYaraPath(options);
        var rulesPath = ResolveRulesPath(options);
        if (string.IsNullOrWhiteSpace(yaraPath) || !File.Exists(yaraPath))
        {
            findings.Add(new Finding
            {
                Title = "YARA engine unavailable",
                Severity = Severity.Info,
                Location = "YARA",
                Evidence = "engines/yara/yara.exe not found",
                Explanation = "The scan continued without YARA because the optional sidecar engine is not installed.",
                Recommendation = "Place yara.exe in engines/yara to enable local YARA matching.",
                ScoreImpact = 0
            });
            return (matches, findings);
        }

        var ruleFiles = Directory.Exists(rulesPath)
            ? Directory.EnumerateFiles(rulesPath, "*.yar", SearchOption.AllDirectories).Concat(Directory.EnumerateFiles(rulesPath, "*.yara", SearchOption.AllDirectories)).ToList()
            : [];

        if (ruleFiles.Count == 0)
        {
            findings.Add(new Finding
            {
                Title = "No YARA rules available",
                Severity = Severity.Info,
                Location = "YARA",
                Explanation = "No .yar/.yara files were found in the configured rules folder.",
                Recommendation = "Add local rules before enabling YARA for deeper matching.",
                ScoreImpact = 0
            });
            return (matches, findings);
        }

        foreach (var ruleFile in ruleFiles)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await RunYaraAsync(yaraPath, ruleFile, filePath, TimeSpan.FromSeconds(Math.Min(30, options.ScanTimeoutSeconds)), cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(result.Error))
            {
                findings.Add(new Finding
                {
                    Title = "YARA rule error",
                    Severity = Severity.Low,
                    Location = Path.GetFileName(ruleFile),
                    Evidence = EvidenceSanitizer.Truncate(result.Error),
                    Explanation = "A local YARA rule failed validation or execution.",
                    Recommendation = "Validate the rule in Rule Manager before using it for triage.",
                    ScoreImpact = 0
                });
            }

            foreach (var line in result.Output.Split(Environment.NewLine, StringSplitOptions.RemoveEmptyEntries))
            {
                var ruleName = line.Split(' ', StringSplitOptions.RemoveEmptyEntries).FirstOrDefault() ?? Path.GetFileNameWithoutExtension(ruleFile);
                var severity = InferSeverity(ruleFile, ruleName);
                matches.Add(new YaraMatchInfo
                {
                    RuleName = ruleName,
                    Namespace = Path.GetFileName(ruleFile),
                    Severity = severity,
                    Metadata = $"source={Path.GetFileName(ruleFile)}",
                    MatchedStrings = EvidenceSanitizer.Truncate(line, 300)
                });

                findings.Add(new Finding
                {
                    Title = "YARA rule matched",
                    Severity = severity,
                    Location = "YARA",
                    Evidence = EvidenceSanitizer.Truncate(line),
                    Explanation = "A local YARA rule matched this file.",
                    Recommendation = "Review the matched rule metadata and evidence before making a final decision.",
                    ScoreImpact = severity switch
                    {
                        Severity.Critical => 40,
                        Severity.High => 30,
                        Severity.Medium => 20,
                        Severity.Low => 10,
                        _ => 0
                    }
                });
            }
        }

        return (matches, findings);
    }

    public List<RuleDescriptor> ListRules(string? rulesPath = null)
    {
        var root = string.IsNullOrWhiteSpace(rulesPath) ? ResolveRulesPath(new AnalysisOptions()) : rulesPath;
        if (!Directory.Exists(root))
        {
            return [];
        }

        return Directory.EnumerateFiles(root, "*.yar", SearchOption.AllDirectories)
            .Concat(Directory.EnumerateFiles(root, "*.yara", SearchOption.AllDirectories))
            .Select(path => new RuleDescriptor
            {
                Name = Path.GetFileNameWithoutExtension(path),
                Path = path,
                Enabled = true,
                Severity = InferSeverity(path, Path.GetFileNameWithoutExtension(path)),
                LastModified = File.GetLastWriteTime(path)
            })
            .OrderBy(rule => rule.Name)
            .ToList();
    }

    public async Task<IReadOnlyList<string>> ValidateRulesAsync(AnalysisOptions options, CancellationToken cancellationToken)
    {
        var errors = new List<string>();
        var yaraPath = ResolveYaraPath(options);
        if (string.IsNullOrWhiteSpace(yaraPath) || !File.Exists(yaraPath))
        {
            errors.Add("YARA engine unavailable: engines/yara/yara.exe not found.");
            return errors;
        }

        foreach (var rule in ListRules(options.YaraRulesPath))
        {
            var result = await RunYaraAsync(yaraPath, rule.Path, rule.Path, TimeSpan.FromSeconds(15), cancellationToken).ConfigureAwait(false);
            if (!string.IsNullOrWhiteSpace(result.Error))
            {
                errors.Add($"{rule.Name}: {EvidenceSanitizer.Truncate(result.Error, 300)}");
            }
        }

        return errors;
    }

    public static string ResolveRulesPath(AnalysisOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.YaraRulesPath))
        {
            return options.YaraRulesPath;
        }

        return ResolveFromKnownRoots("rules");
    }

    private static string? ResolveYaraPath(AnalysisOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.YaraExecutablePath))
        {
            return options.YaraExecutablePath;
        }

        var root = ResolveFromKnownRoots(Path.Combine("engines", "yara"));
        return Path.Combine(root, "yara.exe");
    }

    private static string ResolveFromKnownRoots(string relative)
    {
        var candidates = new List<string>
        {
            Path.Combine(Environment.CurrentDirectory, relative),
            Path.Combine(AppContext.BaseDirectory, relative)
        };

        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null)
        {
            candidates.Add(Path.Combine(directory.FullName, relative));
            directory = directory.Parent;
        }

        return candidates.FirstOrDefault(Directory.Exists) ?? candidates[0];
    }

    private async Task<(string Output, string Error)> RunYaraAsync(string yaraPath, string rulePath, string filePath, TimeSpan timeout, CancellationToken cancellationToken)
    {
        try
        {
            using var process = new Process();
            process.StartInfo = new ProcessStartInfo
            {
                FileName = yaraPath,
                Arguments = $"-m -s \"{rulePath}\" \"{filePath}\"",
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            process.Start();
            var outputTask = process.StandardOutput.ReadToEndAsync(cancellationToken);
            var errorTask = process.StandardError.ReadToEndAsync(cancellationToken);
            var completed = await Task.WhenAny(process.WaitForExitAsync(cancellationToken), Task.Delay(timeout, cancellationToken)).ConfigureAwait(false);
            if (completed is not Task waitTask || !waitTask.IsCompletedSuccessfully)
            {
                TryKill(process);
                return ("", "YARA timeout.");
            }

            var output = await outputTask.ConfigureAwait(false);
            var error = await errorTask.ConfigureAwait(false);
            return (output, error);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.Error(ex, "YARA execution failed");
            return ("", ex.Message);
        }
    }

    private static void TryKill(Process process)
    {
        try
        {
            if (!process.HasExited)
            {
                process.Kill(true);
            }
        }
        catch
        {
            // Best-effort cleanup for an optional sidecar tool.
        }
    }

    private static Severity InferSeverity(string rulePath, string ruleName)
    {
        var text = "";
        try
        {
            text = File.Exists(rulePath) ? File.ReadAllText(rulePath) : "";
        }
        catch
        {
            // Ignore metadata read errors and use name-based fallback.
        }

        var combined = $"{ruleName} {text}";
        if (combined.Contains("critical", StringComparison.OrdinalIgnoreCase))
        {
            return Severity.Critical;
        }

        if (combined.Contains("high", StringComparison.OrdinalIgnoreCase) || combined.Contains("powershell", StringComparison.OrdinalIgnoreCase))
        {
            return Severity.High;
        }

        if (combined.Contains("medium", StringComparison.OrdinalIgnoreCase) || combined.Contains("macro", StringComparison.OrdinalIgnoreCase))
        {
            return Severity.Medium;
        }

        if (combined.Contains("low", StringComparison.OrdinalIgnoreCase))
        {
            return Severity.Low;
        }

        return Severity.Info;
    }
}

public sealed class RuleDescriptor
{
    public string Name { get; set; } = "";
    public string Path { get; set; } = "";
    public bool Enabled { get; set; }
    public Severity Severity { get; set; } = Severity.Info;
    public DateTime LastModified { get; set; }
}
