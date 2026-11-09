using System.IO.Compression;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed class ArchiveScanner
{
    private static readonly HashSet<string> SupportedNestedExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".doc", ".xls", ".ppt", ".dot", ".xlt", ".pps", ".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm",
        ".dotm", ".xltm", ".ppsm", ".pdf", ".rtf", ".txt", ".csv", ".html", ".xml", ".odt", ".ods", ".odp", ".zip"
    };

    public async Task<ParserScanResult> ScanAsync(
        string filePath,
        AnalysisOptions options,
        int depth,
        Func<string, int, CancellationToken, Task<ScanResult>>? nestedScanner,
        CancellationToken cancellationToken)
    {
        var result = new ParserScanResult();
        if (!Path.GetExtension(filePath).Equals(".zip", StringComparison.OrdinalIgnoreCase))
        {
            result.Findings.Add(new Finding
            {
                Title = "Archive sidecar unsupported",
                Severity = Severity.Info,
                Location = Path.GetFileName(filePath),
                Evidence = Path.GetExtension(filePath),
                Explanation = "Built-in archive scanning supports ZIP. RAR/7Z require optional sidecar tooling.",
                Recommendation = "Extract unsupported archives only in a controlled environment.",
                ScoreImpact = 0
            });
            return result;
        }

        var tempDirectory = PathSafety.CreateIsolatedTempDirectory(options.TemporaryFolderPath);
        long extractedTotal = 0;
        try
        {
            using var archive = ZipFile.OpenRead(filePath);
            foreach (var entry in archive.Entries.ToList())
            {
                cancellationToken.ThrowIfCancellationRequested();
                var entryName = entry.FullName.Replace('\\', '/');
                result.TextArtifacts.Add(entryName);

                if (entryName.EndsWith("/", StringComparison.Ordinal))
                {
                    continue;
                }

                if (entryName.Contains("..", StringComparison.Ordinal) || Path.IsPathRooted(entryName))
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Archive zip-slip path blocked",
                        Severity = Severity.High,
                        Location = entryName,
                        Evidence = EvidenceSanitizer.Truncate(entryName),
                        Explanation = "The archive contains a path that could escape the extraction folder.",
                        Recommendation = "Do not extract this archive outside an isolated analysis folder.",
                        ScoreImpact = 30
                    });
                    continue;
                }

                if (IsExecutableLike(entryName))
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Executable-like file inside archive",
                        Severity = Severity.High,
                        Location = entryName,
                        Evidence = EvidenceSanitizer.Truncate(entryName),
                        Explanation = "Archives containing executables or scripts can be used for malware delivery.",
                        Recommendation = "Do not execute extracted files.",
                        ScoreImpact = 25
                    });
                }

                if (LooksDoubleExtension(entryName))
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Double extension inside archive",
                        Severity = Severity.Medium,
                        Location = entryName,
                        Evidence = EvidenceSanitizer.Truncate(entryName),
                        Explanation = "Double extensions can disguise the actual file type.",
                        Recommendation = "Review the real file type before opening.",
                        ScoreImpact = 15
                    });
                }

                extractedTotal += entry.Length;
                if (extractedTotal > options.MaxExtractedArchiveBytes)
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Archive extraction limit reached",
                        Severity = Severity.Medium,
                        Location = Path.GetFileName(filePath),
                        Evidence = $"{extractedTotal:N0} bytes",
                        Explanation = "Extraction stopped to protect against zip bombs or excessive disk usage.",
                        Recommendation = "Analyze large archives on a dedicated workstation.",
                        ScoreImpact = 10
                    });
                    break;
                }

                var extension = Path.GetExtension(entryName);
                if (nestedScanner is null || depth >= options.ArchiveRecursionDepth || !SupportedNestedExtensions.Contains(extension))
                {
                    continue;
                }

                var target = Path.Combine(tempDirectory, entryName);
                if (!PathSafety.IsSafeExtractionTarget(tempDirectory, target))
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Archive extraction path rejected",
                        Severity = Severity.High,
                        Location = entryName,
                        Evidence = EvidenceSanitizer.Truncate(target),
                        Explanation = "Archive extraction was blocked because the target path escapes the temp folder.",
                        Recommendation = "Do not manually extract this archive.",
                        ScoreImpact = 30
                    });
                    continue;
                }

                Directory.CreateDirectory(Path.GetDirectoryName(target) ?? tempDirectory);
                try
                {
                    entry.ExtractToFile(target, true);
                    var nested = await nestedScanner(target, depth + 1, cancellationToken).ConfigureAwait(false);
                    if (nested.RiskLevel is not RiskLevel.Clean && nested.Findings.Any(f => f.ScoreImpact > 0))
                    {
                        result.Findings.Add(new Finding
                        {
                            Title = "Suspicious nested file in archive",
                            Severity = nested.RiskLevel switch
                            {
                                RiskLevel.Critical => Severity.Critical,
                                RiskLevel.High => Severity.High,
                                RiskLevel.Medium => Severity.Medium,
                                _ => Severity.Low
                            },
                            Location = entryName,
                            Evidence = $"{nested.RiskLevel} score {nested.RiskScore}",
                            Explanation = "A supported file inside the archive produced suspicious scan results.",
                            Recommendation = "Do not extract or open nested files until reviewed.",
                            ScoreImpact = Math.Min(30, nested.RiskScore / 2)
                        });
                    }
                }
                catch (InvalidDataException)
                {
                    result.PasswordProtected = true;
                    result.Findings.Add(new Finding
                    {
                        Title = "Password-protected or unreadable ZIP entry",
                        Severity = Severity.Low,
                        Location = entryName,
                        Explanation = "The archive entry could not be extracted. It may be encrypted or corrupted.",
                        Recommendation = "Request an unprotected archive if business use is expected.",
                        ScoreImpact = 10
                    });
                }
            }
        }
        catch (InvalidDataException ex)
        {
            result.Corrupted = true;
            result.Findings.Add(new Finding
            {
                Title = "Corrupted ZIP archive",
                Severity = Severity.Medium,
                Location = Path.GetFileName(filePath),
                Evidence = EvidenceSanitizer.Truncate(ex.Message),
                Explanation = "The archive structure is malformed or unreadable.",
                Recommendation = "Do not extract malformed archives on a production workstation.",
                ScoreImpact = 10
            });
        }
        finally
        {
            try
            {
                Directory.Delete(tempDirectory, true);
            }
            catch
            {
                // Temp cleanup is best effort; failures are reported by OS cleanup later.
            }
        }

        return result;
    }

    private static bool IsExecutableLike(string entryName)
    {
        var extension = Path.GetExtension(entryName);
        return extension.Equals(".exe", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".dll", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".scr", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".bat", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".cmd", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".ps1", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".vbs", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".js", StringComparison.OrdinalIgnoreCase) ||
               extension.Equals(".hta", StringComparison.OrdinalIgnoreCase);
    }

    private static bool LooksDoubleExtension(string entryName)
    {
        var fileName = Path.GetFileName(entryName);
        var first = Path.GetExtension(fileName);
        var second = Path.GetExtension(Path.GetFileNameWithoutExtension(fileName));
        return !string.IsNullOrEmpty(first) && !string.IsNullOrEmpty(second);
    }
}
