using System.Text.Json;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Reports.Services;

public sealed class QuarantineService
{
    private readonly string _quarantineFolder;

    public QuarantineService(string? quarantineFolder = null)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        _quarantineFolder = quarantineFolder ?? Path.Combine(appData, "MiyoMacroSentinel", "quarantine");
        Directory.CreateDirectory(_quarantineFolder);
    }

    public string QuarantineFolder => _quarantineFolder;

    public async Task<string> QuarantineAsync(ScanResult result, CancellationToken cancellationToken = default)
    {
        if (!File.Exists(result.Triage.FilePath))
        {
            throw new FileNotFoundException("Original file not found.", result.Triage.FilePath);
        }

        var hash = string.IsNullOrWhiteSpace(result.Triage.Sha256) ? result.Id : result.Triage.Sha256;
        var safeName = hash + ".quarantine";
        var target = Path.Combine(_quarantineFolder, safeName);
        await using (var source = new FileStream(result.Triage.FilePath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true))
        await using (var destination = new FileStream(target, FileMode.Create, FileAccess.Write, FileShare.None, 81920, true))
        {
            await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
        }

        var metadata = new
        {
            OriginalPath = result.Triage.FilePath,
            result.Triage.FileName,
            result.Triage.Sha256,
            result.RiskScore,
            result.RiskLevel,
            QuarantinedAt = DateTimeOffset.Now
        };
        await File.WriteAllTextAsync(target + ".json", JsonSerializer.Serialize(metadata, new JsonSerializerOptions { WriteIndented = true }), cancellationToken).ConfigureAwait(false);
        return target;
    }

    public async Task RestoreAsync(string quarantinedPath, string restorePath, CancellationToken cancellationToken = default)
    {
        if (!PathSafety.IsSafeExtractionTarget(Path.GetDirectoryName(restorePath) ?? Environment.CurrentDirectory, restorePath))
        {
            throw new InvalidOperationException("Restore path is not safe.");
        }

        await using var source = new FileStream(quarantinedPath, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        await using var destination = new FileStream(restorePath, FileMode.CreateNew, FileAccess.Write, FileShare.None, 81920, true);
        await source.CopyToAsync(destination, cancellationToken).ConfigureAwait(false);
    }

    public void Delete(string quarantinedPath)
    {
        if (!PathSafety.IsSafeExtractionTarget(_quarantineFolder, quarantinedPath))
        {
            throw new InvalidOperationException("Quarantine delete path is outside quarantine folder.");
        }

        File.Delete(quarantinedPath);
        if (File.Exists(quarantinedPath + ".json"))
        {
            File.Delete(quarantinedPath + ".json");
        }
    }
}
