using System.Text.Json;
using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Core.Services;

public sealed class AppSettingsService
{
    private static readonly JsonSerializerOptions JsonOptions = new() { WriteIndented = true };
    private readonly string _settingsPath;

    public AppSettingsService(string? settingsPath = null)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var directory = Path.Combine(appData, "MiyoMacroSentinel");
        Directory.CreateDirectory(directory);
        _settingsPath = settingsPath ?? Path.Combine(directory, "settings.json");
    }

    public AppSettings Load()
    {
        try
        {
            if (!File.Exists(_settingsPath))
            {
                return CreateDefault();
            }

            var json = File.ReadAllText(_settingsPath);
            return JsonSerializer.Deserialize<AppSettings>(json) ?? CreateDefault();
        }
        catch
        {
            return CreateDefault();
        }
    }

    public void Save(AppSettings settings)
    {
        var directory = Path.GetDirectoryName(_settingsPath);
        if (!string.IsNullOrEmpty(directory))
        {
            Directory.CreateDirectory(directory);
        }

        File.WriteAllText(_settingsPath, JsonSerializer.Serialize(settings, JsonOptions));
    }

    public AnalysisOptions ToAnalysisOptions(AppSettings settings)
    {
        return new AnalysisOptions
        {
            ArchiveRecursionDepth = settings.ArchiveRecursionDepth,
            DefangIocs = settings.SafeIocDefangEnabled,
            MaxFileSizeBytes = settings.MaxFileSizeBytes,
            OleToolsEnabled = settings.OleToolsEnabled,
            ReportOutputFolder = settings.ReportOutputFolder,
            TemporaryFolderPath = settings.TemporaryFolderPath,
            YaraEnabled = settings.YaraEnabled
        };
    }

    private static AppSettings CreateDefault()
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var baseFolder = Path.Combine(appData, "MiyoMacroSentinel");
        return new AppSettings
        {
            ReportOutputFolder = Path.Combine(baseFolder, "reports"),
            TemporaryFolderPath = Path.Combine(baseFolder, "temp")
        };
    }
}
