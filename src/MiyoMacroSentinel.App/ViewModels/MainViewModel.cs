using System.Collections.ObjectModel;
using System.Diagnostics;
using System.IO;
using System.Text.Json;
using System.Windows;
using Microsoft.Win32;
using MiyoMacroSentinel.App.Services;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;
using MiyoMacroSentinel.Parsers.Services;
using MiyoMacroSentinel.Reports.Services;
using MiyoMacroSentinel.Rules.Services;
using WinForms = System.Windows.Forms;

namespace MiyoMacroSentinel.App.ViewModels;

public sealed class MainViewModel : ObservableObject
{
    private readonly AppSettingsService _settingsService = new();
    private readonly SafeLogger _logger = new();
    private readonly DocumentScanService _scanner;
    private readonly ReportExporter _reports = new();
    private readonly ScanHistoryRepository _history = new();
    private readonly QuarantineService _quarantine = new();
    private readonly YaraService _rules;
    private AppSettings _settings;
    private CancellationTokenSource? _scanCancellation;
    private string _selectedPage = "Dashboard";
    private string _selectedFilePath = "";
    private string _batchFolder = "";
    private string _fileTypeFilter = "*.*";
    private bool _recursiveBatch = true;
    private bool _isScanning;
    private int _progressValue;
    private string _currentStage = "";
    private string _statusMessage = "";
    private ScanResult? _currentResult;
    private DashboardStats _stats = new();

    public MainViewModel()
    {
        _settings = _settingsService.Load();
        Strings.SetLanguage(_settings.Language);
        _scanner = new DocumentScanService(_logger);
        _rules = new YaraService(_logger);
        Pages =
        [
            new("Dashboard", Strings["Dashboard"]),
            new("SingleFileScan", Strings["SingleFileScan"]),
            new("BatchScan", Strings["BatchScan"]),
            new("ScanHistory", Strings["ScanHistory"]),
            new("RuleManager", Strings["RuleManager"]),
            new("Quarantine", Strings["Quarantine"]),
            new("Reports", Strings["Reports"]),
            new("Settings", Strings["Settings"]),
            new("About", Strings["About"])
        ];

        BrowseFileCommand = new RelayCommand(_ => BrowseFile());
        ScanFileCommand = new AsyncRelayCommand(_ => ScanSelectedFileAsync(), _ => !IsScanning && File.Exists(SelectedFilePath));
        CancelScanCommand = new RelayCommand(_ => _scanCancellation?.Cancel(), _ => IsScanning);
        BrowseBatchFolderCommand = new RelayCommand(_ => BrowseBatchFolder());
        RunBatchCommand = new AsyncRelayCommand(_ => RunBatchAsync(), _ => !IsScanning && Directory.Exists(BatchFolder));
        ExportBatchCommand = new AsyncRelayCommand(_ => ExportBatchAsync(), _ => BatchResults.Count > 0);
        ToggleLanguageCommand = new RelayCommand(_ => ToggleLanguage());
        RefreshHistoryCommand = new AsyncRelayCommand(_ => RefreshHistoryAsync());
        ValidateRulesCommand = new AsyncRelayCommand(_ => ValidateRulesAsync());
        QuarantineCurrentCommand = new AsyncRelayCommand(_ => QuarantineCurrentAsync(), _ => CurrentResult is { HasHighRisk: true });
        OpenReportCommand = new RelayCommand(parameter => OpenPath(parameter?.ToString()), parameter => parameter is string path && File.Exists(path));
        SaveSettingsCommand = new RelayCommand(_ => SaveSettings());

        _ = InitializeAsync();
    }

    public LocalizedStrings Strings { get; } = new();
    public ObservableCollection<NavItem> Pages { get; }
    public ObservableCollection<Finding> Findings { get; } = [];
    public ObservableCollection<Ioc> Iocs { get; } = [];
    public ObservableCollection<HiddenCharacterFinding> HiddenCharacters { get; } = [];
    public ObservableCollection<DecodedArtifact> DecodedArtifacts { get; } = [];
    public ObservableCollection<ScanHistoryRecord> HistoryRecords { get; } = [];
    public ObservableCollection<RuleDescriptor> Rules { get; } = [];
    public ObservableCollection<ScanResult> BatchResults { get; } = [];
    public ObservableCollection<string> ReportPaths { get; } = [];
    public ObservableCollection<string> RuleValidationMessages { get; } = [];

    public RelayCommand BrowseFileCommand { get; }
    public AsyncRelayCommand ScanFileCommand { get; }
    public RelayCommand CancelScanCommand { get; }
    public RelayCommand BrowseBatchFolderCommand { get; }
    public AsyncRelayCommand RunBatchCommand { get; }
    public AsyncRelayCommand ExportBatchCommand { get; }
    public RelayCommand ToggleLanguageCommand { get; }
    public AsyncRelayCommand RefreshHistoryCommand { get; }
    public AsyncRelayCommand ValidateRulesCommand { get; }
    public AsyncRelayCommand QuarantineCurrentCommand { get; }
    public RelayCommand OpenReportCommand { get; }
    public RelayCommand SaveSettingsCommand { get; }

    public string SelectedPage
    {
        get => _selectedPage;
        set => SetProperty(ref _selectedPage, value);
    }

    public string SelectedFilePath
    {
        get => _selectedFilePath;
        set
        {
            if (SetProperty(ref _selectedFilePath, value))
            {
                ScanFileCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public string BatchFolder
    {
        get => _batchFolder;
        set
        {
            if (SetProperty(ref _batchFolder, value))
            {
                RunBatchCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public string FileTypeFilter
    {
        get => _fileTypeFilter;
        set => SetProperty(ref _fileTypeFilter, value);
    }

    public bool RecursiveBatch
    {
        get => _recursiveBatch;
        set => SetProperty(ref _recursiveBatch, value);
    }

    public bool IsScanning
    {
        get => _isScanning;
        set
        {
            if (SetProperty(ref _isScanning, value))
            {
                ScanFileCommand.RaiseCanExecuteChanged();
                RunBatchCommand.RaiseCanExecuteChanged();
                CancelScanCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public int ProgressValue
    {
        get => _progressValue;
        set => SetProperty(ref _progressValue, value);
    }

    public string CurrentStage
    {
        get => _currentStage;
        set => SetProperty(ref _currentStage, value);
    }

    public string StatusMessage
    {
        get => _statusMessage;
        set => SetProperty(ref _statusMessage, value);
    }

    public ScanResult? CurrentResult
    {
        get => _currentResult;
        set
        {
            if (SetProperty(ref _currentResult, value))
            {
                OnPropertyChanged(nameof(HasResult));
                OnPropertyChanged(nameof(CurrentRiskBadge));
                QuarantineCurrentCommand.RaiseCanExecuteChanged();
            }
        }
    }

    public bool HasResult => CurrentResult is not null;

    public string CurrentRiskBadge => CurrentResult is null ? "No scan" : $"{CurrentResult.RiskLevel} / {CurrentResult.RiskScore}";

    public DashboardStats Stats
    {
        get => _stats;
        set => SetProperty(ref _stats, value);
    }

    public AppSettings Settings => _settings;

    public string ReportFolder => string.IsNullOrWhiteSpace(_settings.ReportOutputFolder)
        ? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "MiyoMacroSentinel", "reports")
        : _settings.ReportOutputFolder;

    public string QuarantineFolder => _quarantine.QuarantineFolder;

    public async Task InitializeAsync()
    {
        await _history.InitializeAsync();
        await RefreshHistoryAsync();
        LoadRules();
        StatusMessage = "Ready";
    }

    public void AcceptDroppedFiles(string[] files)
    {
        if (files.Length == 0)
        {
            return;
        }

        SelectedFilePath = files[0];
        SelectedPage = "SingleFileScan";
    }

    private void BrowseFile()
    {
        var dialog = new Microsoft.Win32.OpenFileDialog
        {
            Title = "Select document to scan",
            Filter = "Supported files|*.doc;*.xls;*.ppt;*.dot;*.xlt;*.pps;*.docx;*.xlsx;*.pptx;*.docm;*.xlsm;*.pptm;*.dotm;*.xltm;*.ppsm;*.pdf;*.rtf;*.txt;*.csv;*.html;*.xml;*.odt;*.ods;*.odp;*.zip;*.rar;*.7z|All files|*.*"
        };

        if (dialog.ShowDialog() == true)
        {
            SelectedFilePath = dialog.FileName;
        }
    }

    private void BrowseBatchFolder()
    {
        using var dialog = new WinForms.FolderBrowserDialog { Description = "Select folder for batch scan", UseDescriptionForTitle = true };
        if (dialog.ShowDialog() == WinForms.DialogResult.OK)
        {
            BatchFolder = dialog.SelectedPath;
        }
    }

    private async Task ScanSelectedFileAsync()
    {
        if (!File.Exists(SelectedFilePath))
        {
            StatusMessage = "File not found.";
            return;
        }

        await ScanAndPersistAsync(SelectedFilePath);
    }

    private async Task<ScanResult> ScanAndPersistAsync(string path)
    {
        _scanCancellation = new CancellationTokenSource();
        IsScanning = true;
        ProgressValue = 0;
        CurrentStage = "Starting";
        StatusMessage = "Scanning...";

        try
        {
            var progress = new Progress<ScanProgress>(p =>
            {
                ProgressValue = p.Percent;
                CurrentStage = $"{p.Stage}: {p.Message}";
            });

            var result = await _scanner.ScanAsync(path, _settingsService.ToAnalysisOptions(_settings), progress, _scanCancellation.Token);
            await ExportReportsForResultAsync(result, _scanCancellation.Token);
            await _history.SaveAsync(result, _scanCancellation.Token);
            ApplyCurrentResult(result);
            await RefreshHistoryAsync();
            StatusMessage = $"Scan complete: {result.RiskLevel} ({result.RiskScore})";
            return result;
        }
        finally
        {
            IsScanning = false;
            _scanCancellation?.Dispose();
            _scanCancellation = null;
        }
    }

    private async Task ExportReportsForResultAsync(ScanResult result, CancellationToken cancellationToken)
    {
        Directory.CreateDirectory(ReportFolder);
        await _reports.ExportJsonAsync(result, ReportFolder, cancellationToken);
        await _reports.ExportHtmlAsync(result, ReportFolder, _settings.Language, cancellationToken);
        await _reports.ExportIocCsvAsync(result, ReportFolder, cancellationToken);
    }

    private void ApplyCurrentResult(ScanResult result)
    {
        CurrentResult = result;
        Replace(Findings, result.Findings);
        Replace(Iocs, result.Iocs);
        Replace(HiddenCharacters, result.HiddenCharacters);
        Replace(DecodedArtifacts, result.DecodedArtifacts);
        Replace(ReportPaths, result.ReportPaths);
        OnPropertyChanged(nameof(CurrentRiskBadge));
    }

    private async Task RunBatchAsync()
    {
        if (!Directory.Exists(BatchFolder))
        {
            StatusMessage = "Batch folder not found.";
            return;
        }

        _scanCancellation = new CancellationTokenSource();
        IsScanning = true;
        BatchResults.Clear();
        var files = EnumerateBatchFiles().Take(1000).ToList();
        var completed = 0;
        var results = new List<ScanResult>();
        var gate = new SemaphoreSlim(Math.Max(1, Math.Min(Environment.ProcessorCount / 2, 4)));

        try
        {
            var tasks = files.Select(async file =>
            {
                await gate.WaitAsync(_scanCancellation.Token).ConfigureAwait(false);
                try
                {
                    var progress = new Progress<ScanProgress>(_ => { });
                    var result = await _scanner.ScanAsync(file, _settingsService.ToAnalysisOptions(_settings), progress, _scanCancellation.Token).ConfigureAwait(false);
                    await ExportReportsForResultAsync(result, _scanCancellation.Token).ConfigureAwait(false);
                    await _history.SaveAsync(result, _scanCancellation.Token).ConfigureAwait(false);
                    lock (results)
                    {
                        results.Add(result);
                    }

                    System.Windows.Application.Current.Dispatcher.Invoke(() => BatchResults.Add(result));
                }
                finally
                {
                    var done = Interlocked.Increment(ref completed);
                    System.Windows.Application.Current.Dispatcher.Invoke(() =>
                    {
                        ProgressValue = files.Count == 0 ? 100 : done * 100 / files.Count;
                        CurrentStage = $"Batch {done}/{files.Count}";
                    });
                    gate.Release();
                }
            });

            await Task.WhenAll(tasks);
            await RefreshHistoryAsync();
            StatusMessage = $"Batch complete: {results.Count} files.";
        }
        finally
        {
            IsScanning = false;
            gate.Dispose();
            _scanCancellation?.Dispose();
            _scanCancellation = null;
        }
    }

    private IEnumerable<string> EnumerateBatchFiles()
    {
        var searchOption = RecursiveBatch ? SearchOption.AllDirectories : SearchOption.TopDirectoryOnly;
        var filters = string.IsNullOrWhiteSpace(FileTypeFilter) ? ["*.*"] : FileTypeFilter.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries);
        foreach (var filter in filters)
        {
            IEnumerable<string> files;
            try
            {
                files = Directory.EnumerateFiles(BatchFolder, filter, searchOption);
            }
            catch
            {
                continue;
            }

            foreach (var file in files)
            {
                yield return file;
            }
        }
    }

    private async Task ExportBatchAsync()
    {
        Directory.CreateDirectory(ReportFolder);
        var csv = await _reports.ExportBatchCsvAsync(BatchResults, ReportFolder);
        var json = Path.Combine(ReportFolder, $"batch-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.json");
        await File.WriteAllTextAsync(json, JsonSerializer.Serialize(BatchResults, new JsonSerializerOptions { WriteIndented = true }));
        var html = Path.Combine(ReportFolder, $"batch-{DateTimeOffset.Now:yyyyMMdd-HHmmss}.html");
        await File.WriteAllTextAsync(html, BuildBatchHtml());
        ReportPaths.Add(csv);
        ReportPaths.Add(json);
        ReportPaths.Add(html);
        StatusMessage = "Batch exports created.";
    }

    private string BuildBatchHtml()
    {
        var rows = string.Join(Environment.NewLine, BatchResults.Select(r => $"<tr><td>{EvidenceSanitizer.Html(r.Triage.FileName)}</td><td>{r.RiskLevel}</td><td>{r.RiskScore}</td><td>{EvidenceSanitizer.Html(r.ExecutiveSummary)}</td></tr>"));
        return "<!doctype html><meta charset=\"utf-8\"><title>MiyoMacroSentinel Batch</title><body style=\"font-family:Segoe UI;background:#0b1220;color:#e5f2ff\"><h1>Batch scan</h1><table border=\"1\" cellspacing=\"0\" cellpadding=\"6\"><tr><th>File</th><th>Risk</th><th>Score</th><th>Summary</th></tr>" + rows + "</table></body>";
    }

    private async Task RefreshHistoryAsync()
    {
        var records = await _history.SearchAsync();
        var stats = await _history.GetDashboardStatsAsync();
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            Replace(HistoryRecords, records);
            Stats = stats;
        });
    }

    private void LoadRules()
    {
        Replace(Rules, _rules.ListRules());
    }

    private async Task ValidateRulesAsync()
    {
        RuleValidationMessages.Clear();
        var errors = await _rules.ValidateRulesAsync(_settingsService.ToAnalysisOptions(_settings), CancellationToken.None);
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            if (errors.Count == 0)
            {
                RuleValidationMessages.Add("Rules validated or no YARA errors returned.");
            }
            else
            {
                foreach (var error in errors)
                {
                    RuleValidationMessages.Add(error);
                }
            }
        });
    }

    private async Task QuarantineCurrentAsync()
    {
        if (CurrentResult is null)
        {
            return;
        }

        var path = await _quarantine.QuarantineAsync(CurrentResult);
        StatusMessage = $"Copied to quarantine: {path}";
    }

    private void ToggleLanguage()
    {
        _settings.Language = _settings.Language.Equals("vi", StringComparison.OrdinalIgnoreCase) ? "en" : "vi";
        Strings.SetLanguage(_settings.Language);
        foreach (var page in Pages)
        {
            page.Label = Strings[page.Key];
        }

        _settingsService.Save(_settings);
        OnPropertyChanged(nameof(Settings));
    }

    private void SaveSettings()
    {
        _settingsService.Save(_settings);
        StatusMessage = "Settings saved.";
    }

    private static void OpenPath(string? path)
    {
        if (string.IsNullOrWhiteSpace(path) || !File.Exists(path))
        {
            return;
        }

        Process.Start(new ProcessStartInfo(path) { UseShellExecute = true });
    }

    private static void Replace<T>(ObservableCollection<T> collection, IEnumerable<T> values)
    {
        System.Windows.Application.Current.Dispatcher.Invoke(() =>
        {
            collection.Clear();
            foreach (var value in values)
            {
                collection.Add(value);
            }
        });
    }
}

public sealed class NavItem : ObservableObject
{
    private string _label;

    public NavItem(string key, string label)
    {
        Key = key;
        _label = label;
    }

    public string Key { get; }

    public string Label
    {
        get => _label;
        set => SetProperty(ref _label, value);
    }
}
