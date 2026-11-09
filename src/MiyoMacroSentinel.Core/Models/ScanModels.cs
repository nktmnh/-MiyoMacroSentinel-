using System.Text.Json.Serialization;

namespace MiyoMacroSentinel.Core.Models;

public enum Severity
{
    Info = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4
}

public enum RiskLevel
{
    Clean,
    Low,
    Medium,
    High,
    Critical
}

public enum ScanStage
{
    FileTriage,
    Hashing,
    FileTypeDetection,
    DocumentStructureParsing,
    MacroDetection,
    HiddenCharacterScanning,
    IocExtraction,
    YaraMatching,
    RiskScoring,
    ReportGeneration,
    Completed,
    Failed,
    Cancelled
}

public enum IocType
{
    Url,
    Domain,
    IPv4,
    IPv6,
    Email,
    FilePath,
    RegistryPath,
    Command,
    Base64Like,
    Hash,
    UncPath,
    ShortenedUrl,
    PunycodeDomain,
    SuspiciousTld,
    PeHeader,
    ScriptName
}

public sealed class AnalysisOptions
{
    public long MaxFileSizeBytes { get; set; } = 100 * 1024 * 1024;
    public long MaxExtractedArchiveBytes { get; set; } = 250 * 1024 * 1024;
    public int ArchiveRecursionDepth { get; set; } = 2;
    public int MaxXmlBytes { get; set; } = 5 * 1024 * 1024;
    public int MaxDecodedStringBytes { get; set; } = 512 * 1024;
    public int ScanTimeoutSeconds { get; set; } = 120;
    public bool YaraEnabled { get; set; } = true;
    public bool OleToolsEnabled { get; set; } = true;
    public bool DefangIocs { get; set; } = true;
    public string? YaraExecutablePath { get; set; }
    public string? YaraRulesPath { get; set; }
    public string? OleToolsPath { get; set; }
    public string? ReportOutputFolder { get; set; }
    public string? TemporaryFolderPath { get; set; }
}

public sealed class AppSettings
{
    public string Language { get; set; } = "vi";
    public string Theme { get; set; } = "Dark";
    public bool YaraEnabled { get; set; } = true;
    public bool OleToolsEnabled { get; set; } = true;
    public long MaxFileSizeBytes { get; set; } = 100 * 1024 * 1024;
    public int ArchiveRecursionDepth { get; set; } = 2;
    public string TemporaryFolderPath { get; set; } = "";
    public string ReportOutputFolder { get; set; } = "";
    public int ScanHistoryRetentionDays { get; set; } = 180;
    public bool TelemetryEnabled { get; set; } = false;
    public bool CloudUploadEnabled { get; set; } = false;
    public bool ConfirmBeforeOpeningExternalLinks { get; set; } = true;
    public bool SafeIocDefangEnabled { get; set; } = true;
}

public sealed class ScanProgress
{
    public ScanStage Stage { get; init; }
    public string Message { get; init; } = "";
    public int Percent { get; init; }
}

public sealed class Finding
{
    public string Title { get; set; } = "";
    public Severity Severity { get; set; }
    public string Evidence { get; set; } = "";
    public string Location { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string Recommendation { get; set; } = "";
    public string RuleId { get; set; } = "";
    public int ScoreImpact { get; set; }
    public double Confidence { get; set; } = 0.8;
    public bool IsError { get; set; }
}

public sealed class FileTriageResult
{
    public string FileName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string Extension { get; set; } = "";
    public string RealFileType { get; set; } = "Unknown";
    public string MimeLikeType { get; set; } = "application/octet-stream";
    public long FileSize { get; set; }
    public DateTimeOffset CreationTime { get; set; }
    public DateTimeOffset ModifiedTime { get; set; }
    public string Sha256 { get; set; } = "";
    public string Sha1 { get; set; } = "";
    public string Md5 { get; set; } = "";
    public bool ExtensionMismatch { get; set; }
    public bool DoubleExtension { get; set; }
    public bool HiddenExtensionTrick { get; set; }
    public bool UnicodeTrickInFileName { get; set; }
    public bool EmptyFile { get; set; }
    public bool VeryLargeFile { get; set; }
    public bool PasswordProtected { get; set; }
    public bool Corrupted { get; set; }
    public List<Finding> Warnings { get; set; } = [];
}

public sealed class HiddenCharacterFinding
{
    public string CharacterName { get; set; } = "";
    public string CodePoint { get; set; } = "";
    public int Position { get; set; }
    public string ContextBefore { get; set; } = "";
    public string ContextAfter { get; set; } = "";
    public string Location { get; set; } = "";
    public string Explanation { get; set; } = "";
    public string SuggestedNormalizedText { get; set; } = "";
}

public sealed class Ioc
{
    public IocType Type { get; set; }
    public string Original { get; set; } = "";
    public string DisplayValue { get; set; } = "";
    public string Location { get; set; } = "";
    public string Notes { get; set; } = "";
}

public sealed class DecodedArtifact
{
    public string Decoder { get; set; } = "";
    public string SourceSnippet { get; set; } = "";
    public string DecodedText { get; set; } = "";
    public string Location { get; set; } = "";
    public bool Truncated { get; set; }
}

public sealed class MacroAnalysisSummary
{
    public bool MacroExists { get; set; }
    public int MacroCount { get; set; }
    public bool AutoExecFound { get; set; }
    public List<string> SuspiciousKeywords { get; set; } = [];
    public List<string> ExtractedCommands { get; set; } = [];
    public List<string> ExtractedNetworkIndicators { get; set; } = [];
    public int ObfuscationScore { get; set; }
    public string RiskExplanation { get; set; } = "";
}

public sealed class YaraMatchInfo
{
    public string RuleName { get; set; } = "";
    public string Namespace { get; set; } = "";
    public Severity Severity { get; set; } = Severity.Info;
    public string Metadata { get; set; } = "";
    public string MatchedStrings { get; set; } = "";
}

public sealed class EmbeddedObjectInfo
{
    public string Name { get; set; } = "";
    public string Location { get; set; } = "";
    public string ObjectType { get; set; } = "";
    public bool ExecutableLike { get; set; }
}

public sealed class ScanResult
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string ToolVersion { get; set; } = "0.1.0";
    public DateTimeOffset StartedAt { get; set; } = DateTimeOffset.Now;
    public DateTimeOffset CompletedAt { get; set; }
    public FileTriageResult Triage { get; set; } = new();
    public int RiskScore { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public string ExecutiveSummary { get; set; } = "";
    public double Confidence { get; set; } = 0.75;
    public MacroAnalysisSummary MacroAnalysis { get; set; } = new();
    public List<Finding> Findings { get; set; } = [];
    public List<HiddenCharacterFinding> HiddenCharacters { get; set; } = [];
    public List<Ioc> Iocs { get; set; } = [];
    public List<DecodedArtifact> DecodedArtifacts { get; set; } = [];
    public List<YaraMatchInfo> YaraMatches { get; set; } = [];
    public List<EmbeddedObjectInfo> EmbeddedObjects { get; set; } = [];
    public List<ScanResult> NestedResults { get; set; } = [];
    public List<string> Recommendations { get; set; } = [];
    public List<string> Limitations { get; set; } = [];
    public List<string> ReportPaths { get; set; } = [];

    [JsonIgnore]
    public bool HasHighRisk => RiskLevel is RiskLevel.High or RiskLevel.Critical;
}

public sealed class ScanHistoryRecord
{
    public long Id { get; set; }
    public string FileName { get; set; } = "";
    public string FilePath { get; set; } = "";
    public string Sha256 { get; set; } = "";
    public string FileType { get; set; } = "";
    public DateTimeOffset ScanTime { get; set; }
    public int RiskScore { get; set; }
    public RiskLevel RiskLevel { get; set; }
    public string FindingsSummary { get; set; } = "";
    public string ReportPath { get; set; } = "";
}

public sealed class DashboardStats
{
    public int TotalScannedFiles { get; set; }
    public int CleanFiles { get; set; }
    public int SuspiciousFiles { get; set; }
    public int HighRiskFiles { get; set; }
    public int CriticalFiles { get; set; }
    public List<ScanHistoryRecord> LatestScans { get; set; } = [];
    public List<string> TopMatchedRules { get; set; } = [];
    public List<string> CommonIocTypes { get; set; } = [];
}
