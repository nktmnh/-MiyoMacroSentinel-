using Microsoft.Data.Sqlite;
using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Reports.Services;

public sealed class ScanHistoryRepository
{
    private readonly string _databasePath;

    public ScanHistoryRepository(string? databasePath = null)
    {
        var appData = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);
        var directory = Path.Combine(appData, "MiyoMacroSentinel");
        Directory.CreateDirectory(directory);
        _databasePath = databasePath ?? Path.Combine(directory, "scan-history.sqlite");
    }

    public async Task InitializeAsync(CancellationToken cancellationToken = default)
    {
        await using var connection = OpenConnection();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText =
            """
            CREATE TABLE IF NOT EXISTS ScanHistory (
                Id INTEGER PRIMARY KEY AUTOINCREMENT,
                FileName TEXT NOT NULL,
                FilePath TEXT NOT NULL,
                Sha256 TEXT NOT NULL,
                FileType TEXT NOT NULL,
                ScanTime TEXT NOT NULL,
                RiskScore INTEGER NOT NULL,
                RiskLevel TEXT NOT NULL,
                FindingsSummary TEXT NOT NULL,
                ReportPath TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS IX_ScanHistory_Sha256 ON ScanHistory(Sha256);
            CREATE INDEX IF NOT EXISTS IX_ScanHistory_RiskLevel ON ScanHistory(RiskLevel);
            """;
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task SaveAsync(ScanResult result, CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = OpenConnection();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText =
            """
            INSERT INTO ScanHistory (FileName, FilePath, Sha256, FileType, ScanTime, RiskScore, RiskLevel, FindingsSummary, ReportPath)
            VALUES ($fileName, $filePath, $sha256, $fileType, $scanTime, $riskScore, $riskLevel, $findingsSummary, $reportPath);
            """;
        command.Parameters.AddWithValue("$fileName", result.Triage.FileName);
        command.Parameters.AddWithValue("$filePath", result.Triage.FilePath);
        command.Parameters.AddWithValue("$sha256", result.Triage.Sha256);
        command.Parameters.AddWithValue("$fileType", result.Triage.RealFileType);
        command.Parameters.AddWithValue("$scanTime", result.CompletedAt.ToString("O"));
        command.Parameters.AddWithValue("$riskScore", result.RiskScore);
        command.Parameters.AddWithValue("$riskLevel", result.RiskLevel.ToString());
        command.Parameters.AddWithValue("$findingsSummary", string.Join("; ", result.Findings.Take(5).Select(f => f.Title)));
        command.Parameters.AddWithValue("$reportPath", result.ReportPaths.FirstOrDefault(p => p.EndsWith(".html", StringComparison.OrdinalIgnoreCase)) ?? "");
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    public async Task<List<ScanHistoryRecord>> SearchAsync(string? query = null, RiskLevel? riskLevel = null, CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = OpenConnection();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText =
            """
            SELECT Id, FileName, FilePath, Sha256, FileType, ScanTime, RiskScore, RiskLevel, FindingsSummary, ReportPath
            FROM ScanHistory
            WHERE ($query = '' OR FileName LIKE '%' || $query || '%' OR FilePath LIKE '%' || $query || '%' OR Sha256 LIKE '%' || $query || '%')
              AND ($riskLevel = '' OR RiskLevel = $riskLevel)
            ORDER BY Id DESC
            LIMIT 500;
            """;
        command.Parameters.AddWithValue("$query", query ?? "");
        command.Parameters.AddWithValue("$riskLevel", riskLevel?.ToString() ?? "");

        var records = new List<ScanHistoryRecord>();
        await using var reader = await command.ExecuteReaderAsync(cancellationToken).ConfigureAwait(false);
        while (await reader.ReadAsync(cancellationToken).ConfigureAwait(false))
        {
            records.Add(ReadRecord(reader));
        }

        return records;
    }

    public async Task<DashboardStats> GetDashboardStatsAsync(CancellationToken cancellationToken = default)
    {
        var records = await SearchAsync(cancellationToken: cancellationToken).ConfigureAwait(false);
        return new DashboardStats
        {
            TotalScannedFiles = records.Count,
            CleanFiles = records.Count(r => r.RiskLevel == RiskLevel.Clean),
            SuspiciousFiles = records.Count(r => r.RiskLevel is RiskLevel.Low or RiskLevel.Medium),
            HighRiskFiles = records.Count(r => r.RiskLevel == RiskLevel.High),
            CriticalFiles = records.Count(r => r.RiskLevel == RiskLevel.Critical),
            LatestScans = records.Take(10).ToList(),
            TopMatchedRules = records.SelectMany(r => r.FindingsSummary.Split(';', StringSplitOptions.TrimEntries | StringSplitOptions.RemoveEmptyEntries)).GroupBy(x => x).OrderByDescending(g => g.Count()).Take(5).Select(g => $"{g.Key} ({g.Count()})").ToList(),
            CommonIocTypes = []
        };
    }

    public async Task PruneAsync(int retentionDays, CancellationToken cancellationToken = default)
    {
        await InitializeAsync(cancellationToken).ConfigureAwait(false);
        await using var connection = OpenConnection();
        await connection.OpenAsync(cancellationToken).ConfigureAwait(false);
        var command = connection.CreateCommand();
        command.CommandText = "DELETE FROM ScanHistory WHERE ScanTime < $threshold;";
        command.Parameters.AddWithValue("$threshold", DateTimeOffset.Now.AddDays(-retentionDays).ToString("O"));
        await command.ExecuteNonQueryAsync(cancellationToken).ConfigureAwait(false);
    }

    private SqliteConnection OpenConnection() => new($"Data Source={_databasePath}");

    private static ScanHistoryRecord ReadRecord(SqliteDataReader reader)
    {
        Enum.TryParse<RiskLevel>(reader.GetString(7), out var riskLevel);
        DateTimeOffset.TryParse(reader.GetString(5), out var scanTime);
        return new ScanHistoryRecord
        {
            Id = reader.GetInt64(0),
            FileName = reader.GetString(1),
            FilePath = reader.GetString(2),
            Sha256 = reader.GetString(3),
            FileType = reader.GetString(4),
            ScanTime = scanTime,
            RiskScore = reader.GetInt32(6),
            RiskLevel = riskLevel,
            FindingsSummary = reader.GetString(8),
            ReportPath = reader.GetString(9)
        };
    }
}
