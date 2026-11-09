using System.Text;

namespace MiyoMacroSentinel.Core.Services;

public sealed class SafeLogger
{
    private readonly string _logDirectory;

    public SafeLogger(string? logDirectory = null)
    {
        _logDirectory = string.IsNullOrWhiteSpace(logDirectory)
            ? Path.Combine(AppContext.BaseDirectory, "logs")
            : logDirectory;
        Directory.CreateDirectory(_logDirectory);
    }

    public string LogDirectory => _logDirectory;

    public void Info(string message) => Write("app.log", "INFO", message);

    public void Scan(string message) => Write("scan.log", "SCAN", message);

    public void Error(Exception exception, string context)
    {
        var safeMessage = $"{context}: {exception.GetType().Name}: {exception.Message}{Environment.NewLine}{exception.StackTrace}";
        Write("error.log", "ERROR", safeMessage, 4000);
    }

    private void Write(string fileName, string level, string message, int maxLength = 600)
    {
        try
        {
            var line = $"{DateTimeOffset.Now:O} [{level}] {EvidenceSanitizer.Truncate(message, maxLength)}{Environment.NewLine}";
            File.AppendAllText(Path.Combine(_logDirectory, fileName), line, Encoding.UTF8);
        }
        catch
        {
            // Logging must never interrupt scanning. Full document content is intentionally not logged.
        }
    }
}
