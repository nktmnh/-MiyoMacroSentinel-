using System.Security.Cryptography;
using System.Text;
using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Core.Services;

public sealed class FileTriageService
{
    private static readonly Dictionary<string, string[]> ExtensionFamilies = new(StringComparer.OrdinalIgnoreCase)
    {
        ["Office OpenXML"] = [".docx", ".xlsx", ".pptx", ".docm", ".xlsm", ".pptm", ".dotm", ".xltm", ".ppsm", ".odt", ".ods", ".odp"],
        ["OLE Office Document"] = [".doc", ".xls", ".ppt", ".dot", ".xlt", ".pps"],
        ["PDF Document"] = [".pdf"],
        ["RTF Document"] = [".rtf"],
        ["Text"] = [".txt", ".csv", ".html", ".xml"],
        ["ZIP Archive"] = [".zip"],
        ["RAR Archive"] = [".rar"],
        ["7-Zip Archive"] = [".7z"]
    };

    private static readonly HashSet<string> ExecutableExtensions = new(StringComparer.OrdinalIgnoreCase)
    {
        ".exe", ".dll", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".jse", ".wsf", ".msi", ".com", ".hta"
    };

    public async Task<FileTriageResult> AnalyzeAsync(string path, AnalysisOptions options, IProgress<ScanProgress>? progress, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        var file = new FileInfo(path);
        if (!file.Exists)
        {
            throw new FileNotFoundException("File not found.", path);
        }

        progress?.Report(new ScanProgress { Stage = ScanStage.FileTriage, Percent = 5, Message = "Reading file metadata" });

        var result = new FileTriageResult
        {
            FileName = file.Name,
            FilePath = file.FullName,
            Extension = file.Extension.ToLowerInvariant(),
            FileSize = file.Length,
            CreationTime = file.CreationTime,
            ModifiedTime = file.LastWriteTime,
            EmptyFile = file.Length == 0,
            VeryLargeFile = file.Length > options.MaxFileSizeBytes
        };

        result.DoubleExtension = DetectDoubleExtension(file.Name);
        result.HiddenExtensionTrick = file.Name.Contains('\u202E') || file.Name.Contains('\u202D');
        result.UnicodeTrickInFileName = HiddenUnicodeScanner.ContainsSuspiciousUnicode(file.Name);

        progress?.Report(new ScanProgress { Stage = ScanStage.Hashing, Percent = 12, Message = "Calculating SHA256/SHA1/MD5" });
        await PopulateHashesAsync(path, result, cancellationToken).ConfigureAwait(false);

        progress?.Report(new ScanProgress { Stage = ScanStage.FileTypeDetection, Percent = 20, Message = "Detecting magic bytes" });
        var header = await ReadHeaderAsync(path, 512, cancellationToken).ConfigureAwait(false);
        var detection = DetectMagic(header, result.Extension);
        result.RealFileType = detection.RealType;
        result.MimeLikeType = detection.MimeLikeType;

        result.ExtensionMismatch = IsExtensionMismatch(result.Extension, result.RealFileType);
        AddWarnings(result);
        return result;
    }

    public static (string RealType, string MimeLikeType) DetectMagic(ReadOnlySpan<byte> header, string extension = "")
    {
        // Kiểm tra magic bytes giúp tránh bị lừa bởi tên file giả như invoice.pdf nhưng nội dung là Office/OLE.
        if (header.Length >= 8 && header[0] == 0xD0 && header[1] == 0xCF && header[2] == 0x11 && header[3] == 0xE0)
        {
            return ("OLE Office Document", "application/x-ole-storage");
        }

        if (header.Length >= 4 && header[0] == 0x50 && header[1] == 0x4B && header[2] is 0x03 or 0x05 or 0x07 && header[3] is 0x04 or 0x06 or 0x08)
        {
            return (IsOpenXmlExtension(extension) ? "Office OpenXML" : "ZIP Archive", "application/zip");
        }

        if (header.StartsWith("%PDF"u8))
        {
            return ("PDF Document", "application/pdf");
        }

        if (header.StartsWith("{\\rtf"u8))
        {
            return ("RTF Document", "application/rtf");
        }

        if (header.Length >= 7 && header[0] == 0x52 && header[1] == 0x61 && header[2] == 0x72 && header[3] == 0x21 && header[4] == 0x1A && header[5] == 0x07)
        {
            return ("RAR Archive", "application/vnd.rar");
        }

        if (header.Length >= 6 && header[0] == 0x37 && header[1] == 0x7A && header[2] == 0xBC && header[3] == 0xAF && header[4] == 0x27 && header[5] == 0x1C)
        {
            return ("7-Zip Archive", "application/x-7z-compressed");
        }

        if (LooksLikeUtfText(header))
        {
            return (extension.Equals(".csv", StringComparison.OrdinalIgnoreCase) ? "CSV Text" : "Text", "text/plain");
        }

        return ("Unknown", "application/octet-stream");
    }

    private static bool LooksLikeUtfText(ReadOnlySpan<byte> header)
    {
        if (header.IsEmpty)
        {
            return true;
        }

        var sampleLength = Math.Min(header.Length, 128);
        var controlCount = 0;
        for (var index = 0; index < sampleLength; index++)
        {
            var b = header[index];
            if (b == 0)
            {
                return false;
            }

            if (b < 0x09 || (b > 0x0D && b < 0x20))
            {
                controlCount++;
            }
        }

        return controlCount <= 3;
    }

    private static async Task<byte[]> ReadHeaderAsync(string path, int count, CancellationToken cancellationToken)
    {
        var buffer = new byte[count];
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, 81920, true);
        var read = await stream.ReadAsync(buffer.AsMemory(0, count), cancellationToken).ConfigureAwait(false);
        return buffer[..read];
    }

    private static async Task PopulateHashesAsync(string path, FileTriageResult result, CancellationToken cancellationToken)
    {
        using var md5 = MD5.Create();
        using var sha1 = SHA1.Create();
        using var sha256 = SHA256.Create();

        var buffer = new byte[81920];
        await using var stream = new FileStream(path, FileMode.Open, FileAccess.Read, FileShare.Read, buffer.Length, true);
        while (true)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            md5.TransformBlock(buffer, 0, read, null, 0);
            sha1.TransformBlock(buffer, 0, read, null, 0);
            sha256.TransformBlock(buffer, 0, read, null, 0);
        }

        md5.TransformFinalBlock([], 0, 0);
        sha1.TransformFinalBlock([], 0, 0);
        sha256.TransformFinalBlock([], 0, 0);

        result.Md5 = Convert.ToHexString(md5.Hash ?? []);
        result.Sha1 = Convert.ToHexString(sha1.Hash ?? []);
        result.Sha256 = Convert.ToHexString(sha256.Hash ?? []);
    }

    private static bool IsExtensionMismatch(string extension, string realType)
    {
        if (string.IsNullOrWhiteSpace(extension) || realType == "Unknown")
        {
            return false;
        }

        if (ExtensionFamilies.TryGetValue(realType, out var allowed))
        {
            return !allowed.Contains(extension, StringComparer.OrdinalIgnoreCase);
        }

        if (realType == "CSV Text")
        {
            return extension != ".csv";
        }

        return realType == "Text" && !ExtensionFamilies["Text"].Contains(extension, StringComparer.OrdinalIgnoreCase);
    }

    private static bool DetectDoubleExtension(string fileName)
    {
        var extensions = new List<string>();
        var current = fileName;
        while (!string.IsNullOrEmpty(Path.GetExtension(current)))
        {
            var ext = Path.GetExtension(current);
            extensions.Add(ext);
            current = Path.GetFileNameWithoutExtension(current);
        }

        if (extensions.Count < 2)
        {
            return false;
        }

        return extensions.Any(ext => ExecutableExtensions.Contains(ext)) ||
               extensions.Any(ext => ExtensionFamilies.Values.Any(family => family.Contains(ext, StringComparer.OrdinalIgnoreCase)));
    }

    private static bool IsOpenXmlExtension(string extension) =>
        ExtensionFamilies["Office OpenXML"].Contains(extension, StringComparer.OrdinalIgnoreCase);

    private static void AddWarnings(FileTriageResult result)
    {
        if (result.EmptyFile)
        {
            result.Warnings.Add(CreateWarning("Empty file", Severity.Low, "The file is empty.", "No content can be analyzed.", 0));
        }

        if (result.VeryLargeFile)
        {
            result.Warnings.Add(CreateWarning("Very large file", Severity.Medium, $"{result.FileSize:N0} bytes", "Very large files are scanned with size limits to protect memory.", 5));
        }

        if (result.ExtensionMismatch)
        {
            result.Warnings.Add(CreateWarning(
                "Extension mismatch",
                Severity.High,
                $"{result.Extension} vs {result.RealFileType}",
                "The file name extension does not match its magic bytes.",
                30));
        }

        if (result.DoubleExtension)
        {
            result.Warnings.Add(CreateWarning(
                "Double extension",
                Severity.Medium,
                result.FileName,
                "Double extensions can disguise executable or document content.",
                15));
        }

        if (result.HiddenExtensionTrick || result.UnicodeTrickInFileName)
        {
            result.Warnings.Add(CreateWarning(
                "Unicode trick in file name",
                Severity.High,
                result.FileName,
                "Hidden or bidirectional Unicode can make a filename appear different from its real text.",
                20));
        }
    }

    private static Finding CreateWarning(string title, Severity severity, string evidence, string explanation, int scoreImpact)
    {
        return new Finding
        {
            Title = title,
            Severity = severity,
            Evidence = EvidenceSanitizer.Truncate(evidence),
            Location = "File triage",
            Explanation = explanation,
            Recommendation = "Review the file source before opening it.",
            ScoreImpact = scoreImpact
        };
    }
}
