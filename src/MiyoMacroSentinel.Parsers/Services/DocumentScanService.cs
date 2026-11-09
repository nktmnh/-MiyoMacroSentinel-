using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;
using MiyoMacroSentinel.Rules.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed class DocumentScanService
{
    private readonly FileTriageService _triage = new();
    private readonly HiddenUnicodeScanner _hiddenUnicode = new();
    private readonly IocExtractor _iocExtractor = new();
    private readonly StaticDecoder _decoder = new();
    private readonly RiskScoringEngine _scoring = new();
    private readonly YaraService _yara;
    private readonly SafeLogger _logger;

    public DocumentScanService(SafeLogger? logger = null)
    {
        _logger = logger ?? new SafeLogger();
        _yara = new YaraService(_logger);
    }

    public async Task<ScanResult> ScanAsync(string filePath, AnalysisOptions options, IProgress<ScanProgress>? progress = null, CancellationToken cancellationToken = default)
    {
        using var timeout = CancellationTokenSource.CreateLinkedTokenSource(cancellationToken);
        if (options.ScanTimeoutSeconds > 0)
        {
            timeout.CancelAfter(TimeSpan.FromSeconds(options.ScanTimeoutSeconds));
        }

        return await ScanInternalAsync(filePath, options, progress, timeout.Token, 0).ConfigureAwait(false);
    }

    private async Task<ScanResult> ScanInternalAsync(string filePath, AnalysisOptions options, IProgress<ScanProgress>? progress, CancellationToken cancellationToken, int archiveDepth)
    {
        var result = new ScanResult { StartedAt = DateTimeOffset.Now };
        var textArtifacts = new List<(string Text, string Location)>();
        try
        {
            progress?.Report(new ScanProgress { Stage = ScanStage.FileTriage, Percent = 3, Message = "File triage" });
            result.Triage = await _triage.AnalyzeAsync(filePath, options, progress, cancellationToken).ConfigureAwait(false);
            result.Findings.AddRange(result.Triage.Warnings);
            _logger.Scan($"Scanning {result.Triage.FileName} ({result.Triage.RealFileType})");

            textArtifacts.Add((result.Triage.FileName, "File name"));

            progress?.Report(new ScanProgress { Stage = ScanStage.DocumentStructureParsing, Percent = 28, Message = "Parsing document structure" });
            var parserResult = await RunFormatParserAsync(filePath, result.Triage, options, progress, cancellationToken, archiveDepth).ConfigureAwait(false);
            result.Findings.AddRange(parserResult.Findings);
            result.EmbeddedObjects.AddRange(parserResult.EmbeddedObjects);
            result.Triage.PasswordProtected |= parserResult.PasswordProtected;
            result.Triage.Corrupted |= parserResult.Corrupted;
            if (parserResult.MacroAnalysis is not null)
            {
                result.MacroAnalysis = parserResult.MacroAnalysis;
            }

            textArtifacts.AddRange(parserResult.TextArtifacts.Select((text, index) => (text, $"Extracted text {index + 1}")));

            progress?.Report(new ScanProgress { Stage = ScanStage.HiddenCharacterScanning, Percent = 55, Message = "Scanning hidden Unicode" });
            foreach (var (text, location) in textArtifacts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Unicode ẩn nguy hiểm vì nội dung hiển thị có thể khác chuỗi thật mà parser nhìn thấy.
                result.HiddenCharacters.AddRange(_hiddenUnicode.Scan(text, location));
            }

            progress?.Report(new ScanProgress { Stage = ScanStage.IocExtraction, Percent = 65, Message = "Extracting IOCs" });
            foreach (var (text, location) in textArtifacts)
            {
                cancellationToken.ThrowIfCancellationRequested();
                // Defang IOC để báo cáo không vô tình tạo link độc hại có thể bấm trực tiếp.
                result.Iocs.AddRange(_iocExtractor.Extract(text, location, options.DefangIocs));
                result.DecodedArtifacts.AddRange(_decoder.Analyze(text, location, options));
            }

            result.Iocs = result.Iocs.GroupBy(i => $"{i.Type}|{i.Original}", StringComparer.OrdinalIgnoreCase).Select(g => g.First()).Take(750).ToList();
            result.DecodedArtifacts = result.DecodedArtifacts.Take(100).ToList();

            progress?.Report(new ScanProgress { Stage = ScanStage.YaraMatching, Percent = 75, Message = "Running local YARA rules" });
            var yara = await _yara.ScanAsync(filePath, options, cancellationToken).ConfigureAwait(false);
            result.YaraMatches.AddRange(yara.Matches);
            result.Findings.AddRange(yara.Findings);

            progress?.Report(new ScanProgress { Stage = ScanStage.RiskScoring, Percent = 88, Message = "Scoring risk" });
            _scoring.Score(result);

            progress?.Report(new ScanProgress { Stage = ScanStage.ReportGeneration, Percent = 95, Message = "Preparing report data" });
            result.CompletedAt = DateTimeOffset.Now;
            progress?.Report(new ScanProgress { Stage = ScanStage.Completed, Percent = 100, Message = "Scan completed" });
        }
        catch (OperationCanceledException)
        {
            result.CompletedAt = DateTimeOffset.Now;
            result.Findings.Add(new Finding
            {
                Title = "Scan cancelled",
                Severity = Severity.Info,
                Location = Path.GetFileName(filePath),
                Explanation = "The scan was cancelled before all analysis modules completed.",
                Recommendation = "Run the scan again if a complete result is required.",
                ScoreImpact = 0
            });
            _scoring.Score(result);
            progress?.Report(new ScanProgress { Stage = ScanStage.Cancelled, Percent = 100, Message = "Scan cancelled" });
        }
        catch (Exception ex)
        {
            // Lỗi parser không được làm sập ứng dụng vì nội dung tài liệu luôn được xem là không đáng tin cậy.
            _logger.Error(ex, "Scan failed");
            result.CompletedAt = DateTimeOffset.Now;
            result.Findings.Add(new Finding
            {
                Title = "Scan error",
                Severity = Severity.Medium,
                Location = Path.GetFileName(filePath),
                Evidence = EvidenceSanitizer.Truncate(ex.Message),
                Explanation = "The scanner handled an error without crashing. Parsed content is treated as untrusted.",
                Recommendation = "Retry with a clean copy or inspect with specialized tooling.",
                ScoreImpact = 10,
                IsError = true
            });
            _scoring.Score(result);
            progress?.Report(new ScanProgress { Stage = ScanStage.Failed, Percent = 100, Message = "Scan failed safely" });
        }

        return result;
    }

    private async Task<ParserScanResult> RunFormatParserAsync(
        string filePath,
        FileTriageResult triage,
        AnalysisOptions options,
        IProgress<ScanProgress>? progress,
        CancellationToken cancellationToken,
        int archiveDepth)
    {
        var parserResult = new ParserScanResult();
        var extension = triage.Extension;

        if (triage.VeryLargeFile)
        {
            parserResult.Findings.Add(new Finding
            {
                Title = "Parser size limit applied",
                Severity = Severity.Medium,
                Location = triage.FileName,
                Evidence = $"{triage.FileSize:N0} bytes",
                Explanation = "Deep parsing is limited for very large files to keep memory usage stable.",
                Recommendation = "Analyze very large samples on a dedicated workstation.",
                ScoreImpact = 5
            });
        }

        if (triage.RealFileType == "Office OpenXML" || IsOpenXmlExtension(extension))
        {
            progress?.Report(new ScanProgress { Stage = ScanStage.MacroDetection, Percent = 38, Message = "Checking OpenXML macros and relationships" });
            parserResult.Merge(await new OpenXmlDocumentScanner().ScanAsync(filePath, options, cancellationToken).ConfigureAwait(false));
        }
        else if (triage.RealFileType == "OLE Office Document")
        {
            progress?.Report(new ScanProgress { Stage = ScanStage.MacroDetection, Percent = 38, Message = "Checking legacy OLE macros" });
            parserResult.Merge(await new OleDocumentScanner().ScanAsync(filePath, options, cancellationToken).ConfigureAwait(false));
        }
        else if (triage.RealFileType == "PDF Document" || extension.Equals(".pdf", StringComparison.OrdinalIgnoreCase))
        {
            parserResult.Merge(await new PdfDocumentScanner().ScanAsync(filePath, options, cancellationToken).ConfigureAwait(false));
        }
        else if (triage.RealFileType == "RTF Document" || extension.Equals(".rtf", StringComparison.OrdinalIgnoreCase))
        {
            parserResult.Merge(await new RtfDocumentScanner().ScanAsync(filePath, options, cancellationToken).ConfigureAwait(false));
        }
        else if (extension.Equals(".csv", StringComparison.OrdinalIgnoreCase) || IsPlainTextExtension(extension) || triage.RealFileType is "Text" or "CSV Text")
        {
            parserResult.Merge(await new CsvTextScanner().ScanAsync(filePath, options, cancellationToken).ConfigureAwait(false));
        }
        else if (triage.RealFileType.EndsWith("Archive", StringComparison.OrdinalIgnoreCase) || extension is ".zip" or ".rar" or ".7z")
        {
            // Giải nén archive bị giới hạn trong thư mục tạm cô lập để chặn zip-slip và zip-bomb.
            parserResult.Merge(await new ArchiveScanner().ScanAsync(
                filePath,
                options,
                archiveDepth,
                archiveDepth < options.ArchiveRecursionDepth ? (nestedPath, depth, token) => ScanInternalAsync(nestedPath, options, progress, token, depth) : null,
                cancellationToken).ConfigureAwait(false));
        }
        else
        {
            var text = await TextExtraction.ReadTextPrefixAsync(filePath, (int)Math.Min(options.MaxFileSizeBytes, 5 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
            parserResult.TextArtifacts.Add(text);
        }

        return parserResult;
    }

    private static bool IsOpenXmlExtension(string extension) =>
        extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".docm", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xlsm", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pptm", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".dotm", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xltm", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".ppsm", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".odt", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".ods", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".odp", StringComparison.OrdinalIgnoreCase);

    private static bool IsPlainTextExtension(string extension) =>
        extension.Equals(".txt", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".html", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xml", StringComparison.OrdinalIgnoreCase);
}
