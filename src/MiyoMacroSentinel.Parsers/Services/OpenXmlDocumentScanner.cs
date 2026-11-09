using System.IO.Compression;
using System.Xml;
using System.Xml.Linq;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed class OpenXmlDocumentScanner
{
    private readonly MacroAnalyzer _macroAnalyzer = new();

    public async Task<ParserScanResult> ScanAsync(string filePath, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var result = new ParserScanResult();
        try
        {
            using var archive = ZipFile.OpenRead(filePath);
            var entries = archive.Entries.Select(e => e.FullName.Replace('\\', '/')).ToList();
            result.TextArtifacts.Add(string.Join(Environment.NewLine, entries));

            var vbaEntries = archive.Entries.Where(e => e.FullName.EndsWith("vbaProject.bin", StringComparison.OrdinalIgnoreCase)).ToList();
            if (vbaEntries.Count > 0)
            {
                result.Findings.Add(new Finding
                {
                    Title = "Office macro project detected",
                    Severity = Severity.High,
                    Location = "OpenXML package",
                    Evidence = string.Join(", ", vbaEntries.Select(e => e.FullName)),
                    Explanation = "The package contains vbaProject.bin, which indicates macro-enabled Office content.",
                    Recommendation = "Do not enable macros unless verified by an analyst.",
                    ScoreImpact = 20
                });

                if (IsUnexpectedMacroExtension(Path.GetExtension(filePath)))
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Unexpected macro in non-macro extension",
                        Severity = Severity.High,
                        Location = "OpenXML package",
                        Evidence = Path.GetFileName(filePath),
                        Explanation = "A non-macro Office extension contains macro project data.",
                        Recommendation = "Treat as suspicious and verify the real file origin.",
                        ScoreImpact = 25
                    });
                }

                foreach (var entry in vbaEntries)
                {
                    var bytes = await ReadEntryBytesAsync(entry, Math.Min(options.MaxXmlBytes, 5 * 1024 * 1024), cancellationToken).ConfigureAwait(false);
                    var strings = TextExtraction.ExtractAsciiAndUnicodeStrings(bytes);
                    result.TextArtifacts.Add(strings);
                    var macro = _macroAnalyzer.Analyze(strings, entry.FullName);
                    result.MacroAnalysis = macro.Summary;
                    result.Findings.AddRange(macro.Findings);
                }
            }

            foreach (var entry in archive.Entries.Where(e => e.FullName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                await ScanRelationshipsAsync(entry, result, options, cancellationToken).ConfigureAwait(false);
            }

            foreach (var entry in archive.Entries.Where(e => IsXmlLike(e.FullName)))
            {
                cancellationToken.ThrowIfCancellationRequested();
                var text = await ReadEntryTextAsync(entry, options.MaxXmlBytes, cancellationToken).ConfigureAwait(false);
                result.TextArtifacts.Add(text);
                if (text.Contains("w:vanish", StringComparison.OrdinalIgnoreCase) || text.Contains("display:none", StringComparison.OrdinalIgnoreCase))
                {
                    result.Findings.Add(new Finding
                    {
                        Title = "Hidden text marker",
                        Severity = Severity.Medium,
                        Location = entry.FullName,
                        Evidence = "w:vanish/display:none",
                        Explanation = "Hidden document text can conceal phishing or social engineering content.",
                        Recommendation = "Review hidden text in a safe viewer.",
                        ScoreImpact = 10
                    });
                }
            }

            foreach (var entry in archive.Entries.Where(e => IsEmbeddedObjectPath(e.FullName)))
            {
                var executableLike = IsExecutableLikeName(entry.FullName);
                var embedded = new EmbeddedObjectInfo
                {
                    Name = Path.GetFileName(entry.FullName),
                    Location = entry.FullName,
                    ObjectType = executableLike ? "Executable-like embedded object" : "Embedded object",
                    ExecutableLike = executableLike
                };
                result.EmbeddedObjects.Add(embedded);
                result.Findings.Add(new Finding
                {
                    Title = executableLike ? "Embedded executable-like object" : "Embedded object",
                    Severity = executableLike ? Severity.Critical : Severity.Medium,
                    Location = entry.FullName,
                    Evidence = EvidenceSanitizer.Truncate(entry.FullName),
                    Explanation = "Embedded objects can carry payloads or linked content inside Office documents.",
                    Recommendation = "Inspect embedded objects in a controlled environment.",
                    ScoreImpact = executableLike ? 40 : 20
                });
            }

            if (entries.Any(e => e.Contains("activeX", StringComparison.OrdinalIgnoreCase)))
            {
                result.Findings.Add(new Finding
                {
                    Title = "ActiveX control detected",
                    Severity = Severity.High,
                    Location = "OpenXML package",
                    Evidence = "activeX part",
                    Explanation = "ActiveX controls increase document attack surface.",
                    Recommendation = "Disable active content and escalate for analyst review.",
                    ScoreImpact = 20
                });
            }

            if (entries.Count(e => e.StartsWith("customXml/", StringComparison.OrdinalIgnoreCase)) > 10)
            {
                result.Findings.Add(new Finding
                {
                    Title = "Unusual custom XML volume",
                    Severity = Severity.Low,
                    Location = "OpenXML package",
                    Evidence = "customXml parts",
                    Explanation = "Large custom XML sections can hide metadata or payload-like strings.",
                    Recommendation = "Review custom XML content if other indicators are present.",
                    ScoreImpact = 5
                });
            }
        }
        catch (InvalidDataException ex)
        {
            result.Corrupted = true;
            result.Findings.Add(new Finding
            {
                Title = "Malformed OpenXML/ZIP structure",
                Severity = Severity.Medium,
                Location = "OpenXML parser",
                Evidence = EvidenceSanitizer.Truncate(ex.Message),
                Explanation = "The file could not be parsed as a valid OpenXML ZIP package.",
                Recommendation = "Treat malformed documents cautiously and request a clean copy from the sender.",
                ScoreImpact = 10,
                IsError = true
            });
        }

        return result;
    }

    private static async Task ScanRelationshipsAsync(ZipArchiveEntry entry, ParserScanResult result, AnalysisOptions options, CancellationToken cancellationToken)
    {
        var text = await ReadEntryTextAsync(entry, options.MaxXmlBytes, cancellationToken).ConfigureAwait(false);
        result.TextArtifacts.Add(text);
        try
        {
            using var stream = entry.Open();
            using var limited = new MemoryStream(System.Text.Encoding.UTF8.GetBytes(text));
            using var reader = XmlReader.Create(limited, new XmlReaderSettings { DtdProcessing = DtdProcessing.Prohibit, XmlResolver = null });
            var doc = XDocument.Load(reader);
            foreach (var rel in doc.Descendants().Where(x => x.Name.LocalName == "Relationship"))
            {
                var target = rel.Attribute("Target")?.Value ?? "";
                var mode = rel.Attribute("TargetMode")?.Value ?? "";
                var type = rel.Attribute("Type")?.Value ?? "";
                if (!mode.Equals("External", StringComparison.OrdinalIgnoreCase) && !IsRemoteTarget(target))
                {
                    continue;
                }

                var isTemplate = type.Contains("attachedTemplate", StringComparison.OrdinalIgnoreCase) || target.EndsWith(".dotm", StringComparison.OrdinalIgnoreCase);
                var isRemoteImage = type.Contains("image", StringComparison.OrdinalIgnoreCase);
                result.Findings.Add(new Finding
                {
                    Title = isTemplate ? "External template relationship" : isRemoteImage ? "Remote image relationship" : "External Office relationship",
                    Severity = isTemplate ? Severity.High : Severity.Medium,
                    Location = entry.FullName,
                    Evidence = EvidenceSanitizer.Defang(EvidenceSanitizer.Truncate(target)),
                    Explanation = isTemplate
                        ? "External templates can inject code or active content into Office documents."
                        : "External relationships can fetch remote content or track document opening.",
                    Recommendation = "Block external content and verify the target before opening the document.",
                    ScoreImpact = isTemplate ? 30 : 20
                });
            }
        }
        catch (XmlException ex)
        {
            result.Findings.Add(new Finding
            {
                Title = "Malformed relationship XML",
                Severity = Severity.Low,
                Location = entry.FullName,
                Evidence = EvidenceSanitizer.Truncate(ex.Message),
                Explanation = "Relationship XML could not be parsed cleanly.",
                Recommendation = "Review this file if other suspicious indicators are present.",
                ScoreImpact = 5
            });
        }
    }

    private static bool IsRemoteTarget(string target) =>
        target.StartsWith("http://", StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith("https://", StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith("file://", StringComparison.OrdinalIgnoreCase) ||
        target.StartsWith(@"\\", StringComparison.Ordinal);

    private static bool IsUnexpectedMacroExtension(string extension) =>
        extension.Equals(".docx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".xlsx", StringComparison.OrdinalIgnoreCase) ||
        extension.Equals(".pptx", StringComparison.OrdinalIgnoreCase);

    private static bool IsXmlLike(string entryName) =>
        entryName.EndsWith(".xml", StringComparison.OrdinalIgnoreCase) ||
        entryName.EndsWith(".rels", StringComparison.OrdinalIgnoreCase);

    private static bool IsEmbeddedObjectPath(string entryName) =>
        entryName.Contains("/embeddings/", StringComparison.OrdinalIgnoreCase) ||
        entryName.Contains("/activeX/", StringComparison.OrdinalIgnoreCase) ||
        entryName.Contains("oleObject", StringComparison.OrdinalIgnoreCase);

    private static bool IsExecutableLikeName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower.EndsWith(".exe") || lower.EndsWith(".dll") || lower.EndsWith(".scr") || lower.EndsWith(".js") || lower.EndsWith(".vbs") || lower.EndsWith(".ps1");
    }

    private static async Task<string> ReadEntryTextAsync(ZipArchiveEntry entry, int maxBytes, CancellationToken cancellationToken)
    {
        var bytes = await ReadEntryBytesAsync(entry, maxBytes, cancellationToken).ConfigureAwait(false);
        return TextExtraction.DecodeBestEffort(bytes);
    }

    private static async Task<byte[]> ReadEntryBytesAsync(ZipArchiveEntry entry, int maxBytes, CancellationToken cancellationToken)
    {
        await using var stream = entry.Open();
        using var memory = new MemoryStream();
        var buffer = new byte[81920];
        var total = 0;
        while (total < maxBytes)
        {
            var read = await stream.ReadAsync(buffer.AsMemory(0, Math.Min(buffer.Length, maxBytes - total)), cancellationToken).ConfigureAwait(false);
            if (read == 0)
            {
                break;
            }

            await memory.WriteAsync(buffer.AsMemory(0, read), cancellationToken).ConfigureAwait(false);
            total += read;
        }

        return memory.ToArray();
    }
}
