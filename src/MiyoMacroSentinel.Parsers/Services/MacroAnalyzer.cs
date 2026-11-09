using System.Text.RegularExpressions;
using MiyoMacroSentinel.Core.Models;
using MiyoMacroSentinel.Core.Services;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed partial class MacroAnalyzer
{
    private static readonly string[] AutoExecKeywords =
    [
        "AutoOpen", "AutoClose", "Document_Open", "Document_Close", "Workbook_Open",
        "Workbook_BeforeClose", "Presentation_Open", "AutoExec", "AutoExit"
    ];

    private static readonly string[] ExecutionKeywords =
    [
        "Shell", "WScript.Shell", "CreateObject", "GetObject", "cmd.exe", "powershell",
        "pwsh", "mshta", "wscript", "cscript", "rundll32", "regsvr32", "certutil",
        "bitsadmin", "schtasks"
    ];

    private static readonly string[] NetworkKeywords =
    [
        "XMLHTTP", "WinHttpRequest", "URLDownloadToFile", "ADODB.Stream", "InternetOpen",
        "DownloadFile", "http://", "https://", "ftp://", "\\\\"
    ];

    private static readonly string[] ObfuscationKeywords =
    [
        "Chr", "ChrW", "Asc", "StrReverse", "Replace", "Split", "Join", "Mid",
        "Left", "Right"
    ];

    private static readonly string[] FileRegistryKeywords =
    [
        "AppData", "Temp", "Startup", "ProgramData", "HKCU", "HKLM", "Run", "RunOnce",
        "CreateTextFile", "SaveToFile", "Open For Binary", "Environ"
    ];

    public (MacroAnalysisSummary Summary, List<Finding> Findings) Analyze(string macroText, string location)
    {
        var findings = new List<Finding>();
        var summary = new MacroAnalysisSummary();
        if (string.IsNullOrWhiteSpace(macroText))
        {
            return (summary, findings);
        }

        summary.MacroExists = true;
        summary.MacroCount = Math.Max(1, ProcedureRegex().Matches(macroText).Count);

        // Macro chỉ được phân tích như chuỗi tĩnh; tuyệt đối không chạy macro hoặc mở file bằng Office.
        var autoExec = FindKeywords(macroText, AutoExecKeywords);
        var execution = FindKeywords(macroText, ExecutionKeywords);
        var network = FindKeywords(macroText, NetworkKeywords);
        var obfuscation = FindKeywords(macroText, ObfuscationKeywords);
        var fileRegistry = FindKeywords(macroText, FileRegistryKeywords);

        summary.AutoExecFound = autoExec.Count > 0;
        summary.SuspiciousKeywords = execution.Concat(network).Concat(fileRegistry).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
        summary.ExtractedCommands = CommandRegex().Matches(macroText).Select(m => EvidenceSanitizer.Truncate(m.Value, 180)).Distinct(StringComparer.OrdinalIgnoreCase).Take(20).ToList();
        summary.ExtractedNetworkIndicators = new IocExtractor().Extract(macroText, location).Where(i => i.Type is IocType.Url or IocType.Domain or IocType.IPv4 or IocType.UncPath).Select(i => i.DisplayValue).Distinct(StringComparer.OrdinalIgnoreCase).Take(30).ToList();
        summary.ObfuscationScore = Math.Min(100, obfuscation.Count * 15 + LongLineRegex().Matches(macroText).Count * 10 + Base64Regex().Matches(macroText).Count * 20);
        summary.RiskExplanation = BuildRiskExplanation(summary);

        findings.Add(new Finding
        {
            Title = "Macro code detected",
            Severity = Severity.Medium,
            Location = location,
            Evidence = $"Macro-like procedures: {summary.MacroCount}",
            Explanation = "The document contains macro/VBA indicators. Macros are never executed by this scanner.",
            Recommendation = "Do not enable macros unless the sender and macro purpose are verified.",
            ScoreImpact = 20
        });

        foreach (var keyword in autoExec)
        {
            findings.Add(CreateKeywordFinding("Auto-execution macro detected", Severity.High, keyword, macroText, location, "This macro can run automatically when the document is opened.", 25));
        }

        foreach (var keyword in execution)
        {
            findings.Add(CreateKeywordFinding("Suspicious execution keyword", Severity.High, keyword, macroText, location, "The macro references command or script execution functionality.", 30));
        }

        foreach (var keyword in network)
        {
            findings.Add(CreateKeywordFinding("Network or downloader keyword", Severity.High, keyword, macroText, location, "The macro references network access or download behavior.", 25));
        }

        foreach (var keyword in fileRegistry)
        {
            findings.Add(CreateKeywordFinding("File/registry/system keyword", Severity.Medium, keyword, macroText, location, "The macro references file system, registry, persistence, or environment locations.", 15));
        }

        if (summary.ObfuscationScore >= 30)
        {
            findings.Add(new Finding
            {
                Title = "Macro obfuscation indicators",
                Severity = Severity.Medium,
                Location = location,
                Evidence = $"Obfuscation score {summary.ObfuscationScore}",
                Explanation = "Obfuscation can hide commands, URLs, or payloads from casual review.",
                Recommendation = "Decode and inspect macro strings in a controlled analysis workflow.",
                ScoreImpact = 15
            });
        }

        return (summary, findings);
    }

    private static List<string> FindKeywords(string text, IEnumerable<string> keywords)
    {
        return keywords.Where(keyword => text.Contains(keyword, StringComparison.OrdinalIgnoreCase)).Distinct(StringComparer.OrdinalIgnoreCase).ToList();
    }

    private static Finding CreateKeywordFinding(string title, Severity severity, string keyword, string macroText, string location, string explanation, int score)
    {
        var lineNumber = FindLineNumber(macroText, keyword);
        return new Finding
        {
            Title = title,
            Severity = severity,
            Location = $"{location}: line {lineNumber}",
            Evidence = EvidenceSanitizer.Truncate(keyword),
            Explanation = explanation,
            Recommendation = "Treat this document as suspicious until an analyst confirms the macro purpose.",
            ScoreImpact = score
        };
    }

    private static int FindLineNumber(string text, string keyword)
    {
        using var reader = new StringReader(text);
        var lineNumber = 1;
        while (reader.ReadLine() is { } line)
        {
            if (line.Contains(keyword, StringComparison.OrdinalIgnoreCase))
            {
                return lineNumber;
            }

            lineNumber++;
        }

        return 1;
    }

    private static string BuildRiskExplanation(MacroAnalysisSummary summary)
    {
        if (summary.AutoExecFound && summary.SuspiciousKeywords.Count > 0)
        {
            return "Macro contains auto-execution plus suspicious behavior indicators.";
        }

        if (summary.SuspiciousKeywords.Count > 0)
        {
            return "Macro contains suspicious behavior indicators.";
        }

        return "Macro exists, but no high-confidence malicious behavior was confirmed by static keyword checks.";
    }

    [GeneratedRegex(@"(?i)\b(?:Sub|Function)\s+[A-Za-z_][A-Za-z0-9_]*", RegexOptions.Compiled)]
    private static partial Regex ProcedureRegex();

    [GeneratedRegex(@"(?i)\b(?:powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|schtasks)[^\r\n]{0,180}", RegexOptions.Compiled)]
    private static partial Regex CommandRegex();

    [GeneratedRegex(@"(?m)^.{500,}$", RegexOptions.Compiled)]
    private static partial Regex LongLineRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.Compiled)]
    private static partial Regex Base64Regex();
}
