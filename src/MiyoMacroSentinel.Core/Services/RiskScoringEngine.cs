using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Core.Services;

public sealed class RiskScoringEngine
{
    public void Score(ScanResult result)
    {
        var score = 0;
        var confidenceSignals = 0;

        foreach (var finding in result.Findings)
        {
            score += finding.ScoreImpact > 0 ? finding.ScoreImpact : DefaultImpact(finding.Severity);
            if (!string.IsNullOrWhiteSpace(finding.Evidence))
            {
                confidenceSignals++;
            }
        }

        score += result.HiddenCharacters.Count > 0 ? Math.Min(20, result.HiddenCharacters.Count * 5) : 0;
        score += result.Iocs.Any(i => i.Type is IocType.Command) ? 15 : 0;
        score += result.Iocs.Any(i => i.Type is IocType.Url or IocType.ShortenedUrl or IocType.PunycodeDomain or IocType.SuspiciousTld) ? 10 : 0;
        score += result.DecodedArtifacts.Count > 0 ? Math.Min(15, result.DecodedArtifacts.Count * 3) : 0;
        score += result.YaraMatches.Sum(match => match.Severity switch
        {
            Severity.Critical => 40,
            Severity.High => 30,
            Severity.Medium => 20,
            Severity.Low => 10,
            _ => 0
        });

        result.RiskScore = Math.Clamp(score, 0, 100);
        result.RiskLevel = LevelForScore(result.RiskScore);
        result.Confidence = Math.Clamp(0.55 + confidenceSignals * 0.04 + result.YaraMatches.Count * 0.05, 0.55, 0.95);
        result.ExecutiveSummary = BuildSummary(result);
        result.Recommendations = BuildRecommendations(result);
        result.Limitations = BuildLimitations(result);
    }

    public static RiskLevel LevelForScore(int score) => score switch
    {
        <= 20 => RiskLevel.Clean,
        <= 40 => RiskLevel.Low,
        <= 60 => RiskLevel.Medium,
        <= 80 => RiskLevel.High,
        _ => RiskLevel.Critical
    };

    private static int DefaultImpact(Severity severity) => severity switch
    {
        Severity.Critical => 40,
        Severity.High => 25,
        Severity.Medium => 12,
        Severity.Low => 5,
        _ => 0
    };

    private static string BuildSummary(ScanResult result)
    {
        var fileName = result.Triage.FileName;
        var risk = result.RiskLevel.ToString();
        var evidenceCount = result.Findings.Count + result.HiddenCharacters.Count + result.Iocs.Count + result.YaraMatches.Count;
        return result.RiskLevel switch
        {
            RiskLevel.Clean => $"{fileName} appears clean based on local static checks. No malware is confirmed or executed.",
            RiskLevel.Low => $"{fileName} has low-risk indicators and should still be opened only from a trusted source.",
            RiskLevel.Medium => $"{fileName} is suspicious and requires analyst review. {evidenceCount} indicators were collected.",
            RiskLevel.High => $"{fileName} is high risk. Do not open it or enable active content until reviewed.",
            RiskLevel.Critical => $"{fileName} is critical risk based on strong static indicators. Isolate and escalate to IT/SOC.",
            _ => $"{fileName} risk level: {risk}."
        };
    }

    private static List<string> BuildRecommendations(ScanResult result)
    {
        if (result.RiskLevel is RiskLevel.High or RiskLevel.Critical)
        {
            return
            [
                "Do not open this file.",
                "Do not click Enable Content.",
                "Send the file to IT/SOC for review.",
                "Verify the sender.",
                "If already opened, disconnect from the network and notify an administrator.",
                "Không mở file này.",
                "Không bấm Enable Content.",
                "Gửi file cho bộ phận IT/SOC.",
                "Kiểm tra nguồn gửi file.",
                "Nếu đã mở file, hãy ngắt mạng và báo quản trị viên."
            ];
        }

        return
        [
            "Open only if the sender and business purpose are trusted.",
            "Keep Office protected view and macro blocking enabled.",
            "Review extracted IOCs before clicking links.",
            "Chỉ mở khi tin tưởng nguồn gửi và mục đích tài liệu."
        ];
    }

    private static List<string> BuildLimitations(ScanResult result)
    {
        var limitations = new List<string>
        {
            "Static analysis only. The scanner never executes macros or document content.",
            "A clean result does not guarantee that a file is safe.",
            "Missing optional engines such as YARA or oletools can reduce detection depth."
        };

        if (result.Triage.PasswordProtected)
        {
            limitations.Add("Password-protected content could not be fully inspected.");
        }

        return limitations;
    }
}
