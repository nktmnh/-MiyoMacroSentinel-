using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Parsers.Services;

public sealed class ParserScanResult
{
    public List<Finding> Findings { get; } = [];
    public List<string> TextArtifacts { get; } = [];
    public List<EmbeddedObjectInfo> EmbeddedObjects { get; } = [];
    public MacroAnalysisSummary? MacroAnalysis { get; set; }
    public bool PasswordProtected { get; set; }
    public bool Corrupted { get; set; }

    public void Merge(ParserScanResult other)
    {
        Findings.AddRange(other.Findings);
        TextArtifacts.AddRange(other.TextArtifacts);
        EmbeddedObjects.AddRange(other.EmbeddedObjects);
        PasswordProtected |= other.PasswordProtected;
        Corrupted |= other.Corrupted;
        if (other.MacroAnalysis is not null)
        {
            MacroAnalysis = other.MacroAnalysis;
        }
    }
}
