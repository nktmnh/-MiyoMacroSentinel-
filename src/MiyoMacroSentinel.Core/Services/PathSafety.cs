namespace MiyoMacroSentinel.Core.Services;

public static class PathSafety
{
    public static bool IsSafeExtractionTarget(string baseDirectory, string candidatePath)
    {
        var baseFullPath = Path.GetFullPath(baseDirectory).TrimEnd(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar) + Path.DirectorySeparatorChar;
        var candidateFullPath = Path.GetFullPath(candidatePath);
        return candidateFullPath.StartsWith(baseFullPath, StringComparison.OrdinalIgnoreCase);
    }

    public static string CreateIsolatedTempDirectory(string? preferredRoot = null)
    {
        var root = string.IsNullOrWhiteSpace(preferredRoot) ? Path.GetTempPath() : preferredRoot;
        Directory.CreateDirectory(root);
        var directory = Path.Combine(root, "MiyoMacroSentinel-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        return directory;
    }
}
