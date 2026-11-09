using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace MiyoMacroSentinel.Core.Services;

public static partial class EvidenceSanitizer
{
    public static string Truncate(string? value, int maxLength = 240)
    {
        if (string.IsNullOrEmpty(value))
        {
            return "";
        }

        var normalized = ControlWhitespaceRegex().Replace(value, " ").Trim();
        return normalized.Length <= maxLength ? normalized : normalized[..maxLength] + "...";
    }

    public static string Defang(string value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return value;
        }

        var output = value
            .Replace("http://", "hxxp://", StringComparison.OrdinalIgnoreCase)
            .Replace("https://", "hxxps://", StringComparison.OrdinalIgnoreCase)
            .Replace("ftp://", "fxp://", StringComparison.OrdinalIgnoreCase);

        output = DomainDotRegex().Replace(output, "[.]");
        return output;
    }

    public static string Html(string value) => WebUtility.HtmlEncode(value ?? "");

    public static string NormalizeForDisplay(string value)
    {
        var builder = new StringBuilder(value.Length);
        foreach (var ch in value)
        {
            builder.Append(char.IsControl(ch) && ch is not '\r' and not '\n' and not '\t' ? ' ' : ch);
        }

        return builder.ToString();
    }

    [GeneratedRegex(@"\s+", RegexOptions.Compiled)]
    private static partial Regex ControlWhitespaceRegex();

    [GeneratedRegex(@"\.(?=[A-Za-z0-9-]{2,63}(?:[/:?#]|$))", RegexOptions.Compiled)]
    private static partial Regex DomainDotRegex();
}
