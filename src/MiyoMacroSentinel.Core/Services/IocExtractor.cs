using System.Net;
using System.Text.RegularExpressions;
using MiyoMacroSentinel.Core.Models;

namespace MiyoMacroSentinel.Core.Services;

public sealed partial class IocExtractor
{
    private static readonly HashSet<string> ShortenerDomains = new(StringComparer.OrdinalIgnoreCase)
    {
        "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "cutt.ly", "rebrand.ly", "shorturl.at"
    };

    private static readonly HashSet<string> SuspiciousTlds = new(StringComparer.OrdinalIgnoreCase)
    {
        "zip", "mov", "click", "top", "xyz", "tk", "ml", "ga", "cf", "gq", "work", "rest", "cam"
    };

    public List<Ioc> Extract(string text, string location, bool defang = true)
    {
        var results = new List<Ioc>();
        if (string.IsNullOrWhiteSpace(text))
        {
            return results;
        }

        AddMatches(results, UrlRegex().Matches(text), IocType.Url, location, defang);
        AddMatches(results, EmailRegex().Matches(text), IocType.Email, location, defang);
        AddMatches(results, Ipv4Regex().Matches(text), IocType.IPv4, location, defang);
        AddMatches(results, Ipv6Regex().Matches(text), IocType.IPv6, location, defang);
        AddMatches(results, UncRegex().Matches(text), IocType.UncPath, location, defang);
        AddMatches(results, RegistryRegex().Matches(text), IocType.RegistryPath, location, defang);
        AddMatches(results, WindowsPathRegex().Matches(text), IocType.FilePath, location, defang);
        AddMatches(results, HashRegex().Matches(text), IocType.Hash, location, defang);
        AddMatches(results, Base64Regex().Matches(text), IocType.Base64Like, location, defang, "Long Base64-like string; decode only as static text.");
        AddMatches(results, CommandRegex().Matches(text), IocType.Command, location, defang);
        AddMatches(results, ScriptRegex().Matches(text), IocType.ScriptName, location, defang);
        AddMatches(results, DomainRegex().Matches(text), IocType.Domain, location, defang);

        if (text.Contains("MZ", StringComparison.Ordinal) || text.Contains("TVqQAAMAAAAEAAAA", StringComparison.Ordinal))
        {
            results.Add(Create(IocType.PeHeader, "MZ/PE indicator", location, defang, "Possible embedded PE header indicator."));
        }

        var domains = results
            .Where(i => i.Type is IocType.Url or IocType.Domain)
            .Select(i => ExtractHost(i.Original))
            .Where(h => !string.IsNullOrWhiteSpace(h))
            .Distinct(StringComparer.OrdinalIgnoreCase)
            .ToList();

        foreach (var domain in domains)
        {
            if (ShortenerDomains.Contains(domain!))
            {
                results.Add(Create(IocType.ShortenedUrl, domain!, location, defang, "URL shorteners can hide the final destination."));
            }

            if (domain!.StartsWith("xn--", StringComparison.OrdinalIgnoreCase) || domain.Contains(".xn--", StringComparison.OrdinalIgnoreCase))
            {
                results.Add(Create(IocType.PunycodeDomain, domain, location, defang, "Punycode can disguise internationalized phishing domains."));
            }

            var tld = domain.Split('.').LastOrDefault();
            if (!string.IsNullOrWhiteSpace(tld) && SuspiciousTlds.Contains(tld))
            {
                results.Add(Create(IocType.SuspiciousTld, domain, location, defang, $"Domain uses suspicious TLD .{tld}."));
            }
        }

        return Deduplicate(results);
    }

    private static void AddMatches(List<Ioc> results, MatchCollection matches, IocType type, string location, bool defang, string notes = "")
    {
        foreach (Match match in matches)
        {
            if (!match.Success)
            {
                continue;
            }

            var value = match.Value.Trim(' ', '\t', '\r', '\n', '.', ',', ';', ')', ']', '}');
            if (value.Length == 0)
            {
                continue;
            }

            results.Add(Create(type, value, location, defang, notes));
        }
    }

    private static Ioc Create(IocType type, string value, string location, bool defang, string notes)
    {
        return new Ioc
        {
            Type = type,
            Original = EvidenceSanitizer.Truncate(value, 600),
            DisplayValue = defang ? EvidenceSanitizer.Defang(EvidenceSanitizer.Truncate(value, 600)) : EvidenceSanitizer.Truncate(value, 600),
            Location = location,
            Notes = notes
        };
    }

    private static List<Ioc> Deduplicate(IEnumerable<Ioc> iocs)
    {
        return iocs
            .GroupBy(i => $"{i.Type}|{i.Original}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .Take(500)
            .ToList();
    }

    private static string? ExtractHost(string value)
    {
        if (Uri.TryCreate(value, UriKind.Absolute, out var uri))
        {
            return uri.Host;
        }

        var candidate = value.Trim().TrimEnd('/');
        if (candidate.Contains('@') || IPAddress.TryParse(candidate, out _))
        {
            return null;
        }

        return candidate.Contains('.') ? candidate : null;
    }

    [GeneratedRegex(@"(?i)\b(?:https?|ftp)://[^\s<>'""\)\]]+", RegexOptions.Compiled)]
    private static partial Regex UrlRegex();

    [GeneratedRegex(@"(?i)\b[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}\b", RegexOptions.Compiled)]
    private static partial Regex EmailRegex();

    [GeneratedRegex(@"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b", RegexOptions.Compiled)]
    private static partial Regex Ipv4Regex();

    [GeneratedRegex(@"\b(?:[A-Fa-f0-9]{1,4}:){2,7}[A-Fa-f0-9]{1,4}\b", RegexOptions.Compiled)]
    private static partial Regex Ipv6Regex();

    [GeneratedRegex(@"\\\\[A-Za-z0-9._$-]+\\[^\s<>'""]+", RegexOptions.Compiled)]
    private static partial Regex UncRegex();

    [GeneratedRegex(@"(?i)\bHK(?:CU|LM|CR|U|CC)\\[^\s<>'""]+", RegexOptions.Compiled)]
    private static partial Regex RegistryRegex();

    [GeneratedRegex(@"(?i)\b[A-Z]:\\[^\r\n\t<>'""]+", RegexOptions.Compiled)]
    private static partial Regex WindowsPathRegex();

    [GeneratedRegex(@"\b(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{64})\b", RegexOptions.Compiled)]
    private static partial Regex HashRegex();

    [GeneratedRegex(@"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{80,}={0,2}(?![A-Za-z0-9+/=])", RegexOptions.Compiled)]
    private static partial Regex Base64Regex();

    [GeneratedRegex(@"(?i)\b(?:powershell|pwsh|cmd\.exe|mshta|wscript|cscript|rundll32|regsvr32|certutil|bitsadmin|schtasks)(?:\s+[^\r\n]{0,160})?", RegexOptions.Compiled)]
    private static partial Regex CommandRegex();

    [GeneratedRegex(@"(?i)\b[A-Za-z0-9_\-]+\.(?:ps1|vbs|js|jse|wsf|hta|bat|cmd|exe|dll|scr)\b", RegexOptions.Compiled)]
    private static partial Regex ScriptRegex();

    [GeneratedRegex(@"(?i)\b(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+(?:com|net|org|vn|io|co|info|biz|top|xyz|ru|cn|zip|mov|click|link|work|tk|ml|ga|cf|gq|rest|cam)\b", RegexOptions.Compiled)]
    private static partial Regex DomainRegex();
}
