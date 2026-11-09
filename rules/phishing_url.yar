rule Suspicious_Phishing_Url_Text
{
    meta:
        severity = "medium"
        description = "Suspicious URL text indicators"
    strings:
        $u1 = "http://" nocase
        $u2 = "https://" nocase
        $u3 = ".zip" nocase
        $u4 = ".mov" nocase
        $u5 = "bit.ly" nocase
        $u6 = "tinyurl.com" nocase
    condition:
        ($u1 or $u2) and any of ($u3,$u4,$u5,$u6)
}
