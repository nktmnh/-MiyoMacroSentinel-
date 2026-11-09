rule Suspicious_PowerShell_EncodedCommand
{
    meta:
        severity = "high"
        description = "PowerShell encoded command indicator"
    strings:
        $e1 = "-enc" nocase
        $e2 = "-encodedcommand" nocase
        $p1 = "powershell" nocase
        $p2 = "FromBase64String" nocase
    condition:
        ($p1 and ($e1 or $e2)) or $p2
}
