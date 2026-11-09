rule Office_AutoExec_Macro
{
    meta:
        severity = "high"
        description = "Office macro auto-execution indicators"
    strings:
        $a1 = "AutoOpen" nocase
        $a2 = "Document_Open" nocase
        $a3 = "Workbook_Open" nocase
        $a4 = "AutoExec" nocase
    condition:
        any of them
}

rule Office_Suspicious_PowerShell_Macro
{
    meta:
        severity = "high"
        description = "Macro references PowerShell or script execution"
    strings:
        $p1 = "powershell" nocase
        $p2 = "pwsh" nocase
        $p3 = "WScript.Shell" nocase
        $p4 = "CreateObject" nocase
        $p5 = "cmd.exe" nocase
    condition:
        2 of them
}
