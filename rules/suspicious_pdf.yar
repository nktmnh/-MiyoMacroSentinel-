rule Suspicious_PDF_JavaScript
{
    meta:
        severity = "high"
        description = "PDF JavaScript/OpenAction indicator"
    strings:
        $p = "%PDF"
        $j1 = "/JavaScript" nocase
        $j2 = "/JS" nocase
        $o = "/OpenAction" nocase
        $l = "/Launch" nocase
    condition:
        $p at 0 and any of ($j1,$j2,$o,$l)
}
