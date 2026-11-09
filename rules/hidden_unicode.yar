rule Hidden_Unicode_Bidi_Or_ZeroWidth
{
    meta:
        severity = "medium"
        description = "Hidden Unicode control characters"
    strings:
        $zwsp = { E2 80 8B }
        $zwnj = { E2 80 8C }
        $zwj  = { E2 80 8D }
        $rlo  = { E2 80 AE }
        $lro  = { E2 80 AD }
    condition:
        any of them
}
