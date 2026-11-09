rule External_Office_Relationship
{
    meta:
        severity = "medium"
        description = "Office external relationship indicator"
    strings:
        $r1 = "TargetMode=\"External\"" nocase
        $r2 = "attachedTemplate" nocase
        $r3 = "http://" nocase
        $r4 = "https://" nocase
    condition:
        $r1 and any of ($r2,$r3,$r4)
}
