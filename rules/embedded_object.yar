rule Embedded_Object_Indicator
{
    meta:
        severity = "medium"
        description = "Embedded object indicators in document packages"
    strings:
        $o1 = "embeddings/" nocase
        $o2 = "oleObject" nocase
        $o3 = "Ole10Native" nocase
        $o4 = "activeX" nocase
    condition:
        any of them
}
