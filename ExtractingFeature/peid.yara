rule UPX
{
    meta:
        description = "Detects UPX packed files"
    strings:
        $upx1 = "UPX!" ascii
        $upx2 = "UPX0" ascii
        $upx3 = "UPX1" ascii
        $upx4 = "UPX2" ascii
    condition:
        any of ($upx*)
}

rule ASPack
{
    meta:
        description = "Detects ASPack packed files"
    strings:
        $aspack1 = ".aspack" ascii
        $aspack2 = "ASPack protection" ascii
    condition:
        any of ($aspack*)
}

rule Themida
{
    meta:
        description = "Detects Themida packed files"
    strings:
        $themida1 = "Themida" ascii
        $themida2 = "WinLicense" ascii
    condition:
        any of ($themida*)
}

rule FSG
{
    meta:
        description = "Detects FSG packed files"
    strings:
        $fsg1 = "FSG!" ascii
        $fsg2 = "FSG packer" ascii
    condition:
        any of ($fsg*)
}

rule PECompact
{
    meta:
        description = "Detects PECompact packed files"
    strings:
        $pecompact1 = "PEC2" ascii
        $pecompact2 = "PECompact2" ascii
    condition:
        any of ($pecompact*)
}

rule Armadillo
{
    meta:
        description = "Detects Armadillo packed files"
    strings:
        $armadillo1 = "Armadillo" ascii
        $armadillo2 = "WinLic" ascii
    condition:
        any of ($armadillo*)
}

rule VMProtect
{
    meta:
        description = "Detects VMProtect packed files"
    strings:
        $vmprotect1 = "VMProtect" ascii
        $vmprotect2 = "VMProtectVirtualization" ascii
    condition:
        any of ($vmprotect*)
}

rule GenericPacker
{
    meta:
        description = "Detects generic packing patterns"
    strings:
        $packer1 = "packed" ascii
        $packer2 = "compressed" ascii
        $packer3 = ".pack" ascii
    condition:
        any of ($packer*)
}

