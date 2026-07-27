param(
    [Parameter(Mandatory)]
    [string]$SourcePath,

    [Parameter(Mandatory)]
    [string]$DestinationDirectory
)

$ErrorActionPreference = "Stop"

$resolvedSource = (Resolve-Path -LiteralPath $SourcePath).Path
$sourceBytes = [IO.File]::ReadAllBytes($resolvedSource)
if ($sourceBytes.Length -le 49672) {
    throw "The comprehensive fixture is shorter than the verified mutation offsets."
}
if ([BitConverter]::ToUInt16($sourceBytes, 7940) -ne 3124 -or
    [BitConverter]::ToUInt16($sourceBytes, 7942) -ne 3124 -or
    [BitConverter]::ToUInt16($sourceBytes, 7946) -ne 12 -or
    $sourceBytes[7948] -ne 0 -or
    [BitConverter]::ToInt32($sourceBytes, 0x20) -ne 0 -or
    [BitConverter]::ToInt32($sourceBytes, 0x110) -ne 0 -or
    [BitConverter]::ToUInt16($sourceBytes, 49412) -ne 10504 -or
    [BitConverter]::ToUInt16($sourceBytes, 49418) -ne 2 -or
    [BitConverter]::ToUInt16($sourceBytes, 49663) -ne 10256 -or
    [BitConverter]::ToUInt32($sourceBytes, 49668) -ne 40000) {
    throw "The comprehensive fixture layout changed; review the corruption offsets before updating them."
}

New-Item -ItemType Directory -Path $DestinationDirectory -Force | Out-Null

function Write-CorruptFixture {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Mutate
    )

    $bytes = [byte[]]$sourceBytes.Clone()
    & $Mutate $bytes
    [IO.File]::WriteAllBytes((Join-Path $DestinationDirectory $Name), $bytes)
}

Write-CorruptFixture -Name "CorruptCount.tmp" -Mutate {
    param([byte[]]$bytes)
    $bytes[49418] = 3
    $bytes[49419] = 0
}

Write-CorruptFixture -Name "CorruptRle.tmp" -Mutate {
    param([byte[]]$bytes)
    [BitConverter]::GetBytes([uint16]4000).CopyTo($bytes, 7942)
    $bytes[7949] = 0
}

Write-CorruptFixture -Name "CorruptPage.tmp" -Mutate {
    param([byte[]]$bytes)
    $bytes[49412] = 12
    $bytes[49413] = 0
}

Write-CorruptFixture -Name "CorruptBlockRange.tmp" -Mutate {
    param([byte[]]$bytes)
    $invalidBlockRef = [int](($bytes.Length - 512) / 256) + 1
    [BitConverter]::GetBytes($invalidBlockRef).CopyTo($bytes, 0x20)
    [BitConverter]::GetBytes($invalidBlockRef).CopyTo($bytes, 0x110)
}

Write-CorruptFixture -Name "CorruptBlob.tmp" -Mutate {
    param([byte[]]$bytes)
    [BitConverter]::GetBytes([int]40001).CopyTo($bytes, 49668)
}

Write-CorruptFixture -Name "CorruptBlobNegative.tmp" -Mutate {
    param([byte[]]$bytes)
    [BitConverter]::GetBytes([int]-1).CopyTo($bytes, 49668)
}

Write-CorruptFixture -Name "CorruptBlobMissing.tmp" -Mutate {
    param([byte[]]$bytes)
    $bytes[49663] = 15
    $bytes[49664] = 0
}
