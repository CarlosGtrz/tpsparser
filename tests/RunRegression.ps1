param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $PSScriptRoot "fixtures\COMPREHENSIVE.TPS"
$temporaryFiles = @(
  (Join-Path $PSScriptRoot "CorruptCount.tmp"),
  (Join-Path $PSScriptRoot "CorruptRle.tmp"),
  (Join-Path $PSScriptRoot "CorruptPage.tmp"),
  (Join-Path $PSScriptRoot "CorruptBlob.tmp"),
  (Join-Path $PSScriptRoot "CorruptBlobNegative.tmp"),
  (Join-Path $PSScriptRoot "CorruptBlobMissing.tmp")
)

function Set-UInt16LittleEndian {
  param([byte[]]$Bytes, [int]$Offset, [int]$Value)
  $Bytes[$Offset] = [byte]($Value -band 0xff)
  $Bytes[$Offset + 1] = [byte](($Value -shr 8) -band 0xff)
}

function Set-Int32LittleEndian {
  param([byte[]]$Bytes, [int]$Offset, [int]$Value)
  $encoded = [BitConverter]::GetBytes($Value)
  [Array]::Copy($encoded, 0, $Bytes, $Offset, 4)
}

try {
  if (-not $SkipBuild) {
    $msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    & $msbuild (Join-Path $repo "ParserTests.cwproj") /t:Build "/p:Configuration=$Configuration" "/p:ClarionBinPath=L:\c11.1\bin" /m
    if ($LASTEXITCODE -ne 0) {
      exit $LASTEXITCODE
    }
  }

  $bytes = [IO.File]::ReadAllBytes($fixture)
  Set-UInt16LittleEndian $bytes (49408 + 10) 2
  [IO.File]::WriteAllBytes($temporaryFiles[0], $bytes)

  $bytes = [IO.File]::ReadAllBytes($fixture)
  Set-UInt16LittleEndian $bytes (38912 + 6) 10271
  [IO.File]::WriteAllBytes($temporaryFiles[1], $bytes)

  $bytes = [IO.File]::ReadAllBytes($fixture)
  Set-UInt16LittleEndian $bytes (38912 + 4) 12
  [IO.File]::WriteAllBytes($temporaryFiles[2], $bytes)

  $bytes = [IO.File]::ReadAllBytes($fixture)
  Set-Int32LittleEndian $bytes 81924 50000
  Set-Int32LittleEndian $bytes 92676 50000
  [IO.File]::WriteAllBytes($temporaryFiles[3], $bytes)

  $bytes = [IO.File]::ReadAllBytes($fixture)
  Set-Int32LittleEndian $bytes 81924 -1
  Set-Int32LittleEndian $bytes 92676 -1
  [IO.File]::WriteAllBytes($temporaryFiles[4], $bytes)

  $bytes = [IO.File]::ReadAllBytes($fixture)
  Set-UInt16LittleEndian $bytes 81919 15
  Set-UInt16LittleEndian $bytes 92671 15
  foreach ($offset in 27931, 38939, 49435, 59931, 70427, 103195) {
    $bytes[$offset] = 2
  }
  [IO.File]::WriteAllBytes($temporaryFiles[5], $bytes)

  $testExe = Join-Path $repo "ParserTests.exe"
  $test = Start-Process -FilePath $testExe -WorkingDirectory $repo -WindowStyle Hidden -Wait -PassThru
  exit $test.ExitCode
}
finally {
  foreach ($path in $temporaryFiles) {
    Remove-Item -LiteralPath $path -Force -ErrorAction SilentlyContinue
  }
}
