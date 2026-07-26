param(
  [ValidateSet("Debug", "Release")]
  [string]$Configuration = "Debug",
  [switch]$SkipBuild
)

$ErrorActionPreference = "Stop"
$repo = Split-Path -Parent $PSScriptRoot
$fixture = Join-Path $PSScriptRoot "fixtures\COMPREHENSIVE.TPS"
$batchFixture = Join-Path $PSScriptRoot "fixtures\BATCH10001.TPS"
$workRoot = Join-Path ([IO.Path]::GetTempPath()) "tpsparser-regression"
$work = Join-Path $workRoot ([guid]::NewGuid().ToString("N"))
$corruptFixtureRoot = Join-Path $work "corrupt-fixtures"
$exitCode = 0

function Invoke-TestProcess {
  param(
    [Parameter(Mandatory)]
    [string]$Name,

    [Parameter(Mandatory)]
    [string]$FilePath,

    [string[]]$Arguments = @()
  )

  $startParameters = @{
    FilePath = $FilePath
    WorkingDirectory = $repo
    WindowStyle = "Hidden"
    Wait = $true
    PassThru = $true
  }
  if ($Arguments.Count -gt 0) {
    $startParameters.ArgumentList = $Arguments
  }
  $process = Start-Process @startParameters
  if ($process.ExitCode -ne 0) {
    throw "$Name returned exit code $($process.ExitCode)."
  }
}

try {
  if (-not $SkipBuild) {
    $msbuild = "C:\Program Files\Microsoft Visual Studio\2022\Professional\MSBuild\Current\Bin\MSBuild.exe"
    & $msbuild (Join-Path $repo "ParserTests.cwproj") /t:Build `
      "/p:Configuration=$Configuration" "/p:ClarionBinPath=L:\c11.1\bin" /m
    if ($LASTEXITCODE -ne 0) {
      throw "ParserTests build failed with exit code $LASTEXITCODE."
    }
  }

  New-Item -ItemType Directory -Path $work -Force | Out-Null
  & (Join-Path $PSScriptRoot "New-CorruptFixtures.ps1") `
    -SourcePath $fixture -DestinationDirectory $corruptFixtureRoot

  $falsePageCandidatePath = Join-Path $work "FalsePageCandidate.tmp"
  $falsePageCandidateBytes = [IO.File]::ReadAllBytes($batchFixture)
  $falsePageOuterOffset = 187392
  $falsePageNestedOffset = $falsePageOuterOffset + 256
  if ([BitConverter]::ToInt32($falsePageCandidateBytes, $falsePageOuterOffset) -ne $falsePageOuterOffset -or
      [BitConverter]::ToUInt16($falsePageCandidateBytes, $falsePageOuterOffset + 4) -ne 995 -or
      $falsePageCandidateBytes[$falsePageOuterOffset + 12] -ne 1) {
    throw "The false-page-candidate source layout changed; review the regression mutation offsets."
  }
  [BitConverter]::GetBytes([int]$falsePageNestedOffset).CopyTo(
    $falsePageCandidateBytes,
    $falsePageNestedOffset
  )
  [BitConverter]::GetBytes([uint16]0).CopyTo(
    $falsePageCandidateBytes,
    $falsePageNestedOffset + 4
  )
  [IO.File]::WriteAllBytes($falsePageCandidatePath, $falsePageCandidateBytes)

  $testExe = Join-Path $repo "ParserTests.exe"
  Invoke-TestProcess -Name "ParserTests.exe" -FilePath $testExe `
    -Arguments @($corruptFixtureRoot)
  Invoke-TestProcess -Name "False nested-page candidate regression" -FilePath $testExe `
    -Arguments @("--verify-false-page-candidate", $falsePageCandidatePath)

  $emptyFixturePath = Join-Path $work "EMPTY.TPS"
  Invoke-TestProcess -Name "Empty TPS fixture creation" -FilePath $testExe `
    -Arguments @("--create-empty", $emptyFixturePath)
  Invoke-TestProcess -Name "Empty TPS verification" -FilePath $testExe `
    -Arguments @("--verify-empty", $emptyFixturePath)

  Write-Host "Parser regression tests passed ($Configuration)."
}
catch {
  Write-Error -ErrorAction Continue $_
  $exitCode = 1
}
finally {
  if (Test-Path -LiteralPath $work -PathType Container) {
    $resolvedWorkRoot = [IO.Path]::GetFullPath($workRoot).TrimEnd("\")
    $resolvedWork = [IO.Path]::GetFullPath($work).TrimEnd("\")
    if ([IO.Path]::GetDirectoryName($resolvedWork) -ne $resolvedWorkRoot) {
      throw "Refusing to remove an unexpected regression path: $resolvedWork"
    }
    Remove-Item -LiteralPath $resolvedWork -Recurse -Force
  }
}

exit $exitCode
