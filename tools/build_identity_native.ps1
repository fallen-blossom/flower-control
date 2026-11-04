param(
    [Parameter(Mandatory=$true)][string]$OutputDirectory,
    [string]$CompilerSetup
)
$ErrorActionPreference = 'Stop'
function Get-Sha256([string]$Path) {
    $stream = [IO.File]::OpenRead($Path)
    $hasher = [Security.Cryptography.SHA256]::Create()
    try { return [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '').ToLowerInvariant() }
    finally { $stream.Dispose(); $hasher.Dispose() }
}
if (-not $CompilerSetup) {
    $vswhere = Join-Path ${env:ProgramFiles(x86)} 'Microsoft Visual Studio\Installer\vswhere.exe'
    if (-not (Test-Path -LiteralPath $vswhere -PathType Leaf)) { throw 'installed_cpp_tools_not_found' }
    $installations = @(& $vswhere -latest -products '*' -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath)
    if ($LASTEXITCODE -ne 0 -or $installations.Count -ne 1 -or -not $installations[0]) { throw 'installed_cpp_tools_not_found' }
    $CompilerSetup = Join-Path $installations[0] 'VC\Auxiliary\Build\vcvarsall.bat'
}
$repositoryPath = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..'))
$sourcePath = Join-Path $repositoryPath 'flower_control\drivers\high_helper\program_identity_native.cpp'
$compilerPath = [IO.Path]::GetFullPath($CompilerSetup)
$outputPath = [IO.Path]::GetFullPath($OutputDirectory)
$tempPath = [IO.Path]::GetFullPath([IO.Path]::GetTempPath()).TrimEnd('\')
if ($CompilerSetup -notmatch '^[A-Za-z]:[\\/]' -or $OutputDirectory -notmatch '^[A-Za-z]:[\\/]' -or
    -not $outputPath.StartsWith($tempPath + '\', [StringComparison]::OrdinalIgnoreCase) -or
    (Test-Path -LiteralPath $outputPath)) { throw 'new_os_temp_build_directory_required' }
$parent = [IO.Path]::GetDirectoryName($outputPath)
if (-not (Test-Path -LiteralPath $parent -PathType Container)) { throw 'build_parent_missing' }
while ($parent.Length -ge $tempPath.Length) {
    $item = Get-Item -LiteralPath $parent -Force
    if (($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) { throw 'build_parent_reparse_rejected' }
    if ($parent.Equals($tempPath, [StringComparison]::OrdinalIgnoreCase)) { break }
    $parent = [IO.Path]::GetDirectoryName($parent)
}
foreach ($path in @($repositoryPath, $compilerPath, $outputPath)) {
    if ($path.IndexOfAny([char[]]'"%&!^|<>') -ge 0 -or $path -cmatch '[\x00-\x1f\x7f-\uffff]') {
        throw 'build_path_invalid'
    }
}
if (-not (Test-Path -LiteralPath $sourcePath -PathType Leaf) -or
    -not (Test-Path -LiteralPath $compilerPath -PathType Leaf)) { throw 'build_input_missing' }
$before = Get-Sha256 $sourcePath
New-Item -ItemType Directory -Path $outputPath | Out-Null
$cmdPath = Join-Path $outputPath 'compile-identity.cmd'
$body = @"
@echo off
call "$compilerPath" x64 >nul
if errorlevel 1 exit /b 1
cd /d "$outputPath"
where cl.exe > compiler-path.txt
if errorlevel 1 exit /b 1
where link.exe > linker-path.txt
if errorlevel 1 exit /b 1
cl /nologo /std:c++20 /EHsc /W4 /WX /guard:cf /sdl /utf-8 /DUNICODE /D_UNICODE /LD "$sourcePath" /Fo:identity.obj /Fe:Flower.UacNative.dll /link /Brepro /DYNAMICBASE /NXCOMPAT advapi32.lib wintrust.lib crypt32.lib bcrypt.lib
exit /b %errorlevel%
"@
[IO.File]::WriteAllText($cmdPath, $body, [Text.Encoding]::ASCII)
$logPath = Join-Path $outputPath 'build.log'
& $env:ComSpec /d /c $cmdPath *> $logPath
$resultCode = $LASTEXITCODE
$after = Get-Sha256 $sourcePath
if ($resultCode -ne 0 -or $before -ne $after) { throw 'identity_native_build_failed_or_source_changed' }
$dllPath = Join-Path $outputPath 'Flower.UacNative.dll'
if (-not (Test-Path -LiteralPath $dllPath -PathType Leaf)) { throw 'identity_native_binary_missing' }
$compilerBinary = [IO.File]::ReadAllLines((Join-Path $outputPath 'compiler-path.txt'))[0]
$linkerBinary = [IO.File]::ReadAllLines((Join-Path $outputPath 'linker-path.txt'))[0]
$evidence = [ordered]@{
    schema = 1
    source = $sourcePath
    source_sha256 = $before
    build_script_sha256 = Get-Sha256 $PSCommandPath
    compiler_setup = $compilerPath
    compiler_setup_sha256 = Get-Sha256 $compilerPath
    compiler_binary = $compilerBinary
    compiler_binary_sha256 = Get-Sha256 $compilerBinary
    linker_binary = $linkerBinary
    linker_binary_sha256 = Get-Sha256 $linkerBinary
    dll = $dllPath
    dll_sha256 = Get-Sha256 $dllPath
    build_exit_code = $resultCode
    source_unchanged = $true
    installed = $false
}
$evidence | ConvertTo-Json -Depth 3 | Set-Content -LiteralPath (Join-Path $outputPath 'build-evidence.json') -Encoding UTF8
$evidence | ConvertTo-Json -Compress
