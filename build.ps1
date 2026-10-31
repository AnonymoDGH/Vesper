<#
.SYNOPSIS
  Builds Vesper.

.DESCRIPTION
  Two targets:
    engine  -> out\Vesper.dll   (injected into Roblox, hosts the bridge)
    shell   -> out\Vesper.exe   (Win32 + WebView2 host for the UI)
    all     -> both

  The Luau static library is built once and reused. Nothing is rebuilt unless a
  source is newer than its object, so repeat builds are quick.

.EXAMPLE
  .\build.ps1 -Target engine
  .\build.ps1 -Target all -Clean
#>
[CmdletBinding()]
param(
    [ValidateSet('engine', 'shell', 'all')]
    [string]$Target = 'all',
    [switch]$Clean,
    [switch]$RebuildLuau
)

$ErrorActionPreference = 'Continue'
$Root   = $PSScriptRoot
$Repo   = Split-Path $Root -Parent
$Luau   = Join-Path $Repo 'ref\YuB-X\YuB-X-Module\Dependencies\Luau'
$Inc    = Join-Path $Root 'engine\include'
$Src    = Join-Path $Root 'engine\src'
$Out    = Join-Path $Root 'out'
$Obj    = Join-Path $Out 'obj'
$LuauObj= Join-Path $Out 'luau'
$Cxx    = 'g++'
$CxxDir = Split-Path (Get-Command $Cxx).Source -Parent
$Ar     = 'ar'

$LuauIncludes = @(
    "-I$Inc",
    "-I$(Join-Path $Luau 'Ast\include')",
    "-I$(Join-Path $Luau 'Bytecode\include')",
    "-I$(Join-Path $Luau 'Common\include')",
    "-I$(Join-Path $Luau 'Compiler\include')",
    "-I$(Join-Path $Luau 'VM\include')",
    "-I$(Join-Path $Luau 'VM\src')",
    "-I$(Join-Path $Luau 'Compiler\src')",
    "-I$(Join-Path $Luau 'Ast\src')",
    "-I$(Join-Path $Luau 'Bytecode\src')"
)

$CommonFlags = @('-std=c++17', '-O2', '-w', '-ffunction-sections', '-fdata-sections',
                 '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX', '-D_WIN32_WINNT=0x0601')

function New-Dir([string]$Path) {
    if (-not (Test-Path $Path)) { New-Item -ItemType Directory -Force -Path $Path | Out-Null }
}

# Runs a native tool through cmd so stderr arrives as plain text instead of as
# PowerShell error records, which is what makes compiler failures readable.
function Invoke-Tool {
    param([string[]]$Argv)
    $line = ($Argv | ForEach-Object {
        if ($_ -match '[\s"]') { '"' + ($_ -replace '"', '\"') + '"' } else { $_ }
    }) -join ' '
    $output = cmd /c "$line 2>&1"
    return @{
        Code   = $LASTEXITCODE
        Output = @($output)
    }
}

# A source is rebuilt when it, or any header it might reach, is newer than its
# object. Scanning the header trees is cheaper than tracking includes by hand, and
# it removes the stale-object trap where editing a .hpp silently does nothing.
function Invoke-NeedsBuild([string]$Source, [string]$Object, [string[]]$Headers = @()) {
    if (-not (Test-Path $Object)) { return $true }
    $stamp = (Get-Item $Object).LastWriteTime
    if ((Get-Item $Source).LastWriteTime -gt $stamp) { return $true }
    foreach ($dir in $Headers) {
        if ([string]::IsNullOrEmpty($dir) -or -not (Test-Path $dir)) { continue }
        $newer = Get-ChildItem $dir -Recurse -Include *.hpp, *.h -File -ErrorAction SilentlyContinue |
                 Where-Object { $_.LastWriteTime -gt $stamp } | Select-Object -First 1
        if ($null -ne $newer) { return $true }
    }
    return $false
}

function Build-Luau {
    if ((Test-Path (Join-Path $Out 'libluau.a')) -and -not $RebuildLuau) {
        Write-Host '  luau      up to date' -ForegroundColor DarkGray
        return
    }

    New-Dir $LuauObj
    $sources = Get-ChildItem (Join-Path $Luau 'VM\src'), (Join-Path $Luau 'Compiler\src'),
                              (Join-Path $Luau 'Ast\src'), (Join-Path $Luau 'Bytecode\src'),
                              (Join-Path $Luau 'Common\src') -Filter *.cpp -File |
               Sort-Object FullName

    Write-Host ("  luau      compiling {0} sources" -f $sources.Count)
    $failures = @()
    foreach ($source in $sources) {
        $object = Join-Path $LuauObj ($source.BaseName + '.o')
        if (-not (Invoke-NeedsBuild $source.FullName $object @($Luau))) { continue }
        $result = Invoke-Tool (@($Cxx) + $CommonFlags + $LuauIncludes + @('-c', $source.FullName, '-o', $object))
        if ($result.Code -ne 0) {
            $failures += [pscustomobject]@{ File = $source.Name; Log = ($result.Output | Select-Object -First 6) }
        }
    }

    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) {
            Write-Host ("    FAILED {0}" -f $failure.File) -ForegroundColor Red
            $failure.Log | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
        }
        throw 'libluau.a did not build'
    }

    $luauObjects = (Get-ChildItem $LuauObj -Filter *.o | ForEach-Object { $_.FullName })
    $archive = Invoke-Tool (@($Ar, 'rcs', (Join-Path $Out 'libluau.a')) + $luauObjects)
    if ($archive.Code -ne 0) {
        $archive.Output | Select-Object -First 12 | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
        throw 'archiving libluau.a failed'
    }
    Write-Host ("  luau      libluau.a {0:N0} bytes" -f (Get-Item (Join-Path $Out 'libluau.a')).Length) -ForegroundColor Green
}

function Build-Engine {
    New-Dir $Obj

    $sources = Get-ChildItem $Src -Filter *.cpp -File | Sort-Object Name
    $objects = @()
    $failures = @()

    foreach ($source in $sources) {
        $object = Join-Path $Obj ($source.BaseName + '.o')
        $objects += $object
        if (-not (Invoke-NeedsBuild $source.FullName $object @($Inc, $Luau))) { continue }

        $result = Invoke-Tool (@($Cxx) + $CommonFlags + $LuauIncludes + @('-c', $source.FullName, '-o', $object))
        if ($result.Code -ne 0) {
            $failures += [pscustomobject]@{ File = $source.Name; Log = ($result.Output | Select-Object -First 10) }
        } else {
            Write-Host ("  engine    {0}" -f $source.Name) -ForegroundColor DarkGray
        }
    }

    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) {
            Write-Host ("    FAILED {0}" -f $failure.File) -ForegroundColor Red
            $failure.Log | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
        }
        throw 'engine did not compile'
    }

    $dll = Join-Path $Out 'Vesper.dll'
    $link = @('-shared', '-o', $dll, '-Wl,--gc-sections', '-static', '-static-libgcc',
              '-static-libstdc++', '-Wl,--enable-auto-image-base')
    $link += $objects
    $link += Join-Path $Out 'libluau.a'
    # wininet, not winhttp: the host already has wininet loaded and will not load
    # a new module for us. No --export-all-symbols either: the entry points carry
    # __declspec(dllexport) and a DLL that exports the whole of libstdc++ has an
    # export table nothing else has.
    $link += @('-lws2_32', '-lwininet', '-lpsapi', '-lole32', '-loleaut32', '-luuid', '-luser32',
               '-ladvapi32', '-lgdi32', '-lshlwapi')

    $result = Invoke-Tool (@($Cxx) + $link)
    if ($result.Code -ne 0) {
        Write-Host '    FAILED link' -ForegroundColor Red
        $result.Output | Select-Object -First 60 | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
        throw 'link failed'
    }

    Write-Host ("  engine    Vesper.dll {0:N0} bytes" -f (Get-Item $dll).Length) -ForegroundColor Green
    return $dll
}

function Build-Shell {
    New-Dir $Obj
    $shellSrc = Join-Path $Root 'shell\src'
    $shellObj = Join-Path $Out 'shellobj'
    New-Dir $shellObj

    $sources = Get-ChildItem $shellSrc -Filter *.cpp -File | Sort-Object Name
    $objects = @()
    $failures = @()

    foreach ($source in $sources) {
        $object = Join-Path $shellObj ($source.BaseName + '.o')
        $objects += $object
        if (-not (Invoke-NeedsBuild $source.FullName $object @($shellSrc, $Inc))) { continue }
        $flags = @('-std=c++17', '-O2', '-w', '-municode', "-I$Inc", '-D_WIN32_WINNT=0x0601',
                   '-DWIN32_LEAN_AND_MEAN', '-DNOMINMAX',
                   "-I$(Join-Path $Root 'shell\src')", "-I$(Join-Path $Root 'shell\third_party')")
        $result = Invoke-Tool (@($Cxx) + $flags + @('-c', $source.FullName, '-o', $object))
        if ($result.Code -ne 0) {
            $failures += [pscustomobject]@{ File = $source.Name; Log = ($result.Output | Select-Object -First 10) }
        } else {
            Write-Host ("  shell     {0}" -f $source.Name) -ForegroundColor DarkGray
        }
    }

    if ($failures.Count -gt 0) {
        foreach ($failure in $failures) {
            Write-Host ("    FAILED {0}" -f $failure.File) -ForegroundColor Red
            $failure.Log | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
        }
        throw 'shell did not compile'
    }

    $exe = Join-Path $Out 'Vesper.exe'

    # The manifest is what makes the process per-monitor DPI aware and pulls in
    # common controls v6, without which the dark-mode control theming is a no-op.
    $manifestRc = Join-Path $Root 'shell\src\vesper.rc'
    $resources = Join-Path $Root 'shell\third_party\resources.res'
    if (Test-Path $manifestRc) {
        New-Dir (Split-Path $resources -Parent)
        $windres = Join-Path $CxxDir 'windres.exe'
        $res = Invoke-Tool @($windres, '-I', (Join-Path $Root 'shell\src'), '-O', 'coff',
                             '-i', $manifestRc, '-o', $resources)
        if ($res.Code -ne 0) {
            Write-Host '    FAILED resources' -ForegroundColor Red
            $res.Output | Select-Object -First 20 | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
            throw 'resource compile failed'
        }
        Write-Host '  shell     resources' -ForegroundColor DarkGray
    }

    $link = @('-o', $exe, '-mwindows', '-municode', '-static')
    $link += $objects
    if (Test-Path $resources) { $link += $resources }
    $link += @('-ld2d1', '-ldwrite', '-ldwmapi', '-luxtheme', '-lcomctl32', '-lwinhttp', '-lpsapi',
               '-lshlwapi', '-lole32', '-loleaut32', '-luuid', '-luser32', '-lgdi32',
               '-ladvapi32', '-lshell32', '-lcomdlg32')

    $result = Invoke-Tool (@($Cxx) + $link)
    if ($result.Code -ne 0) {
        Write-Host '    FAILED link' -ForegroundColor Red
        $result.Output | Select-Object -First 40 | ForEach-Object { Write-Host ("      {0}" -f $_) -ForegroundColor DarkRed }
        throw 'link failed'
    }

    Write-Host ("  shell     Vesper.exe {0:N0} bytes" -f (Get-Item $exe).Length) -ForegroundColor Green
}

if ($Clean) {
    Write-Host 'cleaning' -ForegroundColor Yellow
    foreach ($path in @($Obj, (Join-Path $Out 'shellobj'))) {
        if (Test-Path $path) { Remove-Item $path -Recurse -Force }
    }
}

New-Dir $Out
Write-Host 'vesper build' -ForegroundColor Cyan

Build-Luau
if ($Target -in @('engine', 'all')) { Build-Engine | Out-Null }
if ($Target -in @('shell', 'all'))  { Build-Shell }

Write-Host 'done' -ForegroundColor Cyan
