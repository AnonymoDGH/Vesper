$ErrorActionPreference='Continue'
$Root = 'C:\Users\USUARIO\roblox-lua-exec\vesper'
$Repo = 'C:\Users\USUARIO\roblox-lua-exec'
$Luau = Join-Path $Repo 'ref\YuB-X\YuB-X-Module\Dependencies\Luau'
$Inc  = Join-Path $Root 'engine\include'
$Cxx  = 'g++'
$argv = @('-std=c++17','-O1','-w',
  "-I$Inc",
  "-I$(Join-Path $Luau 'Ast\include')",
  "-I$(Join-Path $Luau 'Bytecode\include')",
  "-I$(Join-Path $Luau 'Common\include')",
  "-I$(Join-Path $Luau 'Compiler\include')",
  "-I$(Join-Path $Luau 'VM\include')",
  "-I$(Join-Path $Luau 'VM\src')",
  "-I$(Join-Path $Luau 'Compiler\src')",
  "-I$(Join-Path $Luau 'Ast\src')",
  "-I$(Join-Path $Luau 'Bytecode\src')",
  '-o', (Join-Path $Root 'out\opdump.exe'),
  (Join-Path $Root 'tools\opdump.cpp'),
  (Join-Path $Root 'out\libluau.a'),
  '-static','-static-libgcc','-static-libstdc++','-lws2_32')
$line = (@($Cxx) + $argv | ForEach-Object { if ($_ -match '[\s"]') { '"' + ($_ -replace '"','\"') + '"' } else { $_ } }) -join ' '
$out = cmd /c "$line 2>&1"
$out | Select-Object -First 40
Write-Output ("exit=" + $LASTEXITCODE)
