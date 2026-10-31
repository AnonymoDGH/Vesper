# Superficie Real sobre Vesper

Integración de la API recuperada de `Real.dll` (build 182) en el motor de Vesper.
Vesper pone el attach, la ABI, los hooks y la ejecución dentro del cliente; esta capa añade
los nombres que faltaban para que un script escrito contra Real funcione sin `attempt to call nil`.

## Archivos

| Ruta | Qué hace |
|---|---|
| `engine/include/vesper/real_surface.hpp` | declaración de `vesper::realx::install(lua_State*)` |
| `engine/src/real_surface.cpp` | aliases + implementaciones + stubs |
| `engine/src/env.cpp` | llama a `realx::install(thread)` al final de `env::install` |
| `out/realx_test.cpp` | test standalone de la superficie (sin Roblox) |
| `out/build_realx_test.bat` | compila y ejecuta el test |

## Qué añade

**Aliases** de lo que Vesper ya tenía: `get_genv`, `get_renv`, `get_thread_identity`,
`set_thread_identity`, `is_c_closure`, `is_l_closure`, `is_executor_closure`,
`clone_function`, `hook_function`, `new_c_closure`, `get_raw_metatable`, `set_readonly`,
`is_readonly`, `hook_meta_method`, `get_namecall_method`, `set_namecall_method`,
`read_file`, `write_file`, `append_file`, `is_file`, `is_folder`, `list_files`,
`del_file`, `del_folder`, `set_clipboard`, `base64_encode`, `base64_decode`.

**Nuevas, implementadas**:

- `identifyexecutor` / `getexecutorname` → `Real`; `getexecutorversion` → `2.7.10-vesper`.
- `gettenv`, `getreg`, `getregistry`.
- `gethwid` / `get_hwid` (MachineGuid + volumen + equipo, FNV-1a 64 ×2).
- `getpid` / `get_pid` / `getprocessidentifier`.
- `getfpscap` / `setfpscap` (y snake_case).
- `isrbxactive` / `isgameactive` / `iswindowactive`.
- `queue_on_teleport` / `queueonteleport` / `queue_on_tp` y `clear_teleport_queue`.
- `getfflag` / `setfflag`.
- `comparefunctions` / `compare_functions`, `getfunctionhash` / `get_function_hash`.
- `lz4compress` / `lz4_compress`, `lz4decompress` / `lz4_decompress` (bloque LZ4).
- `Drawing` (tabla con `new` → nil y `cleardrawcache`).

**Stubs seguros** (devuelven tabla vacía o nil, no rompen el script):
`getgc`, `filtergc`, `getloadedmodules`, `getrunningscripts`, `getscripts`, `getinstances`,
`getnilinstances`, `getscriptglobals`, `getscriptbytecode`, `getscriptclosure`,
`getscripthash`, `getscriptfunction`, `getcallingscript`, `decompile`, `dumpstring`,
`getconnections`, `firesignal`, `firetouchinterest`, `fireclickdetector`,
`fireproximityprompt`, `saveinstance`, `get/setrenderproperty`, `gethui`…

## Verificación

Standalone (sin Roblox, contra Luau upstream limpio):

```
[ok] identifyexecutor -> Real
[ok] getexecutorversion -> 2.7.10-vesper
[ok] gethwid length -> 32
[ok] gettenv type -> table
[ok] getreg type -> table
[ok] lz4 roundtrip -> 100
[ok] fflags -> 1
[ok] fpscap -> 144
[ok] getfunctionhash -> 16
[ok] getgc type -> table
[ok] Drawing -> table:nil
all checks passed
```

> El Luau vendorizado de Vesper no se puede usar fuera del cliente (su loader asume el espacio de
> opcodes de Roblox), por eso el test standalone enlaza el Luau limpio de
> `Real_DLL_Recovered/rebuild/third_party/luau`.

## Probar dentro de Roblox

```powershell
cd C:\Users\USUARIO\roblox-lua-exec\vesper
.\out\Vesper.exe --clients
.\out\Vesper.exe --launch --wait 40
.\out\Vesper.exe --exec tests\hello.lua
.\out\Vesper.exe --exec mi_script.lua
```

El cliente instalado es `version-9ac8595712b447a7` y hay offsets para esa build
(`dumps/9ac8-live.bin`). Para un script de prueba de la superficie Real:

```lua
print(identifyexecutor(), getexecutorversion())
print(gethwid(), getpid(), getfpscap())
writefile("real_surface.txt", "ok")
print(readfile("real_surface.txt"))
print(type(getgenv()), type(getreg()), type(gettenv()))
print(#lz4_decompress(lz4_compress("0123456789")))
```

## Límites

- `hookfunction`, `getrawmetatable`, `hookmetamethod` son los de Vesper: dependen de que el
  ABI/offsets de la build estén validados (es lo que ya hacía Vesper).
- Las funciones que necesitan el `DataModel`/registro de scripts siguen en stub: no hay puente
  a `ScriptContext` para `getscriptbytecode`, `getinstances`, `getconnections`, etc.
- `Drawing` requiere el overlay del shell; la tabla existe pero `Drawing.new` devuelve nil.
- Sin probar en cliente en esta sesión: el test hecho es el standalone de arriba.
