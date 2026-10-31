# Build `version-9ac8595712b447a7` — estado medido

Todo lo de abajo está respaldado por una línea de log, un volcado o una medición
del proceso. Lo que es hipótesis se dice explícitamente.

---

## 1. Lo que funciona

| Pieza | Evidencia |
|---|---|
| Perfil embebido | `offsets: loaded version-9ac8595712b447a7 from embedded table (243 entries)` |
| `lua_State` sin llamar al cliente | `attach: decoded sc+0x200 -> 0x… plausible=1 validate_state=1` |
| `ScriptContext` por trabajos | `attach: script context=0x… (strategy 3/via-jobs)` |
| `lua_State` del juego | `attach: lua state=0x…` |
| Arranque en línea, sin hilos | `engine: startup thread N finished the session` |
| Relevo si el hilo muere | `entry: startup thread N is gone before finishing; taking the claim over` |
| Relevo de la bandera de orden | `pump: command thread N is gone; taking the busy flag over` |
| Canal de órdenes | `serve:` → `command #1: claimed on tid N` → `exec_source` |
| Compilación | `exec: compiled 68 bytes with vendored->internal` |

## 2. Layout de `9ac8` (fuente: dump de estructuras del build)

```
lua_State (136 bytes)
  0x00 marked/memcat/tt     0x03 status        0x08 gt
  0x10 end_ci               0x18 base_ci       0x20 nCcalls (u16)
  0x22 baseCcalls           0x24 cachedslot    0x28 userdata (RobloxExtraSpace*)
  0x30 finalizers           0x38 namecall      0x40 gclist
  0x48 openupval            0x50 ci            0x58 base
  0x60 stack                0x68 stack_last    0x70 top
  0x78 global               0x80 stacksize (codificado)  0x84 size_ci

LuaTable
  tt +0x02   safeenv +0x04   nodemask8 +0x05   lsizenode +0x06   readonly +0x07
  sizearray +0x08            metatable +0x10   array +0x18        node +0x20

LuaNode (medido, no el de Luau upstream)
  paso 0x20; valor en +0x00 y clave en +0x10; tt de cada TValue en +0x0C

TString
  len +0x14   data +0x18   (hash en +0x10, codificado)

global_State
  registry (TValue) +0x618   mainthread +0x1A0   cb_userthread +0x648
```

Los tags **no** son los de Luau estándar. Se resuelven leyendo
`luaT_typenames` (RVA `0x67DCAB0`) del propio cliente: en este build
`string = 6`, `table = 7`, `function = 8`, `userdata = 9`.

Codificación de `stacksize`: `valor ^ (uint32)dirección` (`vmval3` en el dump de
estructuras del build). Verificado contra la ventana de pila.

## 3. Identificación del trabajo correcto

Hay dos `WaitingHybridScriptsJob`. Dos criterios independientes coinciden:

| Trabajo | `registry_sizearray` | `owned` (+0x198) | Conclusión |
|---|---|---|---|
| A | `4` | fuera del DataModel real | shell de la app |
| B | `2048` | `real_dm − 0x1f0` | partida |

`owned` cae en la misma región que el DataModel, desplazado `0x1f0`, que es
`RenderJob::RealDataModel` en los offsets públicos del build. El motor elige B.

## 4. El muro

### 4.1 Llamar al cargador termina la sesión

Cuatro procedencias, mismo resultado: **sesión terminada, sin minidump**.

| Procedencia | Evidencia |
|---|---|
| Hilo sintético `pvt::make` | `step: pvt::make end thread=0x…` y silencio |
| Estado real del juego | `lane D: loading on the game's own state` y cierre |
| Llamada directa | `exec: luau_load(parent) …` y cierre |
| Call gate dentro de `fltlib` | `exec: call gate at 0x180004240` y cierre |

El `CrashHandler` registra `Will not add to session state` y no aparece `.dmp`:
no es un fallo de memoria, es el cliente terminando su sesión.

### 4.2 Crear un hilo remoto no es una opción

`CreateRemoteThread` con `NtContinue` y contexto propio muere con `0xC000071C`
tanto apuntando a nuestra entrada como a la rutina del gate (dentro de imagen).
Lo que se castiga es **crear el hilo**, no dónde empieza.

### 4.3 `.text` no es escribible

`VirtualProtect(PAGE_EXECUTE_READWRITE)` sobre `resume_continue` y
`luau_execute` falla con error 5 en páginas `MEM_IMAGE`/`PAGE_EXECUTE_READ`.
Sin eso no hay hook de la VM, y sin hook no hay ejecución en el hilo de Lua.

## 5. Hipótesis descartadas por medición

| Hipótesis | Resultado |
|---|---|
| VEH propio congela al cliente | Con `X` (guard apagado) muere igual |
| `get_global_state` del cliente | Se sustituyó por la decodificación de `sc+0x200`; el cliente sobrevive |
| La segunda inyección degrada el cliente | Era `R6031` de la CRT por doble `DllMainCRTStartup`; ahora hay mutex por PID |
| `0x4254A10` es un loader de 5 argumentos | Fast-fail de cookie de pila (`0xC0000409` subcódigo 2) |
| La procedencia de la llamada importa | El call gate dentro de `fltlib` tampoco salva al cliente |

## 6. Errores propios corregidos

- `nCcalls`/`baseCcalls` escritos en `+0x10`/`+0x12` (zona `end_ci` en este
  build). Correcto: `+0x20`/`+0x22`.
- `push_on_parent` declarada `bool`: `pop_from_parent` nunca coincidía y cada
  hilo quedaba en la pila del juego.
- `thread_helper` sin validar, usado como `lua_newthread` sin comprobación.
- Un `find_string_key` con paso `0x28` (el real es `0x20`) que hacía que ninguna
  clave se encontrara; se detectó volcando los nodos y calibrando el paso.

## 7. Lo que queda abierto

1. Por qué el cargador rechaza a un llamante externo. No hay volcado; la
   terminación es deliberada. La comprobación debe estar en el propio cargador o
   en el runtime, sobre el hilo llamante.
2. Si existe alguna ruta que cargue un chunk sin pasar por `luau_load` (por
   ejemplo, reutilizar un `Proto` ya cargado por el cliente).
3. Si un entorno sin Hyperion (emulado) permite desarrollar el hook de la VM y
   validar el carril completo antes de volver a este build.

## 8. Cómo reproducir el estado actual

```powershell
# 1. Cliente limpio, una inyección
.\out\Vesper.exe --map out\Vesper.dll --pid <pid> --entry VesperAttach `
                 --gate --pagefile --apc --probe-event --wait 25

# 2. Orden dentro de la ventana de 90 s del hilo que sirve
.\out\Vesper.exe --exec script.lua --pid <pid>
```

Con `stage` = `2DX` el carril de carga sobre el estado real corre sin el
manejador de excepciones propio; con `2L` un comando ejecuta la sonda de lectura
en vez de un chunk.
