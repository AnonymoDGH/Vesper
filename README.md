# Vesper

Investigación y motor experimental de inyección y ejecución de Luau dentro del
cliente de Roblox para Windows, sobre el build `version-9ac8595712b447a7`.

No es un ejecutor funcional. Es el registro de un intento serio, con cada paso
medido, y de un muro que quedó documentado con evidencia en lugar de con
opiniones. Todo lo que aquí se afirma está respaldado por una línea de log, un
volcado o una medición del proceso.

---

## Qué hay aquí

```
engine/        DLL que se mapea dentro del cliente (C++17, MinGW)
shell/         cargador y cliente de línea de órdenes (mapea, entrega, lee respuestas)
offsets/       perfiles de offsets por build, con layout y mapa de opcodes
docs/          la investigación escrita
tools/         utilidades de análisis (volcados, desensamblado, minidumps)
tests/         scripts de regresión
```

## Cómo funciona el motor

El cliente rechaza módulos que no pasaron por su loader, y su runtime mata los
hilos cuyo código viene de una página privada. Así que nada de `LoadLibrary` ni
de cuevas de código:

1. **Mapeo manual** de una sección `SEC_IMAGE` desde el fichero, con
   relocalizaciones e imports resueltos a mano. Memoria respaldada por imagen,
   ausente de toda lista de módulos.
2. **Gate**: se mapea además `fltlib.dll` desde disco y se escribe una rutina de
   tres instrucciones en una página libre dentro de la imagen. Un APC solo puede
   apuntar a una dirección que esté dentro de una imagen, y esa rutina lo es.
3. **Entrega por APC** a hilos que el propio cliente creó. No se crea ningún
   hilo: crear uno desde fuera es exactamente lo que el runtime castiga.
4. **Resolución del estado**: `ScriptContext` a través de los trabajos del
   scheduler; `lua_State` decodificado de `sc+0x200` (XOR por dword con la
   dirección del campo), sin llamar al cliente.

## Lo que está medido y funciona

| Pieza | Evidencia |
|---|---|
| Mapeo manual + gate + entrada por APC | `entry ran on one of the target's threads` |
| `ScriptContext` por trabajos del scheduler | `attach: script context=0x… (strategy 3/via-jobs)` |
| `lua_State` sin llamar al cliente | `decoded sc+0x200 -> 0x… plausible=1 validate_state=1` |
| Tramo correcto del trabajo de la partida | `registry_sizearray=2048` + `owned = real_dm − 0x1f0` |
| Lectura de tablas con el layout real | nodos de `0x20`, clave en `+0x10`, tags `6/7/8` |
| Canal de órdenes sobre el hilo del attach | `serve:` → `command #1: claimed` → `exec_source` |
| Compilación en proceso y traza por pasos | `exec: compiled … / step: …` |

## El muro, con las cuatro mediciones

Cargar un chunk es imposible desde un hilo que no sea el de Lua. Se probaron
cuatro procedencias distintas y las cuatro acaban igual: **sesión terminada, sin
volcado minidump** (terminación deliberada, no crash).

| Procedencia de la llamada a `luau_load` | Resultado |
|---|---|
| Hilo sintético (`pvt::make`) | El cliente muere en la carga |
| Estado real del juego | El cliente termina la sesión |
| Nuestra imagen (llamada directa) | El cliente termina la sesión |
| Rutina `call` dentro de `fltlib` (call gate) | El cliente termina la sesión |

Y las otras dos puertas también están cerradas:

| Camino | Resultado |
|---|---|
| Crear un hilo remoto (`NtContinue`, entrada propia o del gate) | `0xC000071C` |
| Parchear `.text` para enganchar la VM | `VirtualProtect` → error 5 |

Sin poder cargar un chunk no hay closure, y sin closure no se puede entregar a
`task.defer`. Es circular.

## Errores propios encontrados y corregidos

Estos sí eran bugs, y están documentados porque explican resultados anteriores:

- **`nCcalls` en `+0x10`**: en `9ac8` esa zona es `end_ci`. Se corrompía el marco
  y `validate_state` fallaba. Correcto: `+0x20` / `+0x22`.
- **`push_on_parent` devolvía `bool`**: cada dirección se convertía en `1` y
  `pop_from_parent` nunca retiraba la ranura; cada hilo quedaba en la pila del
  juego.
- **`0x4254A10` como loader de cinco argumentos**: no lo es. El volcado muestra
  `0xC0000409` subcódigo 2, el `__security_check_cookie` del cliente fallando
  por un marco de pila mal formado.
- **Segunda inyección en el mismo cliente**: `DllMainCRTStartup` se ejecutaba dos
  veces y la CRT respondía `R6031` con un diálogo modal que congela el hilo.
  Ahora el motor reclama un mutex por PID y el shell rechaza la segunda.

## Compilar

Requiere MinGW-w64 en el `PATH` (probado con `C:\MinGW\bin`) y PowerShell.

```powershell
.\build.ps1 -Target all
```

Produce `out\Vesper.dll` y `out\Vesper.exe`.

## Uso

```powershell
# Una sola inyección por cliente
.\out\Vesper.exe --map out\Vesper.dll --pid <pid> --entry VesperAttach `
                 --gate --pagefile --apc --probe-event --wait 25

# El hilo del attach se queda sirviendo órdenes 90 s: enviar dentro de esa ventana
.\out\Vesper.exe --exec script.lua --pid <pid>
```

`%LOCALAPPDATA%\Vesper\stage` contiene un dígito (1–4) y letras opcionales:
`D` carril de carga sobre el estado real, `L` sonda de solo lectura, `M` permite
ejecutar sin partida, `X` desactiva el manejador de excepciones propio.
El fichero se lee una vez por proceso.

## Documentación

- [`docs/9ac8-findings.md`](docs/9ac8-findings.md) — todo lo medido, con las
  líneas de log que lo respaldan.
- [`docs/night-shift.md`](docs/night-shift.md) — criterios de aceptación y
  mediciones anteriores.

## Fuentes y agradecimientos

Este trabajo se apoya en material público. No se redistribuye ninguno de esos
ficheros; se enlazan desde aquí:

- **Offsets y estructuras de `9ac8`** — [`Offsetmanager/Roblox-Internal-External-Offsets`](https://github.com/Offsetmanager/Roblox-Internal-External-Offsets) y el volcado de estructuras del build, que es la autoridad sobre `lua_State`, `LuaTable`, `global_State` y las codificaciones `vmval1..4`.
- **Offsets del cliente** — [`imtheo`](https://offsets.imtheo.lol/) y los dumps de `lrd14`, `soulovery'all` y `codex`, usados solo como contraste.
- **Carril de ejecución de referencia** — [`dimondfendom123/ForlornWare`](https://github.com/dimondfendom123/ForlornWare), que documenta la forma correcta: `lua_newthread`, `luaL_sandboxthread`, cargar y entregar a `task.defer`.
- **Luau** — [luau-lang/luau](https://github.com/luau-lang/luau).

## Alcance

Herramienta de investigación sobre un build concreto del cliente, para uso sobre
cuentas y procesos propios. No incluye ni distribuye binarios de Roblox: los
volcados usados para el análisis (`dumps/`) están excluidos del repositorio.
