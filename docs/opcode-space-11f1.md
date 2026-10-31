# El espacio de opcodes de 11f1, deducido

Estado: **deducción con evidencia, pendiente de la corrida que la confirma.** Léase
entero antes de tocar el encoder, porque la conclusión es la contraria a la que
sugieren las bases públicas.

## El hecho verificado en Luau público

Comprobado por un tercero sobre `luau-lang/luau` HEAD `9d7748a` (16-oct-2026), leyendo
el código, no de memoria:

1. `luau_load` **copia las palabras de 32 bits tal cual**, sin mapear el byte de
   opcode (`VM/src/lvmload.cpp:487-488`).
2. El intérprete despacha con una tabla indexada por `LUAU_INSN_OP(insn)`, el byte
   bajo, usado directo.
3. **Y lo importante:** hay un bucle posterior que recorre `p->code` con
   `LUAU_INSN_OP` + `getOpLength` y **reescribe `GETTABLEKS`, `SETTABLEKS` y
   `NAMECALL` a sus variantes `UDATA`** (`lvmload.cpp:670-706`). Ese bucle, por
   construcción, **sólo es correcto si los opcodes ya están en el espacio estándar**.
4. Un `BytecodeEncoder` se aplica una sola vez por función, en `endFunction`
   (`Bytecode/src/BytecodeBuilder.cpp:265-266`), sobre el array completo de
   instrucciones, antes de escribir. Recibe palabras de 32 bits enteras y tiene que
   avanzar él mismo con `getOpLength` sobre el opcode **original**.

## Lo que medimos nosotros, y cómo encaja

Al cargar nuestro chunk, los bytes del `code[]` del `Proto` **cambiaron** respecto a lo
que entregamos: `6c 76 73` pasó a `b6 dc 7d`, con los operandos intactos (`2a 00` = 42
en las tres lecturas). Eso parecía una permutación de opcodes del cliente.

**La lectura que encaja con el hecho 3 es otra, y es más simple:** si nuestro
`RobloxEncoder` ya había transformado los bytes antes de entregarlos, entonces el
loader los leyó **como si fueran estándar** — y algunos coincidieron numéricamente con
`GETTABLEKS` / `SETTABLEKS` / `NAMECALL`, que es exactamente lo que ese bucle reescribe
a sus variantes `UDATA`. O sea: **el cambio que observamos no es una decodificación, es
la pasada de reescritura estándar**, y eso sólo puede ocurrir si el loader de 11f1 es,
en ese aspecto, **stock**.

Corolario: **el bytecode que hay que entregar está en el espacio estándar.** Nuestro
encoder está haciendo daño, no falta un encoder.

## Y la aritmética, que descarta las recetas públicas

Sobre el byte de opcode, con `f` el mapeo observado `f(0x6C)=0xB6`, `f(0x76)=0xDC`,
`f(0x73)=0x7D`:

- **Multiplicación constante `k*x mod 256`:** imposible. `108·k ≡ 182 (mod 256)`
  requiere solución y no la hay, porque `gcd(108,256)=4` y `4 ∤ 182`. Falla ya con el
  primer par.
- **Afín `a*x+b`:** incompatible. Los dos primeros pares dan `a ≡ 55 (mod 128)`; el
  tercero exige `a = 117`.
- **XOR con constante:** incompatible. Los XOR de los tres pares son `0xDA`, `0xAA` y
  `0x0E`.

Esto importa porque circulan dos recetas y **ninguna es el mapa del cliente**:
`RavageDevs/SkidBase` usa `tabla[op * 227]` y `xmsw747/XMSW-Easy-Roblox-Exploit-Base`
usa `op *= 227`. La segunda queda descartada por aritmética; la primera, si el espacio
es estándar, **no debe aplicarse en absoluto** en esta build. Que ellas lo hagan no es
una prueba de que haya que hacerlo: son builds anteriores, y el comportamiento del
loader cambia entre versiones.

## CORRECCIÓN: medido, y va al revés de lo que dice el resto de este documento

Corrida con el encoder **desactivado** (stock puro, `return 41 + 1`):

```
compilado:  41 00 00 00  04 00 2a 00  16 00 02 00
tras load:  7e 00 00 00  a0 00 2a 00  0e 00 02 00
```

**El loader de 11f1 sí mapea el byte de opcode al cargar.** Con entrada estándar
sale otra cosa, así que la entrada esperada **no** es el espacio estándar y todo el
razonamiento de arriba queda invalidado: lo que se observó en la corrida con encoder
(`6c 76 73` -> `b6 dc 7d`) tampoco era una reescritura, era el mismo mapeo con otra
entrada. Las dos corridas lo que demuestran es que el mapeo ocurre siempre.

Lo que sigue siendo cierto y sirve: la aritmética (no es multiplicación constante, ni
afín, ni XOR — la entrada de arriba tampoco lo es), y el hecho de que el VM despacha
con el byte **almacenado**, así que el espacio interno es el que aparece en el
`code[]` de un `Proto`.

### Lo que hay que hacer, y no es copiar la receta de nadie

El mapeo se puede **derivar empíricamente**, porque controlamos la entrada y leemos la
salida:

1. Leer el `code[]` de un `Proto` **del propio juego**: su última instrucción es
   `RETURN`, así que da el número interno de `RETURN` directo. Con eso sabemos en qué
   espacio vive el VM.
2. Alimentar el loader con instrucciones de opcode elegido (un chunk mínimo por
   byte) y leer el `code[]` resultante: cada par (entrada, salida) es una entrada de
   la tabla.
3. Invertirla sobre los opcodes que necesitemos y codificar el bytecode **con esa
   inversa**, no con `op *= 227` ni con `tabla[op*227]`. Esas dos recetas son de otras
   builds; aquí la tabla es de este cliente y se mide.

Con la inversa derivada, el chunk debería cargar en el espacio interno correcto y
`luau_execute` dejar de morir al entrar.

## El experimento que lo confirma, y es una sola corrida

Forzar el encoder **desactivado** (bytecode stock tal cual sale de `Luau::compile`) y
ejecutar `return 41 + 1`.

- Si vuelve **42** con el cliente vivo: confirmado, y el fallo era nuestro encoder.
- Si el VM sigue muriendo al entrar: entonces el loader sí transforma, o el problema
  está en el hilo (contexto de seguridad), y hay que volver a la comparación contra el
  `code[]` de un `Proto` **del propio juego** — que es la única fuente de verdad sobre
  en qué espacio vive este cliente.

Aviso para quien lo ejecute: si un agente anterior dejó el encoder forzado a
`op *= 227` (porque así lo pedía un brief anterior a esta deducción), ese cambio es
**contrario** a lo que dice este documento y hay que revertirlo antes de probar.

---

## RESUELTO 2026-10-18 — `return 41 + 1` = 42, cliente vivo

Verificado en vivo (pid 7728 y pid 8652, place 189707, build `11f155f3450f4c8e`):
`exec: chunk=cli ok=1 value="42"` con el proceso **vivo**, y
`resume_continue -> status=0 reached=1`.

### 1. El mapa del loader, medido en desensamblado

`luau_load` (0x269E780) decodifica el byte de opcode en un bucle en `0x269F907`:

```
0x269F907  lea r14, [rip - 0x269f90e]     ; r14 = base del módulo
0x269F920  mov edx, dword ptr [r8]        ; palabra de instrucción
0x269F923  movzx eax, dl                  ; byte de opcode de ENTRADA
0x269F926  movzx ecx, byte [rax + r14 + 0x71433E0]   ; table[in]
0x269F92F  and edx, 0xffffff00
0x269F935  or  ecx, edx
0x269F939  mov dword ptr [r8], eax        ; stored = table[in]
```

Así que **`stored = table[in]`**, indexado directo, con `table` =
`rva.opcode_lookup_table` (`0x71433E0`). No es `table[in*227]`, ni un producto,
ni un XOR. Las tres comprobaciones propuestas **fallan**:

| op | `table[(op*227)&0xFF]` | esperado | ¿coincide? |
|----|------------------------|----------|------------|
| 0x41 | `table[0xA3]` = **0xDF** | 0x7E | no |
| 0x04 | `table[0x8C]` = **0x4B** | 0xA0 | no |
| 0x16 | `table[0x82]` = **0x82** | 0x0E | no |

Pero el índice directo sí reproduce todo (seis de seis pares medidos, corridas A
y B): `table[0x41]=0x7E`, `table[0x04]=0xA0`, `table[0x16]=0x0E` (A) y
`table[0x6C]=0xB6`, `table[0x76]=0xDC`, `table[0x73]=0x7D` (B). La tabla es una
biyección de 0..255 y es la misma en todas las sesiones probadas.

### 2. La inversa sola NO alcanza: el enum interno del cliente ≠ el enum vendido

La dispatch del VM (`execute_false` 0x266D720, fetch en 0x266D863) indexa una
tabla de bytes en `0x267B0AC` (destinos en `0x267AF38`). Acepta **92** valores de
opcode; cualquier otro (caso `0x5C`) salta a `0x267A989` = `mov ecx,0x25; int
0x29`, una trampa deliberada. Dos consecuencias:

* El bytecode stock (`table[std]`) y la inversa simple (`std`) dan opcodes
  **inválidos**: el VM trapó en la primera instrucción. Eso — y no la propiedad
  del hilo — es lo que mataba al cliente al entrar al intérprete.
* El enum de la Luau vendida (YuB-X, 90 opcodes 0x00..0x59) no es el enum interno.

Los opcodes internos se identificaron desensamblando los handlers: LOADN=`0x4B`
(`0x266DF83`, `R[A]=double(D)`), LOADB=`0x49`, LOADNIL=`0x0D`, MOVE=`0xC8`
(`0x266DFCA`, `R[A]=R[B]`), CLOSEUPVALS=`0x6B`, RETURN=`0x82` (`0x2670A70`, pop de
CallInfo), NOP(skip)=`0x9C` (`0x2671152`).

### 3. El encoder que funciona

Por cada opcode vendido `V`: buscar el opcode interno `I` que lo implementa, y
emitir `input = table⁻¹[I]`. Para `return 41 + 1` (PREPVARARGS, LOADN 42, RETURN)
la entrada es `00 8C 82` y el loader guarda `9C 4B 82` (NOP, LOADN, RETURN).
`resume_continue` devuelve status 0 y el valor 42. El valor de retorno escrito por
`RETURN` está en el slot `ci->func` de la callee, no en `L->top - 0x10`.


## Lo que sigue sin saberse

1. Si el loader de 11f1 transforma en alguna otra ruta (no descartado, sólo no
   observado).
2. Los offsets de `Identity` y `Capabilities` dentro del contexto por hilo, y si el
   contexto por hilo es el campo `L+0x80`. La base pública escribe `identity = 8` y
   `capabilities = ~0` ahí, pero los offsets hay que medirlos en el hilo vivo.
3. El punto de entrada cuando el VM aplaza la ejecución (`SCHEDULED_REENTRY`): la
   apuesta es `task.defer(closure)` con la pila `[closure, task.defer]` y
   `lua_pcall(hilo, 1, 0, 0)`, para que el trabajo lo corra el host y no nosotros.

---

## MAPA 2026-10-18 — 64 de 92 opcodes internos cableados (13 confirmados en vivo), scripts reales corriendo

Método, sin correr el cliente para deducir: los 92 handlers se desensamblan del
volcado vivo (`dumps/11f1-live.bin`, base == offset de fichero para `.text`) con la
tabla de dispatch (`0x267B0AC` byte, `0x267AF38` jump table) y se comparan, por
forma, con el enum vendido (`ref/YuB-X/.../Bytecode.h`) y con el intérprete público.
El enum interno **no** es el vendido ni una permutación monótona de él: cada handler
se reconoce por lo que hace (qué campo toca, qué ayuda llama, qué doble operación
hace) y por los literales de tag. Registro por opcode en
`struct.internal_opcode.*` del JSON de la build.

Tabla `internal = vendored` (61 entradas; las marcadas (?) llevan la evidencia
fina anotada y no se han ejercitado aún en vivo):

| int | vend | evidencia | int | vend | evidencia |
|----|------|-----------|----|------|-----------|
| 0x9C | NOP | `add r12,4; jmp fetch` (2 ins, 0x2671152) | 0xF2 | LOADK | 1 palabra, `D`→`K[D]`, salta a la cola de LOADKX 0x2679762 |
| 0x0D | LOADNIL | `mov [r15+rax*8+0xc],0` (tag 0) | 0x61 | LOADKX | 2 palabras, `AUX`→`K[AUX]` |
| 0x49 | LOADB | tag 1 = booleano, `lea r12,[r12+r8*4]` (salta C) | 0xB4 | GETIMPORT | copia `K[D]` si no-es-nil, `add r12,8` |
| 0x4B | LOADN | `cvtdq2pd`; tag 3 = número | 0xC2 | GETGLOBAL | lee slot de caché `[proto+0x28]+(hash&C)*0x20` |
| 0xC8 | MOVE | `movups` de 16 bytes R[B]→R[A] | 0x00 | SETGLOBAL | escribe ese mismo slot (sin registro B) |
| 0x82 | RETURN | pop de CallInfo / destino `ci->func` | 0xC3 | GETUPVAL | `cl+0x20+B*16` con deref si tag 0x10 |
| 0x6B | CLOSEUPVALS | recorre la lista de upvalues abiertos (L+0x18) | 0x32 | SETUPVAL | `[cl+0x20+B*16]=R[A]` + barrera GC |
| 0xC5 | GETTABLE | tag 7 = tabla; índice `R[C]` con atajo entero | 0xD7 | SETTABLE | ídem, escribe |
| 0xB8 | GETTABLEN | índice inmediato `C` al array `[tab+0x18]` | 0x18 | SETTABLEN | ídem, escribe R[A] |
| 0xDD | GETTABLEKS | clave `K[AUX]`, caché de slot, escribe C de vuelta | 0xEC | SETTABLEKS | ídem, escribe |
| 0xD0 | NAMECALL(?) | 2 palabras: `R[A]=cache`, `R[A+1]=R[B]` | 0xBF | CALL | tag 8 = función → `luaD_call` |
| 0x7B | JUMP | `movsx D; lea r12,[r12+rax*4]; add r12,4` | 0x3A | JUMPBACK | safepoint GC + salto D |
| 0x0F | JUMPX | `sar rax,8` (E de 24 bits) + safepoint | 0x2C | JUMPIF | salta si es *verdadero* (nil/false → no) |
| 0x10 | JUMPIFNOT | salta si es *falso* | 0x0B | JUMPIFLT | num: `comisd` y salta si `R[A]<R[AUX]` |
| 0x58 | JUMPIFNOTLT | num: salta si no `R[A]<R[AUX]` | 0x2F | JUMPIFEQ(?) | despacho por tag común |
| 0x99 | ADD | `addsd` | 0x8A | SUB | `subsd` |
| 0x38 | MUL | `mulsd` | 0xAD | DIV | `divsd` |
| 0x02 | DIVK | `divsd` con `K[C]` | 0x54 | SUBK | cola común de resta |
| 0x6D | SUBRK | `K[B]-R[C]` | 0x7F | MULK | `K[C]*R[B]` |
| 0xF5 | ADDK(?) | `addsd` con `K` | 0xCB | MOD(?) | llama ayuda `0x26329D0` |
| 0x92 | MODK(?) | ídem con `K[C]` | 0xDA | POW(?) | llama `0x5D19D20` (libm pow) |
| 0xA0 | POWK(?) | atajo `x*x` para exponente 2 | 0xEA | IDIV(?) | ayuda `0x2632980` |
| 0x24 | IDIVK(?) | ídem con `K[C]` | 0xCE | DIVRK(?) | `divsd` con `K[B]` |
| 0x5B | AND | falsy→B, si no C | 0x66 | OR | truthy→B, si no C |
| 0x77 | ANDK | falsy→B, si no `K[C]` | 0x1E | ORK | truthy→B, si no `K[C]` |
| 0x7D | CONCAT | recorre `R[B..C]`; tag string/num; `TM_CONCAT`=0x12 | 0x6C | NOT | escribe booleano invertido |
| 0x4D | MINUS | `xorps xmm9` (máscara de signo) | 0x13 | NEWTABLE | `luaH_new` (tag 7, dummynode) + array AUX |
| 0xE0 | DUPTABLE | `sub_2652FF0` con `K[D]` | 0x05 | FORNPREP | comprueba 3 registros número y salta |
| 0x3B | FORNLOOP | `index+=step`, compara, salta | 0x8E | DUPCLOSURE | `K[D]` con `cmp [K+0x10], cl->env` |
| 0x8F | ? | copia `K[AUX]` y fija flag `+0x58` | 0x67 | FASTCALL(?) | lee la CALL `C` palabras delante |
| 0xCF | COVERAGE(?) | índice de instrucción en `[proto+0x30]^` | 0x04 | JUMPXEQKB | compara con bit bajo de AUX |
| 0xD9 | JUMPXEQKN | compara con `K[AUX]` (número) | 0x90 | JUMPXEQKS | compara con `K[AUX]` (string, tag 6) |
| 0x8C | JUMPXEQKNIL(?) | 1 palabra, `dec eax; xor` con AUX | 0x11 | PREPVARARGS | cuenta varargs de `ci`/proto |
| 0xE2 | CMPPROTO(?) | salta si `R[A]` no es función (tag 8) | 0x83 | FORGPREP(?) | valida `[gen,state,index]` |
| 0x8F | ? | — | | | |

Nota de precisión: `PREPVARARGS` interno es `0x11`, pero el encoder lo pliega al
`NOP` interno (`0x9C`) porque los chunks de prueba no son variádicos; así estaba
probado antes y sigue probado (`return 41 + 1` = 42). Cuando un chunk use `...` habrá
que emitir `0x11`.

### Verificado en vivo (una sesión por chunk, cliente vivo en todos)

| chunk | valor | opcodes internos ejercitados |
|-------|-------|------------------------------|
| `return 41 + 1` | **42** | NOP, LOADN, RETURN |
| locales `1 + 2*3` | **7** | LOADN, RETURN |
| `for i=1,10` | **55** | FORNPREP, ADD, FORNLOOP |
| `"hello world"` | **hello world** | LOADK, RETURN |
| `if 5 < 10` | **105** | JUMPIFNOTLT, ADDK |
| tabla hash `{p=3} t.q=4` | **8** | DUPTABLE, SETTABLEKS, GETTABLEKS, ADD |
| `while` + todo lo anterior | **26** (rich.lua: 4 locales, concat, tabla hash, `if`, `for`) | ver abajo |

`rich.lua` → **26** con el cliente vivo. Es el chunk más rico que corre hoy:
`local a=1; local b=2; local s="ab".."cd"; local t={p=3}; t.q=4; if a<b then a=a+10 end; for i=1,3 do sum=sum+i end; return a+b+t.p+t.q+sum`.
El total de opcodes con evidencia de desensamblado y cableados en el encoder es 64;
los 13 que aparecen en las trazas vivas (`NOP, LOADN, LOADK, MOVE, RETURN,
GETTABLEKS, SETTABLEKS, DUPTABLE, JUMPIFNOTLT, ADD, ADDK, FORNPREP, FORNLOOP`) son
los confirmados por ejecución. `NEWCLOSURE` y `NAMECALL` quedan **sin mapear a
propósito** (handler interno no fijado): sin mapear el VM trapea y nombra el hueco;
con un valor incorrecto el chunk correría mal en silencio.

### El gap que queda (medido, en el log)

1. **`CAPTURE` (vendored `0x46`) no está mapeado.** Su byte crudo `table[0x46]`
   decodifica a un opcode interno **válido pero distinto**, así que un chunk con
   upvalues *carga y corre pero devuelve un valor equivocado* en silencio
   (`nest2.lua` = `local x=5; local function f() return x end; return 1`
   devolvió **5**, no 1). Es el fallo más peligroso porque no trapea.
2. **Un chunk con `DUPCLOSURE` y sin `CAPTURE` falla en `luau_load` con
   `status=-1`** (`nest1.lua`, y `func.lua`/`big.lua`/`mix.lua`). `nest2.lua`, que
   sí lleva `CAPTURE`, carga con status 0, así que el fallo no es "proto hijo" sino
   algo del camino reutilizable: la hipótesis viva es que el loader rechaza la
   constante CLOSURE de `K` cuando el proto no tiene upvalues; hay que probarlo.
3. **Un chunk mixto de 7 instrucciones falla con `status=1`** (`comp.lua`: LOADK +
   DUPTABLE + SETTABLEKS + JUMPIFNOTLT + FORN + JUMPBACK + GETTABLEKS; todos sus
   opcodes están mapeados). Falta aislar qué instrucción lo rompe.
4. **`SETLIST` (vendored `0x37`) y `LENGTH` (vendored `0x34`) no están mapeados**:
   una tabla con parte array `{1,2,3}` no cargará correctamente todavía.

El siguiente paso más rentable, dado lo anterior, es aislar (3) con un banco de
chunks de una sola instrucción y terminar de mapear `CAPTURE`/`SETLIST`/`LENGTH`
desde el volcado (los handlers candidatos están ya en `%TEMP%\hb.txt`).

---

## RESUELTO 2026-10-18 — el mapa completo, por la tabla de clases del loader

El mapa ya no hay que deducirlo handler a handler. El bucle del loader
(`0x269F907-0x269F974`) usa **dos** tablas, no una:

```asm
0x269F920  mov  edx, [r8]                 ; palabra
0x269F923  movzx eax, dl                  ; byte de ENTRADA
0x269F926  movzx ecx, byte [rax+r14+0x71433E0]  ; stored = decode_table[input]
0x269F939  mov  dword [r8], ecx           ; guarda `stored`
0x269F93C  movzx ecx, cl                  ; stored otra vez
0x269F93F  movzx eax, byte [rcx+r14+0x7144260]  ; class = class_table[stored]
0x269F948  add  eax, -7                   ; longitud = switch(class-7) -> 4 u 8
```

* `decode_table` (0x71433E0) mapea `entrada -> internal` (universo: 256).
* `class_table` (0x7144260) mapea `internal -> vendored`. **Es el enum vendido
  otra vez, y su inversa es el mapa completo vendored->internal.**
* La longitud de cada instrucción se decide por `class_table[stored]` con
  `getOpLength` del enum vendido, así que un opcode interno equivocado también
  **desincroniza el bucle de decodificación**: por eso el byte crudo de CAPTURE
  (`table[0x46]`) hacía que el chunk siguiente se decodificara mal y `nest2`
  devolviera 5.

Comprobado offline sobre `dumps/11f1-live.bin` (y contra las corridas vivas ya
conocidas): `class_table[0x9C]=0x00 NOP`, `[0x4B]=0x04 LOADN`, `[0x82]=0x16
RETURN`, `[0xDD]=0x0F GETTABLEKS`, `[0x13]=0x35 NEWTABLE`, `[0x8E]=0x40
DUPCLOSURE`. La tabla es una biyección de 256 bytes, así que la inversa da
exactamente un opcode interno por cada opcode vendido (0x00..0x58, 89 entradas).

Opcodes nuevos, cableados en `build_semantic_map()` (modo 4):

| op | vend | int | | op | vend | int |
|----|------|-----|---|----|------|-----|
| LENGTH | 0x34 | **0x2E** | | CAPTURE | 0x46 | **0xC9** |
| SETLIST | 0x37 | **0xE5** | | NEWCLOSURE | 0x13 | **0xD1** |
| NAMECALL | 0x14 | **0xD0** | | FORGLOOP | 0x3A | 0x56 |
| GETVARARGS | 0x3F | 0x11 | | PREPVARARGS | 0x41 | 0xDF |

Y se **corrigen** las entradas tentativas que estaban mal: `MOD 0xCB->0xEA`,
`MODK 0x92->0x24`, `IDIV 0xEA->0xCB`, `IDIVK 0x24->0x92`, `COVERAGE 0xCF->0x6E`,
`FASTCALL 0x67->0x14`. El encoder además reconstruye el mapa desde la tabla viva
en el attach (`rva.luau.loader_opcode_class_table`, RVA corregido a `0x7144260`)
y sólo cae al mapa estático medido si esa página no está residente.

Nota sobre `CAPTURE`: el handler de `DUPCLOSURE`/`NEWCLOSURE` consume las
instrucciones `CAPTURE` **inline** (bucle en `0x2678FE4` sobre `proto->nups`), no
por despacho; lo único que importa de la instrucción es que su longitud sea 1
palabra, que `class_table[0xC9]=0x46` garantiza.

---

## RESUELTO 2026-10-18 — el gap real era el formato de wire, no los opcodes

Con el mapa completo seguía fallando lo mismo: `nest2` devolvía 5 en vez de 1 y
`nest1` (`DUPCLOSURE` sin `CAPTURE`) moría en `luau_load` y **mataba al cliente**.
La causa no era ningún opcode: es el **formato de serialización**.

`lvmload.cpp` lee, por cada proto y **cuando `version >= 11`**, un vector de
feedback:

```
lvmload.cpp:734   if (version >= 11) { p->feedbackvecsize = readVarInt(...); ... }
```

y `BytecodeBuilder::getVersion()` devuelve 11 porque `LBC_VERSION_TARGET == 11`.
Pero `writeFunction()` escribía esa sección **sólo si `FFlag::LuauEmitCallFeedback`**
(apagado por defecto), así que el bytecode salía con versión 11 **sin** la
sección. El loader leía entonces el `mainid` de un chunk como si fuera
`feedbackvecsize` y desplazaba todo el parseo del último proto:

* chunks de **1 proto**: el desfase sólo corrompe el trailer; `protos[0]` sigue
  siendo el único candidato y "funciona" de casualidad (`return 41+1`, `rich`,
  `print`, `#t`, `{1,2,3}`).
* chunks de **2+ protos**: el loader elige el proto equivocado (ejecuta la
  función interna) o revienta. De ahí `nest2`=5, `f7`=7 y el crash de `nest1`.

Arreglo (parche en el Luau vendorizado, `BytecodeBuilder.cpp`): emitir siempre la
sección de feedback (vacía si no hay slots), sin tocar el codegen. El wire queda
alineado con el loader del cliente.

Verificado en vivo tras el parche (una sesión por par, cliente vivo):

| chunk | antes | ahora |
|-------|-------|-------|
| `return 41 + 1` | 42 | **42** |
| `local function f() return 7 end; return 1` | 7 | **1** |
| `local x=5; local function f() return x end; return 1` (nest2) | 5 | **1** |
| `local function f() return 1 end; return 1` (nest1) | crash del cliente | **1** |
| `local x=1; local y=2; local function f() return x+y end; return f()` | — | **3** |
| `local a={1,2,3}; return a[1]` (SETLIST) | — | **1** |
| `local t={1,2,3}; return #t` (LENGTH) | — | **3** |
| chunk mixto de 7 ops (antes `status=1`) | status 1 | **34** |
| `rich.lua` | 26 | **26** |
| `local t=type(print); print("hello world"); return t` | — | **"function"** |

Estado del espacio de opcodes: **89/89 opcodes vendidos (0x00..0x58) cableados**;
ninguno queda sin mapear. `PREPVARARGS` se sigue plegando a NOP a propósito (los
chunks entran sin varargs; el interno real es 0xDF).

---

## Addendum 2026-10-18 (noche)

El "bytecode corrupted" que aparece al ejecutar chunks ricos **no es del mapa de
opcodes**. Los chunks que lo disparan parsean limpiamente contra las tablas del
propio cliente (`decode_table` en 0x71433E0 y `class_table` en 0x7144260,
comprobado offline con `%TEMP%\parse_bc.py`): cada proto consume exactamente su
`sizecode` y ningún opcode sale del enum. El rechazo es del `luau_load` del
cliente y depende del contenido: `optimizationLevel=1` con `FASTCALL` dentro de
un proto con upvalues, la sección de debug (line info / nombre de función),
chunks con `>= 7` protos, y tablas con muchas claves de cadena. El motor ahora
recompila por una escalera `(opt1,dbg2)→(opt0,dbg2)→(opt1,dbg0)→(opt0,dbg0)`
antes de declarar un chunk incargable. Detalle en `docs/hostapi-11f1.md`.



