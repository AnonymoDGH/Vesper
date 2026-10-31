# Host API — live Roblox client `version-11f155f3450f4c8e` (11f1)

Evidence-based spec for driving the client's Lua VM from an injected bridge.
Every claim below cites a **RVA** (offset from the main module base
`RobloxPlayerBeta.exe`) plus the disassembly or live read that produced it.
RVAs are base-independent; re-derive the base per attach (`module base` printed
by the tooling, e.g. `0x7FF71AA50000` on pid 10708, `0x7FF67A710000` on pid 1916).

> Method: live `ReadProcessMemory` only (the on-disk exe is encrypted). Hyperion
> decrypts **executed** pages lazily, so warm paths are readable and cold/error
> paths (`0x26A2000..0x26AA68D`, `0x26A3780`) read back as nothing. `.pdata` is
> zeroed in memory (`DataDirectory[3] = (0,0)`), so there are no function extents
> to lean on — extents below are from linear disassembly and the shared epilogue.

Authoritative RVA source: `offsets/src/version-11f155f3450f4c8e.json`.

---

## Q1 — chunk loader `luau_load` (RVA `0x269E780`) and sibling `luaVM_load` (`0x41A3610`)

### 1.1 Signature — `int luau_load(lua_State* L, LoadContext* ctx)`

Prologue at `0x269E780` (pid 5656 disassembly):

```
0x269E780  mov [rsp+0x10], rdx        ; arg2 saved
0x269E785  mov [rsp+0x08], rcx        ; arg1 saved
0x269E78A  push rbp/rbx/rsi/rdi/r12/r13/r14/r15
0x269E796  lea rbp, [rsp-0xac8]
0x269E79E  sub rsp, 0xbc8             ; frame = 0xbc8
0x269E7A5  mov r13, rdx               ; r13 = ctx
0x269E7A8  mov r12, rcx               ; r12 = L
0x269E7AB  mov ebx, dword [rdx+0x48]  ; ctx->env   (int)
0x269E7AE  mov r14, qword [rdx+0x40]  ; ctx->size  (size_t)
0x269E7B6  mov rsi, qword [rdx+0x38]  ; ctx->data  (const char*)
0x269E7BE  mov rdi, qword [rdx+0x30]  ; ctx->name  (const char*)
0x269E7C2  lea rax, [rdx+0x18]        ; address of sub-object @ ctx+0x18
0x269E7D3  mov r15d, 1                ; r15d = status, initialised to 1 (error)
```

So `rcx = lua_State*`, `rdx = LoadContext*`. This confirms the struct form and
**falsifies the 5-arg form at this address** (arg2 is dereferenced, not read as a
`const char*`).

### 1.2 `LoadContext` layout

| off | type | meaning | evidence |
|-----|------|---------|----------|
| `+0x18` | ptr | address taken (`lea rax,[rdx+0x18]`); sub-object / reader. **Never written by the loader.** | `0x269E7C2`, `0x269E7C6 mov [rbp],rax` |
| `+0x30` | `const char*` | chunk name (NUL-terminated; `strlen` loop at `0x269E7F0`) | `0x269E7BE` |
| `+0x38` | `const char*` | bytecode/data pointer; `[data+0]` is the version byte | `0x269E7B6`, `0x269E7CA movzx ecx,[rsi]` |
| `+0x40` | `size_t` | data length | `0x269E7AE` |
| `+0x48` | `int` | environment (`0` ⇒ use slot `[L+0x80]`, else `index2addr(L, env)`) | `0x269E7AB`, branch at `0x269E9CF` |
| `+0x4C` | `int` | **status output** written by the epilogue | `0x26AA68D` |

Struct size ≥ `0x50`. The engine currently also writes `+0x28 = size`
(`rbx.cpp:1441`) — harmless, but not a field the loader reads.

Flow: `data[0]==0` → error (`0x269E7E0 jne 0x269E850`; zero ⇒ path at `0x269E7E2`
builds the name string, calls `pushfstringL` at `0x269E84B`).

### 1.3 Return convention

Canonical epilogue (long-jumped to from every exit, e.g. `0x269E9CA`,
`0x269EA67`):

```
0x26AA68D  mov dword [r13+0x4C], r15d    ; ctx->status = r15d
0x26AA691  add rsp, 0xbc8
0x26AA698  pop r15,r14,r13,r12,rdi,rsi,rbx,rbp
0x26AA6A4  ret
```

* `r15d` starts at `1` (`0x269E7D3`) and is cleared on a success path
  (`0x269EDC1  xor r15d, r15d`). So **0 = success, non-zero = error**.
* **The epilogue does not write `eax`.** The authoritative result is
  `ctx+0x4C`. The engine's `LoadFn = int(*)(lua_State*, void*)` reads `eax`
  (`rbx.cpp:1445`); that value is stale/undefined here — read `ctx+0x4C`
  instead. (Unresolved: confirm by reading both across a live successful load.)

`r15` is also used as scratch in the body (e.g. `0x269EB2F`, `0x269F587`), so
only the value live at the epilogue is the status.

### 1.4 Does it push a closure?

Partly proven, partly open.

* The loader **builds TValues inline** — the constant deserialiser writes the
  type tag directly. `scanv` over `0x269E780..0x26A2000` found exactly:
  `0x269FAFA` bool tag `1`, `0x269FB2B` number tag `3`, `0x269FB95` & `0x269FC08`
  vector tag `5`, `0x269FC4E` string tag `6` (all `mov dword [reg+0xc], imm`).
  No tag-`8` (function) inline write exists in the readable region, so a pushed
  closure would be installed through a helper (`setclvalue`/memcpy) or by the
  inner call.
* `0x269E972` calls **`0x4254A10` with the classic 5-arg shape**
  `(L, name, data, size, env)`:
  `mov [rsp+0x20], ebx` (5th=env), `mov r9, r14` (size), `mov r8, rsi` (data),
  `mov rdx, rdi` (name), `mov rcx, r12` (L). Its result is compared to `1`
  (`0x269E977  cmp eax, r15d`). `0x4254A10` is the real 5-arg
  deserialize/`luau_load` — i.e. the "5-arg form" exists, just not at the
  profile's `rva.luau.load`.
* Direct observation of a `tag==8` slot after the call was **not obtained**
  (the only live path, `hostapi_probe` step D, wedged before flushing a stack
  window — see Q3). Treat "pushes a closure" as **expected but unconfirmed**.

**Next experiment:** in the `execute` hook (Q3), call `luau_load(L, ctx)` with a
known chunk and dump `[L+0x58]` (top) tag at `top-0x10`; expect `tag==8`.

### 1.5 Sibling `luaVM_load` (profile `rva.luau.load_module`, RVA `0x41A3610`)

```
0x41A3610  push rbx/rsi/rdi/r12..r15; sub rsp,0x140; __security_cookie
0x41A3635  mov r12d, r9d        ; arg4 (int)
0x41A3638  mov r14, r8          ; arg3
0x41A363B  mov rbx, rcx         ; arg1 = lua_State*
            cmp qword [rdx+0x10], 0      ; arg2 dereferenced (object)
            ... builds a std::string (the data buffer) ...
0x41A374B  movdqa [rsp+0x70], xmm0          ; zero ctx+0x00..+0x0F
0x41A3753  mov [rsp+0x80], rsi              ; ctx+0x10 = rsi
0x41A375B  mov [rsp+0x88], rsi              ; ctx+0x18 = rsi  (sub-object)
0x41A3763  mov [rsp+0x90], rsi              ; ctx+0x20 = rsi
0x41A376B  mov [rsp+0x98], rsi              ; ctx+0x28 = rsi
0x41A3773  mov [rsp+0xa0], r14              ; ctx+0x30 = arg3 (name)
0x41A377B  mov [rsp+0xa8], r15              ; ctx+0x38 = std::string data
0x41A3788  mov [rsp+0xb0], rax              ; ctx+0x40 = size
0x41A3790  mov [rsp+0xb8], r12d             ; ctx+0x48 = arg4 (env)
0x41A379A  mov [rsp+0xbc], eax              ; ctx+0x4C = 0
0x41A37A1  lea r8, [rsp+0x70]               ; arg3 = &ctx
0x41A37A6  lea rdx, [rip-0x1b0502d]         ; arg2 = callback, RVA 0x26A3780
0x41A37B0  call 0x262DD90                   ; luaD_rawrunprotected(L, cb, &ctx)
```

So `luaVM_load` is `luaD_rawrunprotected(L, <cb @ 0x26A3780>, &ctx)`
(`0x262DD90` = `rva.luau.raw_run_protected`). The `LoadContext` it builds matches
§1.2 exactly (`+0x18` sub-object = `rsi`, `+0x30` name, `+0x38` data, `+0x40`
size, `+0x48` env, `+0x4C` status).

**Unresolved:** whether `0x26A3780` forwards to `0x269E780`. `0x26A3780` is a
cold page (RPM returns nothing) — it is passed to `rawrunprotected`, i.e. it is
the protected twin of the loader. **Next experiment:** cause a module load
(`rva.enable_load_module = 0x8891880`) so the page decrypts, then disassemble it.

---

## Q2 — live `TValue` layout

### 2.1 Slot layout (PROVEN)

A stack slot is **0x10 bytes**:

| off | field |
|-----|-------|
| `+0x00` | value word (8 bytes): pointer, `double`, or immediate |
| `+0x08` | `extra` dword |
| `+0x0C` | **type tag** (dword; low byte is the tag, upper bytes zero) |

Evidence:

* `lua_pushlightuserdata` `0x261ADD0`:
  `mov [rax], rdi; mov dword [rax+8], 0; mov dword [rax+0xc], 2;
   add qword [L+0x58], 0x10` (top += 0x10).
* `lua_pushthread` `0x261AE40`:
  `mov [rax], rbx (=L); mov dword [rax+0xc], 0xa;
   add qword [L+0x58], 0x10; cmp [gs+0x60], rbx`.
* `luaT_objtypename` `0x265A440`: `movsxd r8, dword [rdx+0xc]` (tag read as dword).
* The interpreter reads the tag at `[rcx+0xc]`.

`L+0x58` = `top` (also `live::kTop`), moved by exactly `0x10` per slot.

### 2.2 Tag values (PROVEN live)

Read live from the per-global type-name table at **`[gs+0x3d0 + tag*8]`** where
`gs = [L+0x50]` (used by `luaT_objtypename` at `0x265A5B5`). On pid 1916,
`L=0x1A7D8FE30D0`, `gs=0x1A7D8FE3160`, each entry is a `TString*`; `+0x18` is its
char data:

| tag | name | | tag | name |
|-----|------|-|-----|------|
| 0 | `nil` | | 8 | `function` |
| 1 | `boolean` | | 9 | `userdata` |
| 2 | `userdata` (lightuserdata) | | 10 | `thread` |
| 3 | `number` | | 11 | `buffer` |
| 4 | **`integer`** | | 12 | `class` |
| 5 | `vector` | | 13 | `object` |
| 6 | `string` | | | |
| 7 | `table` | | | |

> **This build inserts `integer` at tag 4** (Roblox extension), shifting the
> standard Luau enum: `string` is **6** (not 5), `table` **7** (not 6),
> `function` **8** (not 7), `userdata` **9**, `thread` **10**, `buffer` **11**,
> then Roblox's `class` 12 / `object` 13.

Cross-checks that all agree:

* `lua_pushthread` writes tag `0xa` = 10 = `thread`. ✔
* `lua_pushlightuserdata` writes tag `2`. ✔
* `luaT_objtypename` treats `tag==9` as the metatable-bearing object type
  (`cmp r8d,9`, `0x265A44B`) and `string` as `6` (`cmp cl,6`, `0x265A4B9`). ✔
* The loader's constant switch writes bool `1`, number `3`, vector `5`,
  string `6` (§1.4). ✔
* The `lua_State`'s own GC type byte is `0x0A` at `[L+0]` (`validate_state`
  requires byte0 `== 0x0A`; live read showed `[L+0]=0x0A`). ✔

### 2.3 `TString`

`+0x00` GC link, `+0x10` hash (u32), `+0x14` length (u32), **`+0x18` char data**.
Evidence: `luaL_typename` `0x262A240` → `luaT_objtypename` returns a `TString*`,
then `add rax, 0x18`; live reads of `[ptr+0x10]=hash`, `[ptr+0x14]=len`,
`[ptr+0x18]=data` all decoded correctly.

---

## Q3 — call / run convention

### 3.1 The `execute` thunk (PROVEN)

`rva.luau.execute` = `0x265F2B0`, a 15-byte thunk taking **only `rcx`
(`lua_State*`)**:

```
0x265F2B0  cmp byte [rcx+4], 0            ; 80 79 04 00
0x265F2B4  jne 0x265FAB0                  ; 0f 85 f6 07 00 00   -> execute_true
0x265F2BA  jmp 0x266D720                  ; e9 61 e4 00 00      -> execute_false
0x265F2BF  int3
```

`execute_true` `0x265FAB0` and `execute_false` `0x266D720` are the two Luau VM
interpreter entries. Both begin `mov r13, rcx; lea r14, [rcx+0x40]` — `rcx`-only
ABI (`execute_false` then dereferences `[rcx+0x40]` = current `CallInfo`).
Byte `[L+4]` selects the variant; live, `[L+4] = 0` ⇒ the `execute_false` lane.

The engine's `thunk_shape_length` (`rbx.cpp:1622`) matches this exactly
(`80 79 <d8> <imm8>` + `jcc` + `jmp` = `0x0F` bytes), so its 14-byte absolute
`jmp` patch fits.

> `0x265F2C0`, immediately after the thunk, is a **separate 4-argument function**
> (`mov [rsp+0x20],r9d / [rsp+0x18],r8d / [rsp+0x10],rdx; push rbx`) — it is
> **not** `execute`. Do not hook it.

### 3.2 Why host calls wedge from the bridge thread

The engine's own notes say it (`rbx.cpp:1473-1485`): the resolved `lua_State` is
the game's **main thread**, which the game's Lua thread owns. Two threads must
not push call frames on one `lua_State`.

* A **pure push** (`lua_pushfstringL`, `0x261AD70`) from any thread is observed to
  be benign — it only moves `top`.
* A **call-ish entry** (`luaL_requiref`, `luau_load`) wedges.

Observed in this session: `GET /hostprobe` (which runs `pushfstringL` → `luaL_requiref`
→ `luau_load` from the bridge thread) **hung for >20 s and froze the engine's
`trace: refresh enter` loop**, while the client process stayed alive and
`Responding = True`. (The exact step that wedges — A vs C vs D — is unresolved
because the engine's log writes were not flushed before the freeze.)

### 3.3 Is hooking `rva.luau.execute` right?

**Yes.** It is the VM entry the client calls on the game's own Lua thread, so a
detour installed there runs our code *inside* that thread, with the client's C
API being called by the client itself — the only safe way to run call-ish
operations. The engine's approach (`hook_execute_entry` → `hook_execute_body` →
real `execute_true`/`execute_false` selected via `hook_dispatch_target`) matches
the ABI proven above: `1` input register, tail-entered by `jmp`, must return the
way the thunk would (call, don't tail-jump, to preserve the return address).

Caveat: `execute` is the interpreter dispatch, so the detour is entered **very
frequently** (per VM entry/resume, not per instruction). The engine's fast path
(one relaxed atomic load + one byte read on the idle path) is therefore the right
design.

---

## Operational facts (for the next session)

* **Attaching stops the client within seconds** — pid 5656 ≈7 s, pid 1916 ≈13 s,
  pid 10708 wedged at the first host-API call. There is no reliably "safe" attach.
* **Cold pages are unreadable.** `0x26A2000..0x26AA68D` and `0x26A3780` return no
  bytes (Hyperion only decrypts executed pages). After the `/hostprobe` wedge the
  client's *code* pages also became unreadable to RPM.
* `.pdata` is zeroed in memory; there are no function extents.
* Module base varies per run — always re-derive (e.g. `0x7FF71AA50000`).
* Bridge auth is the header **`X-Vesper-Token: <token>`** (or `?token=`), not
  `Authorization: Bearer` (`http.cpp:452`). Non-`/`, non-`/ping` routes require it.
* Handy RVAs used as anchors: `get_global_state 0x41ACDB0`,
  `pushfstringL 0x261AD70`, `index2addr 0x2619850`,
  `pushlightuserdata 0x261ADD0`, `pushthread 0x261AE40`,
  `luaL_typename 0x262A240`, `luaT_objtypename 0x265A440`,
  `raw_run_protected 0x262DD90`, `execute 0x265F2B0`,
  `execute_true 0x265FAB0`, `execute_false 0x266D720`,
  `load 0x269E780`, `load_module 0x41A3610`.

## Unresolved items

| # | Item | Next experiment |
|---|------|-----------------|
| 1 | Content of `0x26A3780` (forwards to `0x269E780`?) | Force a module load (`0x8891880`) so the page decrypts, then disassemble. |
| 2 | Does `luau_load` leave a closure on the stack? | In the `execute` hook, call `luau_load(L, ctx)` with a known chunk, dump `[L+0x58]-0x10` tag (expect `8`). |
| 3 | Which host call wedges (A/C/D)? | Split `hostapi_probe` into separate routes that flush the log after each step. |
| 4 | Return value: `eax` vs `ctx+0x4C` | Read both across one live successful load; the epilogue only writes `ctx+0x4C`. |
| 5 | Exact function extent of `luau_load` | Recover `.pdata` from the on-disk PE or trace the epilogue jmp-sites. |

---

## Addendum 2026-10-16 - executor-sequence RVAs (private-thread lane)

Goal: locate the 11f1 RVAs for the SkidBase sequence
`lua_newthread` -> `luaL_sandboxthread` -> `luau_load` -> `lua_getfield(task)` ->
`lua_getfield(defer)` -> `lua_pcall`.

Method actually used: live `ReadProcessMemory` of the module image
(base `0x7FF672C40000`, pid 9036; second run pid 10796), byte-signature matching
against the vendored Luau sources in
`ref/YuB-X/YuB-X-Module/Dependencies/Luau/VM/src/*.cpp`, and `E8 rel32`
cross-reference sweeps over the whole readable `.text`.

The live `lua_State` layout used as the decoding key (all confirmed from
disassembly, not assumed):

| offset | field | how it was pinned |
|--------|-------|-------------------|
| `+0x10` / `+0x12` | `nCcalls` / `baseCcalls` | saved/restored as `word` around every `luaD_rawrunprotected` |
| `+0x18` | `errorJmp` | tested/assigned in the pcall epilogues |
| `+0x28` / `+0x40` | `base_ci` / `ci` | `old_ci = ci - base_ci`, restored after the protected run |
| `+0x48` / `+0x58` | `base` / `top` | `(top - base) >> 4` in `lua_checkstack`; `base_ci->base` stored to `+0x48` |
| `+0x50` | `global` (`global_State*`) | matches the existing descriptor note; `[+0x650]` read from it |
| `+0x60` | `stack` | `savestack()`/`restorestack()` pairs in `lua_pcall` |

### Resolved RVAs

| RVA | function | confidence | evidence |
|-----|----------|------------|----------|
| `0x261BA30` | `lua_pcall(L, nargs, nresults, errfunc)` | **very high** | 4th arg `r9d` tested `!= 0`, then `[r9-1]*16 + [L+0x48] - [L+0x60]` = `savestack(index2addr(L,errfunc))`; `c.func` computed as `[L+0x58] - (nargs+1)*16 - [L+0x60]`; its `Pfunc` (`0x261BD20`) reads `CallS{func=[ud], nresults=[ud+8]}` and does `L->nCcalls++` against `0xC8` (`LUAI_MAXCCALLS`); error path re-enters `luaD_rawrunprotected(L, callerrfunc=0x2631120, ef)`. Source: `lapi.cpp:1113`. |
| `0x261BD20` | `f_call` (the `Pfunc` for the above) | high | `[ud]` / `[ud+8]` load = `struct CallS`; `word [rcx+0x10]++`; bound check vs `0xC8`. |
| `0x4254A10` | 5-arg load forward target | medium-high | Sole caller is `rva.luau.load` (`0x269E780`) at `0x269E972`, invoked with exactly `luau_load`'s ABI: `rcx=L`, `rdx=[ctx+0x30]` name, `r8=[ctx+0x38]` data, `r9=[ctx+0x40]` size, `[rsp+0x20]=[ctx+0x48]` env. Body spills all five args, seeds `[rsp+0x58] = 0xFFFFFFFF` (result sentinel), calls `0x4255600`, and clears `[L->global+0x630] &= 0xBFFFFFFF`. Body is opaque-predicate obfuscated (`mul` by magic constants, repeated calls to `0x4254D80`). |
| `0x4255600` | next hop inside that gate | medium | Only callee of `0x4254A10`'s real path (`0x4254A84`); receives `rdx = &(name,data,size)` and `r8 = &(result=-1, 0, 0)`. |
| `0x269E070` | protect wrapper called by `rva.luau.load` | high | Sole caller is `0x269E780` at `0x269FC72`; builds a stack `LoadContext`, `lea rdx,[rip+0x1a4]` -> `0x269E250` as the `Pfunc`, `lea r8,[r11-0x28]` as `ud`, then `call luaD_rawrunprotected` (`0x262DD90`) at `0x269E0D1`; epilogue does `luaD_seterrorobj` (`0x262EF10`) + `restore_stack_limit` (`0x2630F20`) + `ci`/`base` restore. |
| `0x269E250` | protected deserializer (`Pfunc`) | medium | Function at the `lea rdx,[rip+0x1a4]` site of `0x269E070`; walks the bytecode and interns strings (dual-hash lookups against the obfuscated global at `[L+0x70]`, `[global+0x38]/[global+0x40]`). This is where the closure push should land, but the push itself sits in a cold path not yet dumped. |
| `0x261A2B0` | `lua_absindex` | **very high** | `lea eax,[rdx+0x270F]; cmp eax,0x270F; ja` = pseudo-index test, then `[rcx+0x58]-[rcx+0x48] >> 4`, `+1`, `+idx`. Source `lapi.cpp:236`. Added as a decoding anchor. |
| `0x261A490` | `lua_typename` | very high | `cmp edx,-1; lea rax,[rip+...]; ret` matches `t == LUA_TNONE ? "no value" : luaT_typenames[t]`. Source `lapi.cpp:328`. |
| `0x261AED0` | `lua_setsafeenv(L, idx, value)` | high | `index2addr`-style resolve then `mov byte ptr [rax+7], cl` on the table object; `(rax+7) == table->safeenv`. Needed by `luaL_sandboxthread`. |

### Unresolved (pages never resident)

`lua_newthread`, `luaL_sandboxthread`, `lua_getglobal`, `lua_getfield`,
`lua_gettop`, `lua_settop`, `lua_insert`, `lua_remove` could **not** be located,
and were deliberately **not** added to the offset table (a wrong value is worse
than a missing one; the engine falls back to probing).

Reason: Hyperion commits `.text` lazily and decommits cold pages. Measured on
this client: only **46%** of `.text` (`RVA 0x1000..0x630A45C`) and **83%** of the
Luau window (`0x2500000..0x2A00000`) read back as non-zero; repeated 4 KiB
`ReadProcessMemory` passes recovered pages only slowly (43% -> 46% over 300 s on
a hot client). Concrete negatives:

- `lua_gettop` is 3-4 instructions (`mov R,[rcx+0x58]; sub R,[rcx+0x48]; sar R,4; ret`).
  Every register variant of that byte pattern returns **0 hits** across the whole
  image, and the 4 generic `mov R,[+58] ... sub R,[+48]` sites in the Luau window
  (`0x261A2BD` absindex, `0x2626350`, `0x265FA61`, `0x267B2D8`) are all
  something else. Its page is simply not committed.
- `lua_newthread` must deref `L->global->cb.userthread`. The signature
  `mov rax, [reg+0x650]` (8-bit-mod disp32) has exactly **2** hits in all of
  `.text` (`0x261BB78`, `0x269E104`) and both land inside the two pcall-family
  functions already identified - so `lua_newthread`'s page is absent too.
- `luaL_sandboxthread` must `lua_setfield(L, -2, "__index")`. `__index` lives at
  `RVA 0x7142608` in fully-mapped `.rdata`; a sweep for `lea reg,[rip+disp32]`
  targeting it returns **0** sites, so that function is also uncommitted.
- Call-frequency ranking of everything calling into `0x2619000..0x2628000`
  (4045 call sites) yields `lua_checkstack` 848, `luaL_typeerrorL` 566,
  `lua_error` 562, `pseudo2addr` 255 - and **no** `lua_getfield`/`lua_gettop`
  entry, which is itself evidence they live in unmapped pages.

Next experiment: drive code paths that force those pages in (e.g. exercise
`coroutine.create`, `table.insert`, `loadstring` in a live session, or attach
during a heavier place load), then re-sweep. `lua_gettop` is the cheapest probe:
its body is unambiguous once readable.

---

## Luau C-API sweep, build 11f155f3450f4c8e (2026-10-16)

Method: page-caching `ReadProcessMemory` dumper (merges across passes so Hyperion's lazy
`.text` commits accumulate) + capstone. Client was a ~4 h warm `RobloxPlayerBeta.exe`
(place 189707). **The entire `lapi.cpp` window `0x2619000-0x2629000` read back 100 %
non-zero on the first pass**, so the "these functions live on uncommitted pages"
theory recorded earlier in this file is disproved. The reason the sweep misses came
back empty is different: those functions have no standalone body in this build.

### Confirmed / newly identified

| RVA | Function | Confidence | Evidence |
|---|---|---|---|
| `0x2619780` | `lua_pseudo2addr` | certain | already in table; called by `index2addr` |
| `0x2619850` | `lua_index2addr` | certain | calls `pseudo2addr` for the pseudo range |
| `0x2619930` | `luaD_checkstack` | certain | `L+0x40`->`ci`, compares `ci+0x18` before every push |
| `0x261A2B0` | `lua_absindex` | certain | `mov rax,[rcx+58]; sub rax,[rcx+48]; sar rax,4; inc eax; add eax,edx` |
| `0x261A490` | `lua_typename` | certain | returns `luaT_typenames[t]` |
| `0x261AAC0` | `lua_tothread` | **high** | index2addr inlined, then `cmp dword [rax+0xC],0xA` -> returns `[rax]` else `xor eax,eax` |
| `0x261AE40` | `lua_pushthread` | **high** | barrier + checkstack + `mov [top],rbx; mov dword[top+0xC],0xA; add [rbx+0x58],0x10`, returns `L == g->mainthread` (`cmp [rcx+0x60],rbx`). Pushes `L` itself. |
| `0x261B000` | `lua_setmetatable` | high | `obj=top-2`, `mt=top-1`; writes `obj->mt` at `+0x10` (tt 8) or `+0x80` (tt 0xA); `add [rbx+0x58],-0x10`; returns 1 |
| `0x261B0C0` | `lua_call` | high | 357 B, sole callee `0x263FC10` (`luaD_call`), same family as `lua_f_call` `0x261BD20` |
| `0x263FC10` | `luaD_call` | high | sole callee of `lua_call` / `lua_f_call` |
| `0x265DE50` | Luau object allocator (`luaM_newgco`-class) | high | `lua_newuserdatatagged` (`0x261D650`) resolves a `g+0x68` memcat bucket then calls it |
| `0x261A970` | string-slot accessor | medium | index2addr inlined, `cmp dword [rax+0xC],5` (LUA_TSTRING) else NULL |
| `0x4323680` | Roblox SC thread helper | medium | `lua_tothread` on `nargs+1` (NULL-checked), then wipes/re-inits that thread and re-pushes it |
| `0x4323E50` | Roblox `Task::defer` engine method | medium | MSVC prologue, `sub rsp,0x140`, stack cookie; arg is a Roblox object, not a `lua_State*` |

### Layout re-verified from live code

`lua_State`: `marked@+2`, `status@+4`, `base_ci@+0x28`, `ci@+0x40`, `base@+0x48`,
`global@+0x50`, `top@+0x58`, `stack@+0x60`, `gclist@+0x78`.
`TValue` = 16 B, `value@+0`, `tag@+0xC`; `LUA_TTHREAD == 0xA`.
`global_State`: `gcbytes@+0`, `gc_threshold@+8`, `gray@+0x20`, `mainthread@+0x60`,
`memcat table@+0x68`, **`cb.userthread@+0x648`**. `CallInfo`: `func@+8`, `top@+0x18`.

### `lua_newthread`: body recovered, but there is NO standalone RVA

Every `lua_newthread` is **inlined** in this build. `0xA` (thread tag) is stored in exactly
21 places in all of `.text`, and only two are in the VM window: `0x261AE90`
(`lua_pushthread`, pushes `L` itself) and `0x261C9BF` (pushes a thread passed *in* as an
argument). Neither allocates. A global sweep for `lua_newthread`'s unique tail --
`mov rax,[g+0x648]` where `g = L->global` -- returns 28 hits, of which the only VM-region
one (`0x2642DCC`) is `lgc.cpp` thread-GC code.

The cleanest inlined copy is inside the Roblox helper at `0x4323680`, body at
`0x4323C5A..0x4323CEF`:

    ; rbx = fresh lua_State*, rsi = its stack, rdi = L
    mov qword [rbx+0x58], rsi            ; L1->top = stack
    mov qword [rbx+0x38], rsi-0x50       ; L1->base = top - 5 slots
    mov [rax+0x08], rsi  / mov [rax+0x10], 0   ; ci->func, ci->base
    mov dword [rax+0xC], 0               ; first slot = nil
    add qword [rbx+0x58], 0x10           ; L1->top++
    mov rax, [rcx]; mov [rax], rcx       ; L1->base = ci->func
    mov rax, [rbx+0x58]; add rax, 0x140  ; ci->top = top + LUA_MINSTACK(0x140)
    mov [rbx+0x80], [rdi+0x80]           ; inherit parent slot
    mov byte [rbx+0x4], [rdi+0x4]        ; status
    mov rax, [rdi+0x58]                  ; <- lua_newthread(L), the only thing left:
    mov [rax], rbx                       ;    setthvalue(L, L->top, L1)
    mov dword [rax+0xC], 0xA             ;    L->top->tt = LUA_TTHREAD
    add qword [rdi+0x58], 0x10           ;    api_incr_top(L)
    mov rax, [rdi+0x50]; mov rax,[rax+0x648]
    test rax, rax; je skip
    mov rdx, rbx; mov rcx, rdi           ;    g->cb.userthread(L, L1)
    call [rip+...]

Other inlined copies (all C++-entangled, **not** safely callable): `0x425CF0B`,
`0x425E811`, `0x426076F`, `0x4264B25`, `0x4265557`, `0x4265D93`, `0x4323CCD`.

### `Task::defer` is not a `lua_CFunction`

`0x4323E50` is a Roblox C++ method. Its prologue is `mov [rsp+0x10],rbx / mov [rsp+0x18],rsi /
mov [rsp+0x20],rdi / push rbp,r12,r13,r14,r15 / lea rbp,[rsp-0x40] / sub rsp,0x140 / mov rax,
[rip+cookie] / xor rax,rsp`. It dereferences `rcx+8` and `[rax+0x18]->+0x30` for Roblox
objects, then `call 0x4323680` with `edx=0`. It never reads arguments off a `lua_State`
stack, so pushing it as a C function will **not** implement `task.defer`. The Lua-visible
`task.defer` is a separate `lua_CFunction` in Roblox's scripting-library registration and
was not located.

### Could not resolve

- `luau_newthread` / `lua_newthread` - no standalone RVA (inlined; body above).
- `lua_gettop` - no standalone body; inlined into `lua_absindex` at `0x261A2C5`.
  `L->top - L->base >> 4` must be done inline.
- `lua_settop`, `lua_remove`, `lua_insert`, `lua_getfield` - no standalone bodies found.
- `lua_getglobal` - **is a macro** in stock Luau
  (`#define lua_getglobal(L,s) lua_getfield(L, LUA_GLOBALSINDEX, (s))`, `LUA_GLOBALSINDEX`
  = `-10002`); there is no code to find.
- `luaL_sandboxthread` - no standalone body. `lua_setsafeenv` (`0x261AED0`) has zero
  callers and `lua_replace` (`0x261A2E0`) has exactly one (`0x346FAEF`, Roblox code), so the
  sandbox sequence is fully inlined.
- The Lua-visible `task.defer` C function.

---

## Addendum 2026-10-16 (evening) - the private-thread lane, built and measured

Everything below was measured on live clients (place 189707, build 11f155f3450f4c8e),
one attach per client, logs in `%LOCALAPPDATA%\Vesper\logs\engine-<pid>.log`.

### Q4 - `lua_newthread` has no RVA, so the body was reimplemented

The cleanest inlined copy is in the Roblox thread helper at RVA `0x4323680`
(body `0x4323852..0x4323CF5`). Disassembled from a memory dump
(`dumps/11f1-image2.bin`, an image dump, not the encrypted file), it is
**three allocations plus a fixed set of stores** - the thread does not allocate
itself, which is why there is no entry to call:

| Block | Size | Memory category (a byte in the image) | Live value |
|---|---|---|---|
| `lua_State` | `0x88` | `u8[base + 0x7FD2E08]` | 12 |
| `CallInfo` array | `0x180` | `u8[base + 0x7FD2F00]` | 23 |
| `TValue` stack | `0x2D0` (45 slots) | `u8[base + 0x7FD3050]` | 31 |

The categories are read out of the client's own image at those RVAs (each is a
signed byte; a negative value selects the legacy `frealloc` path). They are
`rva.luau.memcat_state`, `rva.luau.memcat_ci` and `rva.luau.memcat_stack` in the
offset table.

### Q5 - the allocator: `0x265DBA0`, signature settled

`call 0x265DBA0` from the inlined body is **not** a free-form allocator. Its body
is `movsxd r9, edx / mov rdx,[rcx+0x50] / lea rbx,[rdx+r9*8] / mov r8,[rbx+0x1B0]`,
i.e.

    void* bump_alloc(lua_State* L, int memcat);

It takes **no size**: the chunk size is a property of the page the category is
carved out of (`[page+0x24]` is the stride, `[page+0x30]` the downward bump,
`[page+0x28]` the free list, `[page+0x34]` the live count), and the object starts
8 bytes into the chunk. `rcx` is the `lua_State*` (`L+0x50` = `global_State`),
`edx` is the category. The legacy branch is `g->frealloc(g->ud, NULL, 0, size)`
with `frealloc` at `g+0x38` and `ud` at `g+0x40`.

After each allocation the client adds the *logical* size to `g->totalbytes`
(`g+0x08`) and to `g->memcat_bytes[parent->memcat]` (`g + memcat*8 + 0x2DB0`),
then calls `g->cb_alloc(L, block, 0, size, 0xa|0x11, 0, 0)` **only if
`*(g+0x658) != 0`**. On this build that slot is `0x0`, so there is nothing to
skip; `g->cb_userthread` (`g+0x648`) *is* set (`0x7ff71f8ab0c0`) and is skipped
by default (`VESPER_CALL_USERTHREAD=1` opts in; calling it changes nothing).

### Q6 - the six field writes, confirmed live

`validate_state()` - the same check the engine uses to accept the game's own
state - **passes on the thread this lane builds** (`newthread: validate_state=1`
in the log). The writes are the ones in the header comment of `pvt::make`:
`end_ci = ci + 0x150`, `base_ci = ci = <ci array>`, `size_ci = 8`, `stack`,
address-obfuscated `stacksize` (`*(u32*)(L+0x70) = (u32)(L+0x70) ^ 0x2D0`),
one nil slot, `L->top`, `L->base`, `L+0x80` inherited from the parent, the tag
byte `0x0A`, `L+0x50 = global`.

`sizeof(lua_State)` on this build is therefore **`0x88`**, and the memory
categories are *not* encoded in the block: the client copies the parent's `L+6`
into the child's `L+1` and `L+6`.

### Q7 - the chunk loads on it; the VM refuses to run on it

`luau_load(thread, ctx)` returns status `0` and pushes a real closure on the
private thread, exactly as on the live state. `lua_pcall(thread, 0, 1, 0)`
(`0x261BA30`) then returns **`-1` with `L+3 == 0x7F`** and `L->ci` advanced by
one CallInfo that it never unwinds.

`0x7F` is `SCHEDULED_REENTRY` (`ldo.h:61` in the vendored sources, which are
Roblox's own). `performcall` (RVA `0x261BD20`, which is `luaD_callint` inlined)
compares `nCcalls` (`L+0x10`) against `baseCcalls` (`L+0x12`) *before* entering
the VM:

    movzx eax, word [rcx+0x10]        ; nCcalls, as it was
    inc  ax / mov [rcx+0x10], ax
    movzx r9d, word [rcx+0x12]        ; baseCcalls
    ...
    cmp ax, [saved baseCcalls]
    ja   luau_execute                 ; nCcalls > baseCcalls -> run the VM
    mov  byte [rbx+3], 0x7f           ; otherwise -> defer to the scheduler

A fresh thread has both counters at 0, so the call is *deferred*: the VM is
never entered. `lua_pcall`'s epilogue turns that into -1
(`0x261BCCE..0x261BCDE`: status 1, 6 or 0x7F all return -1 even when the
protected call itself returned 0).

Forcing the other branch (`nCcalls = 1`, `VESPER_FORCE_VM=1`) makes
`luau_execute` run - and **the client dies within milliseconds**, twice, once
from the bridge thread and once from the tick thread, with and without
`g->cb_userthread`. That is Hyperion: bytecode is not executed on a thread the
host does not own. The deferred answer is therefore not a bug to work around, it
is the guard.

### Q8 - `luaL_sandboxthread`

Still no standalone body, and now moot for the milestone: the probe chunk
(`return 41 + 1`) needs no global, and it is **not** skipped silently - the
thread inherits the parent's `L+0x80` (its metatable slot) exactly as the
client's own `lua_newthread` does, and `tests/hello.lua` is written to touch no
global for that reason. `tests/hello-globals.lua` is the variant that needs the
sandbox and it does not run yet.

### What `--exec` does end to end

`Vesper.exe --exec file.lua` -> `POST /exec` (`bridge.cpp:handle_exec`) ->
`rbx::exec_source` -> compile in-process with the vendored Luau -> build the
private thread -> `luau_load` -> `lua_pcall` -> answer `{ok, value, error,
report}`. The engine log gets one `exec:` line per step and the full report is
returned to the shell. `%LOCALAPPDATA%\Vesper\autorun.lua` runs the same lane at
attach time (before the bridge is even answering), because the client tears
foreign threads down seconds after attach and an HTTP round trip can lose that
race.

---

## Addendum 2026-10-16 (late) - the scheduled-reentry route, and what it costs

Goal of this pass: make `return 41 + 1` come back as **42**. It does not, yet.
What follows is everything that was *measured* on live clients (place 189707,
build `11f155f3450f4c8e`, one attach per client) and the one open question it
leaves. All disassembly below is from `dumps/11f1-live.bin`, a full image dump
of a warm client (22:30, pid 10496, 49.7 % of `.text` non-zero); the two
control signatures `CONTROL_EXEC_THUNK` (`0x265F2B0`) and `CONTROL_WHJS_STEP`
(`0x428DFE0`) both read back correctly from it.

### The `nCcalls` gate is `luaD_callint`, and it is not the only way in

`0x261BD20` is `luaD_callint` with `performcall` **inlined**. Re-read from the
live image:

```
0x261BD34  movzx eax, word [rcx + 0x10]   ; nCcalls
0x261BD42  movzx r9d, word [rcx + 0x12]   ; baseCcalls
0x261BD47  mov [rsp+0xe0], ax             ; save OLD nCcalls
0x261BD5B  mov [rsp+0xe8], r9w            ; save OLD baseCcalls
0x261BD4F  inc ax / mov [rcx+0x10], ax    ; ++nCcalls
0x261BD6E  cmp ax, 0xC8 ...               ; LUAI_MAXCCALLS / hard limit 0xE1
...
0x261C44A  or  dword [rax + 0x2C], 1      ; L->ci->flags |= LUA_CALLINFO_RETURN
0x261C473  movzx eax, word [rsp+0xE0]     ; OLD nCcalls
0x261C47B  cmp  ax, word [rsp+0xE8]       ; OLD baseCcalls
0x261C483  ja   0x261C48B                  ; nCcalls > baseCcalls -> run the VM
0x261C485  mov  byte [rbx+3], 0x7F         ; else SCHEDULED_REENTRY
0x261C48B  ... call 0x265FAB0 / 0x266D720 ; luau_execute
```

`0x261C485` is the **only** writer of `0x7F` anywhere in `.text`
(`C6 43 03 7F` scan over `0x2600000..0x2740000`, one hit). So the gate is
exactly one compare, and it compares the values saved on entry.

`lua_pcall` (`0x261BA30`) gets there through the client's own protection:

```
0x261BABB  lea rdx, [rip+0x25E]     ; Pfunc = 0x261BD20 (luaD_callint)
0x261BADB  call 0x262DD90           ; luaD_rawrunprotected
...
0x261BCCA  test esi, esi             ; status from rawrunprotected
0x261BCCC  jne  0x261BCEA           ; the throw path (seterrorobj + ci restore)
0x261BCCE  movzx eax, byte [rbx+3]  ; L->status
0x261BCD2  cmp al, 1 / 6 / 0x7F
0x261BCDE  mov eax, 0xFFFFFFFF      ; return -1, frame NOT unwound
```

Because the gate sets a status instead of throwing, `rawrunprotected` returns 0,
`lua_pcall` takes the `-1` return and **skips** the `L->ci` restore at
`0x261BC75`. The CallInfo that `luau_precall` built is still there when
`lua_pcall` returns. That is the opening.

### `resume_continue` is the ungated VM entry (RVA `0x2630540`)

`resume_continue` is `static` in `ldo.cpp` but this build keeps an out-of-line
copy, and it is called as a `Pfunc` from 20 sites (so it is
`void(lua_State*, void*)`):

```
0x2630540  push rbx / sub rsp,0x20 / mov rdi, rdx / mov rbx, rcx
0x2630550  movzx eax, byte [rbx+3]     ; L->status
0x2630554  test al, al  / je
0x2630558  cmp al, 0x7F  / jne exit   ; SCHEDULED_REENTRY is accepted
0x2630567  mov rax, [rbx+0x28]        ; L->base_ci
0x2630570  mov rcx, [rbx+0x40]        ; L->ci
0x2630574  cmp rcx, rax / jbe exit    ; require ci > base_ci
0x263057D  mov byte [rbx+3], 0        ; L->status = LUA_OK
0x2630581  mov rax, [rcx+8]           ; ci->func
0x2630585  mov rdx, [rax]             ; Closure*
0x2630588  cmp byte [rdx+3], 0 / je   ; cl->isC == 0 -> Luau closure
0x26305FA  mov eax, [rcx+0x2C]; test al,8   ; LUA_CALLINFO_OPYIELD -> luau_finishop
0x2630647  cmp byte [rbx+4], 0        ; the execute_true/false selector
0x2630650  call 0x265FAB0             ; execute_true
0x263065A  call 0x266D720             ; execute_false
0x2630550  (loop)
```

**There is no `nCcalls`/`baseCcalls` compare anywhere in it.** The `while`
condition in `ldo.cpp` literally reads
`while ((L->status == LUA_OK || L->status == SCHEDULED_REENTRY) && L->ci > L->base_ci)`,
which is the deferred state `lua_pcall` leaves behind. This is the client's own
completion path for a scheduled reentry, so it is the honest way to finish the
call rather than the `VESPER_FORCE_VM=1` hack (which enters the VM from
`performcall` with counters no Roblox-owned thread ever has).

### The sequence that is now implemented

`rsv::run()` in `engine/src/rbx.cpp`:

1. `pvt::make(parent)` - the private thread (unchanged).
2. `luau_load(thread, ctx)` - status 0, closure pushed.
3. `lua_pcall(thread, 0, 1, 0)` - returns `-1`, `L->status == 0x7F`, frame kept.
4. `rsv::frame_ready` verifies `status == 0x7F`, `ci > base_ci`, `ci->func` tag 8,
   `closure->isC == 0`.
5. Set `isactive = 1`, `nCcalls = baseCcalls = 1` (what `resume_start` leaves).
6. `luaD_rawrunprotected(thread, resume_continue@0x2630540, nullptr)` - the VM runs
   under the client's own protection, so a Luau error comes back as a status.

Measured on pid 9796 (`%LOCALAPPDATA%\Vesper\logs\engine-9796.log`):

```
exec: luau_load -> status 0, closure on the private thread
exec: calling lua_pcall(thread, 0, 1, 0)
exec: lua_pcall -> rc=-1 top 0x156abff0d58->0x156abff0d58 delta=+0 guarded=1
exec: frame: status=0x7F ci=0x156b3760a78 base_ci=0x156b3760a48 depth=1 func_slot=0x156abff0d48 tag=8 closure=0x156bca1b8d0 isC=0
exec: calling resume_continue(0x156b1b01aa0) @ 0x2630540 under luaD_rawrunprotected @ 0x262dd90
```

Everything up to that last line is in the log. The client is **gone** after it.

### The bytecode is not the problem (measured, pid 8204)

`VESPER_NO_RESUME=1` (or a `%LOCALAPPDATA%\Vesper\no-resume` marker file, which
can be toggled between bridge calls on one session) stops after the frame dump so
the thread survives and the frame can be inspected without entering the VM.

Plain-compiler output for `return 41 + 1` (31 bytes, logged as `bytecode[31]`):

```
0b 03 00 00 01 01 00 00 01 02 00 03 | 41 00 00 00 | 04 00 2a 00 | 16 00 02 00 | 00 01 00 00 00 00
                              sizecode=3  insn[0]     insn[1]       insn[2]
```

and the instruction array the client's loader produced (`ci+0x20`), same run:

```
7e 00 00 00 | a0 00 2a 00 | 0e 00 02 00 | 03 00 00 00 | ...
```

Operand bytes are byte-for-byte identical; **only the opcode byte changed**:
`0x41 -> 0x7E`, `0x04 -> 0xA0`, `0x16 -> 0x0E`. So the loader accepted the
plaintext, read it correctly and rewrote the opcodes into the client's own
space before storing them. `rva.opcode_lookup_table` (`0x71433E0`) is that
space: 256+ pseudo-random bytes indexed as `table + fieldoffset`, with
`0x26579C0` as the one-instruction helper (`lea rax,[rdx+rcx]; ret`). This is
also why the existing `RobloxEncoder` (which indexes `lookup[opcode*227]`) is
wrong, and why `compile()`'s output is not a better candidate than the plain
compiler's - the loader does the transformation itself.

**Conclusion: the chunk the VM is asked to run is the client's own canonical
form of `return 41 + 1`. The crash is not a mis-decoded instruction stream.**

### What is still missing

`luau_execute` (`0x266D720`, the `execute_false` lane, selected because
`[L+4] == 0`) enters, and the client is terminated. What happens next is not
recorded:

* No access violation reaches the engine's vectored exception handler
  (`AddVectoredExceptionHandler(1, note_exception)`, added this pass, writes one
  `veh:` line and returns `EXCEPTION_CONTINUE_SEARCH`). In pid 7308's log the
  last `veh:` line is a `0x80000003` **inside RobloxPlayerBeta.dll**
  (`0x7ffadcb77c49`) raised ~450 ms after the lane started, i.e. Hyperion's own
  trap, not a fault of ours.
* No WER `Application` event is produced either.
* So the termination looks deliberate (Hyperion), not like an ordinary null
  dereference. **This is an inference from the absence of a fault, not a
  measurement of a kill.**

The open question is therefore narrow and answerable: *what does
`luau_execute` require of a thread that Roblox's own `lua_newthread` provides
and `pvt::make` does not?* Candidate fields, in the order they are worth
checking:

1. `luau_execute`'s prologue reads only `L->ci` and `ci->flags` (`test byte
   [rdx+0x2C], 4` at `0x266D748`, then a `g->cb` call when bit 2 is set - ours
   is not), so the missing state is deeper in, at the first dispatch.
2. Roblox's per-thread identity (`rva.get_identity_struct` `0x1d24020`,
   `rva.impersonator` `0x1d24280`): attach already logs
   `could not locate thread identity field`. A thread that never got an
   identity may be rejected at the dispatch.
3. `g->cb_userthread` (`g+0x648`, set to `0x7ff71f8ab0c0` on this build): the
   private thread is built without notifying it. **Tested with
   `VESPER_CALL_USERTHREAD=1` (pid 8124): the callback fires and the client is
   still terminated at the resume.** Ruled out as the cause.
4. The GC's view: the thread is pushed on the parent so it is reachable, but it
   was never handed to `g->cb_userthread`, and three instructions are enough for
   a `luaC_checkGC` to sweep it.

### Next experiment, in order

1. Re-run the resume with `VESPER_CALL_USERTHREAD=1`. Cheapest, and it removes
   the one callback the client's own thread creation always fires.
   **DONE, pid 8124 - still terminates.** The log shows the callback firing
   (`exec: g->cb_userthread(0x7ff71f8ab0c0) called=1`) and the lane reaching the
   resume:

   ```
   exec: exec: g->cb_userthread(0x7ff71f8ab0c0) called=1
   exec: calling resume_continue(0x1cdad4e8838) @ 0x2630540 under luaD_rawrunprotected @ 0x262dd90
   ```

   and the client is gone after that line.

2. Install a one-shot probe in `resume_continue`'s caller - not a detour: log
   `L`, `L->ci`, `L->base`, `L->top`, `L->global`, `L+0x48`, `L+0x50`, `L+0x60`
   and the first 8 words at `ci+0x20` immediately before the `call`, and again
   from a `Pfunc` that runs *inside* the protected region, to see whether the
   VM returned at all or died on entry.
3. Only then go back to the scheduler hand-off (`task.defer` plumbing at
   `0x4323000..0x4325000`, `rva.task.defer` `0x4323E50`), whose payoff is that
   the run point is the game's own Lua thread with a live frame - inside which
   `luau_load` + `lua_pcall` on the *game's* state satisfies the gate anyway,
   because there `nCcalls > baseCcalls`.

### Hyperion traps, measured (pid 8124)

The vectored handler recorded three deliberate traps, **before** the exec lane
started, and the same three again a second later:

```
veh: exception 0x80000003 at 00007ffadcb77c49 rip=00007ffadcb77c49 rbx=fa7ec47c5906d2e7
veh: exception 0x80000004 at 00007ffadd22a621 rip=00007ffadd22a621 rbx=c535117dc829a079
veh: exception 0xC000001D at 00007ffadd891cf0 rip=00007ffadd891cf0 rdi=0000000000000042
```

`0x80000003` (breakpoint), `0x80000004` (single step) and `0xC000001D`
(illegal instruction) in sequence, at addresses inside RobloxPlayerBeta.dll with
register values that are not addresses, is Hyperion's own trap machinery rather
than a fault of ours. They are the reason the engine's own threads also stop
within ~5 s of attach (pid 6960: the log ends at `trace: refresh enter` and the
bridge socket is closed while the client stays alive and `Responding`).

So the client has two separate failure modes and they must not be confused:

| symptom | pid | when |
|---|---|---|
| engine threads + bridge die, **client alive** | 5460, 6960, 8204 | ~5 s after attach, with or without the resume |
| **client dies** | 9796, 7308, 8124 | within ~100 ms of `call resume_continue` |

Only the second one is caused by entering the VM, and it produces no fault that
reaches the vectored handler.

### Corrected entries in the offset table

| key | value | note |
|---|---|---|
| `rva.luau.callint` / `rva.luau.performcall` | `0x261bd20` | `luaD_callint` with `performcall` inlined |
| `rva.luau.reentry_gate` | `0x261c473` | the one compare; `0x261c485` writes `0x7F` |
| `rva.luau.resume_continue` | `0x2630540` | ungated `luau_execute` driver, `void(L, void*)` |
| `rva.luau.resume_continue_execute_true` | `0x2630650` | `call 0x265FAB0` |
| `rva.luau.resume_continue_execute_false` | `0x263065a` | `call 0x266D720` |
| `rva.luau.precall_inline_a` / `_b` | `0x263302c` / `0x2635040` | inlined `luau_precall` |
| `rva.luau.vmvalue_table_index` | `0x26579c0` | `lea rax,[rdx+rcx]; ret` |
| `struct.callinfo.base/func/proto/top/savedpc/flags` | `0x00/0x08/0x10/0x18/0x20/0x2c` | from the inlined `luau_precall` writes |

`rva.luau.luaD_call` `0x263FC10` is **not** `luaD_call`: it is a string-table
lookup (tag shift, `g+0x348`, 32-byte entries). The key is unused by the engine
but the identification in the earlier addendum is wrong.

### Still open

1. Executing bytecode at all needs a Roblox-owned thread: the scheduler
   hand-off (`task.defer`, Lua binding near `0x4323E50`) or another entry the
   host drives itself.
2. `luaL_sandboxthread` (globals on a private thread).
3. **What `luau_execute` checks on entry.** This is now the only thing between
   the resume lane and a value; see "Next experiment" above.
4. Whether the host opcode remap (`rva.opcode_lookup_table`) is needed -
   **answered, negatively**: the loader rewrites opcodes itself, so the plain
   compiler's output is the right input.

---

## Addendum 2026-10-18 - RESOLVED: `return 41 + 1` = 42, client alive

The bytecode space was the whole blocker. Corrects item 4 above: the plain
compiler's output is **not** the right input, and no Roblox-owned thread was
needed. Measured end-to-end on pid 7728 and pid 8652 (place 189707):

```
exec: compiled 39 bytes with vendored->internal (head 0b 03 00 00)
exec: bytecode[39]= ...00000000 8c002a00 82000200...
exec: after load: ... code@...= 9c000000 4b002a00 82000200 ...
exec: calling resume_continue(0x...) @ 0x2630540 under luaD_rawrunprotected @ 0x262dd90
exec: resume_continue -> status=0 reached=1 top 0x...->0x... delta=+304
exec: after resume: L->status=0x00
exec: chunk=cli ok=1 value="42" (slot=0x... value=0x4045000000000000 tag=3 number=42)
```

### The loader map (RVA 0x269F907-0x269F939)

`stored = table[input]` - a **direct** index into `rva.opcode_lookup_table`
(`0x71433E0`), a 256-byte bijection. `r14` is the module base
(`lea r14,[rip-0x269f90e]` targets RVA 0). Not `table[in*227]`, not `in*227`:
the three `table[(op*227)&0xFF]` probes read `0xDF/0x4B/0x82`, while the direct
reads `table[0x41]/[0x04]/[0x16] = 0x7E/0xA0/0x0E` reproduce run (A) exactly
(and `table[0x6C]/[0x76]/[0x73] = 0xB6/0xDC/0x7D` reproduce run (B)).

### Why entering the VM killed the client

`execute_false`'s dispatch (fetch `0x266D863`) uses the byte table at **`0x267B0AC`**
(targets `0x267AF38`, same three-level switch shape as the loader's). It accepts
only **92** opcodes; case `0x5C` jumps to `0x267A989` = `mov ecx,0x25; int 0x29`,
a deliberate trap. Stock bytecode stores `table[std]` and the plain inverse stores
`std`; both put invalid opcodes in `code[0]`, so the VM trapped - which is the
"no fault reaches the VEH, client gone in ~100 ms" death, **not** thread ownership
and **not** `VESPER_CALL_USERTHREAD`. `resume_continue` was always the right entry.

### The vendored enum differs from the client's internal enum

The internal opcodes (identified by disassembling the dispatch handlers in
`dumps/11f1-live.bin`) are: LOADN=`0x4B` (`0x266DF83`, `R[A]=double(D)`, tag 3),
LOADB=`0x49` (`0x266DF4C`), LOADNIL=`0x0D` (`0x266DF2D`), MOVE=`0xC8` (`0x266DFCA`,
`R[A]=R[B]`), CLOSEUPVALS=`0x6B` (`0x266E1D8`), RETURN=`0x82` (`0x2670A70`; the
handler pops the CallInfo at `0x2670B2F` and writes results to `[ci+8]`),
NOP/skip=`0x9C` (`0x2671152`, `add r12,4; jmp fetch`).

The encoder is `input = table⁻¹[internal(V)]` (`rbx.cpp` mode 4, `SemanticEncoder`;
`g_vendor_to_internal` holds the identified pairs). For `return 41 + 1`
(PREPVARARGS(0)->NOP, LOADN 42, RETURN): input `00 8C 82` -> stored `9C 4B 82`.

### Result value location

`RETURN` copies its results to the callee's `ci->func` slot (`rdx = [ci+8]` at
`0x2670AC3`), then sets `L->top` to the caller's `ci->top`. So the value is **not**
at `L->top - 0x10` (that slot reads nil); read the remembered `ci->func` slot
(`render_slot_value`). `VESPER_NO_RESUME=1` still works for inspection.

### Still open

1. The full vendored->internal map (only 7 of 92 opcodes are identified). Needed
   for any chunk beyond the probe; derive the rest the same way (disassemble
   `JT[bt[internal]]`) or find the client compiler's opcode table.
2. `luaL_sandboxthread` (globals on a private thread) - unchanged.
3. Per-thread identity/capabilities (`no per-thread RobloxExtraSpace matched`) -
   not required for the probe, still unmeasured.

---

## Addendum 2026-10-18 (late) - the wire-format gap that made nested chunks lie or crash

Once the opcode space was complete (see `docs/opcode-space-11f1.md`), two
symptoms remained and both were **serialization**, not opcodes:

* a chunk whose first proto is an inner function executed that inner function
  (`local function f() return 7 end; return 1` returned **7**);
* a chunk with a nested non-capturing function (`nest1`) made `luau_load` fail
  with status `-1` **and terminated the client**.

Cause: the client's `luau_load` reads, **per proto and for `version >= 11`**, a
feedback-vector section (`lvmload.cpp:734`):

```c
if (version >= 11) { p->feedbackvecsize = readVarInt(data, size, offset); ... }
```

`BytecodeBuilder::getVersion()` returns `11` because `LBC_VERSION_TARGET == 11`,
but `writeFunction()` wrote that section only behind
`FFlag::LuauEmitCallFeedback` (off by default) - so the version announced 11
while every proto omitted it. The loader consumed the chunk's `mainid` trailer as
`feedbackvecsize` and mis-linked the last proto; single-proto chunks still picked
`protos[0]` and worked by accident.

Fix: the vendored `BytecodeBuilder.cpp` now writes the section unconditionally
(empty when no feedback slots are recorded) - a serialization-only change; the
generated code is unchanged. Verified live: `nest1` -> 1, `nest2` -> 1, `f7` -> 1,
with the client alive.

---

## Addendum 2026-10-18 (late) - the global environment, measured

The `RobloxExtraSpace` layout in the vendored `lua.h` is
`SharedExtraSpace@+0x18` (Shared::ScriptContext `@+0x20`), `Capabilities@+0x38`,
`Identity@+0x60`, reached from `lua_State` via `userdata` (the vendored header
puts that field at `+0x68`, but that layout does **not** match this build).

Measurement run (place 189707): a wide read-only scan of every qword field of the
live main `lua_State` was scored on that shape. **No field produced an identity in
the 1..64 range at `+0x60`**; the only "matches" were TValues (a candidate whose
`+0x38` was the bit pattern of the double `0.1`). The scan now requires the
`SharedExtraSpace -> ScriptContext` pointer to equal the known ScriptContext
before any write, so it no longer pokes unrelated heap objects. Identity wiring is
therefore **still open** and is *not* needed for the milestone.

What made the milestone work is the environment slot: the loader resolves a
chunk's environment from `[L+0x80]` when `LoadContext.env == 0`, and the private
thread inherits that slot from the parent. Measured: `parent env slot
[L+0x80]=<table>`. A chunk that resolves a global therefore works even with
`no per-thread RobloxExtraSpace matched`:

```
exec: chunk=cli ok=1 value="function"   # local t = type(print); print("hello world"); return t
```

---

## Addendum 2026-10-18 (night) - the chunk environment is NOT injectable, and
## `luau_load` rejects several chunk shapes with "bytecode corrupted"

Two findings from the overnight regression run (place 189707, build
`11f155f3450f4c8e`, one client per chunk, client alive in every case).

### 1. Environment injection does not reach the loaded chunk

The milestone's "env from `[L+0x80]`" is real for *reading* (the parent slot is
inherited and globals resolve), but it is **not a writable hook** for the loaded
chunk on this build. Measured with the UNC prelude:

- the prelude runs on a private thread, builds `E = setmetatable({}, {__index =
  getfenv()})` with fields on it, and returns `E` (`unc: env table built`,
  `env=0x... tag=7`);
- pointing the user thread's `[L+0x80]` at `E`, **and** separately handing the
  loader the table's stack index via `LoadContext+0x48` (`index2addr`), both
  leave the user chunk resolving the **real globals**: `type`, `pairs`, `print`
  work, but `E`'s own fields (`__n`, `identifyexecutor`) read `nil`.

So a Lua-level executor surface cannot be mounted by swapping the env slot.
Related, measured: `_G` is **nil** inside a chunk (`type(_G) == "nil"`) while
`getfenv` exists (`type(getfenv) == "function"`).

### 2. `luau_load` returns `status=1`, `"bytecode corrupted"`, for several chunk
### shapes the vendored compiler emits

Isolated by bisection. Each failing chunk parses cleanly against the client's
own `decode_table`/`class_table` (offline parser `%TEMP%\parse_bc.py`), so the
opcode wire is fine; the client's loader rejects on its own, content-dependently:

| shape | example | result |
|---|---|---|
| `optimizationLevel 1` FASTCALL in a proto with `nups > 0` | `local function f(a,b) return rawset(E,a,b) end; return 1` | fails; loads at opt 0 |
| debug info (line info / function name) present | same chunk with `debugLevel=2` | fails; loads at `debugLevel=0` |
| `>= 7` protos in one chunk | 6 closures + main (7 protos) | fails; 5 closures (6 protos) load |
| table literal with ~120 string keys | `{ k1=1, ..., k120=120 }` | fails; 40 string constants load |

Mitigation shipped in `exec_on_private_thread`: a recompile ladder
`(opt1,dbg2) → (opt0,dbg2) → (opt1,dbg0) → (opt0,dbg0)`, plus running the UNC
prelude on its **own** private thread so a rejected prelude no longer poisons the
user chunk's thread. The failure text is now read back from the stack and logged.

---

## Addendum 2026-10-18 (third) - the surface can no longer wedge `--exec`

Measured regression: the eight UNC preludes were run **inline on the exec path**
with no cap. On a busy client each `load -> call -> resume` pass took ~1 s, so the
eight of them exceeded the shell's HTTP timeout and the user's chunk was never
reached (`run: failed - no response from the bridge`; engine log stopped after the
preludes, no `chunk=cli` line).

Fix, `engine/src/rbx.cpp` only: `install_unc_surface(parent, budget_ms)` replaces
the inline loop, bounded by `kUncBudgetMs = 4000` ms and resumed on the next exec
via a persistent index. The user's chunk always runs; a prelude the loader rejects
is logged and skipped without stopping the rest. The preludes were reordered so
`identifyexecutor`, `getgenv`/`getrenv`/`checkcaller` and `getthreadidentity` are
the first three.

### `rc=-1` on a prelude is not a failure

`lua_pcall` returns -1 for `SCHEDULED_REENTRY` (0x7F) even when the protected call
succeeded, which is why every working prelude logs `unc: prelude rc=-1 ...`. The
same line carries `value=0x3ff0000000000000 tag=3` (= the `1.0` the prelude
returned) and the `resume_continue -> status=0 reached=1` line. A real failure is a
missing closure after a status-0 load:

```
unc: frame: status=0x7F ci=... base_ci=... depth=1 func_slot=... tag=0 closure=0x0 isC=1
```

i.e. `luau_load` returned success but pushed no closure on that private thread -
the same content-dependent loader behaviour as section 2 above. It now costs only
that one global.

### Re-verified against a live client (one client per chunk, client alive)

`t42`→42, `rich`→26, `arr`→1, `len`→3, `nest1`→1, `nest2`→1, `prnt`→"function",
`unc1`→"Vesper|table|true|8". `print("hello world")` returns `nil` (what `print`
returns) and lands in the client's own log as `Info [FLog::CreatorOutput] hello
world`.

Environmental note, not part of the fix: the engine's threads freeze (log stops,
`/ping` times out) ~6-30 s after attach while the client stays alive - the
documented "engine threads + bridge die, client alive" mode. It reproduces with the
`no-unc` marker (surface disabled) and with `return 41 + 1`, so it is unrelated to
the surface; verification is therefore one chunk per client, run as soon as the lane
is ready.

