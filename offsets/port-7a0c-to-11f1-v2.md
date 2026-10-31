# Offset port version-7a0c6d10fcb34a2c -> version-11f155f3450f4c8e

- generated 2026-10-16T02:40:19+00:00
- from `C:\Users\USUARIO\roblox-lua-exec\vesper\dumps\7a0c-image2.bin`
- to `C:\Users\USUARIO\roblox-lua-exec\vesper\dumps\11f1-image2.bin`
- bases: A 0x7ff6fbca0000, B 0x7ff7379d0000
- relocated 71, unported 21, skipped 2

| key | old rva | new rva | conf | delta | note |
|---|---|---|---|---|---|
| rva.fake_datamodel | 0x8dc5d00 | — | FAIL | ref: no relocated site (0 sites seen) |
| rva.task_scheduler.raw | 0x7f7c6e0 | 0x7f7e6e0 | 0.95 | +0x2000 | direct: seed32 probe+0x10 unique, window 0.95 |
| rva.task_scheduler | 0x8d6f048 | 0x8d71348 | 0.95 | +0x2300 | direct: seed32 probe+0x20 unique, window 0.96 |
| rva.task_scheduler.target_fps | 0x8d6f0f8 | 0x8d713f8 | 0.95 | +0x2300 | direct: seed32 probe+0x60 unique, window 0.91 |
| rva.task_scheduler.target_fps_alt | 0x85daa10 | — | FAIL | ref: no relocated site (4 sites seen) |
| rva.get_global_state | 0x41ab690 | 0x41acdb0 | 0.60 | +0x1720 | ref: 1/1 sites agree (call) |
| rva.get_lua_state | 0x41ab690 | 0x41acdb0 | 0.60 | +0x1720 | ref: 1/1 sites agree (call) |
| rva.get_lua_state_for_instance | 0x41ab690 | 0x41acdb0 | 0.60 | +0x1720 | ref: 1/1 sites agree (call) |
| rva.opcode_lookup_table | 0x7141390 | 0x71433e0 | 0.99 | +0x2050 | direct: seed32 probe+0x0 unique, window 1.00 |
| rva.enable_load_module | 0x888f650 | 0x8891880 | 0.75 | +0x2230 | direct: seed16 probe+0xa0 scored 212/256 (2 hits) |
| rva.ktable | 0x84698a0 | 0x846baa0 | 0.95 | +0x2200 | ref: 8/20 sites agree (rip) |
| rva.identity_ptr | 0x854cbb8 | — | FAIL | ref: no relocated site (64 sites seen) |
| rva.get_identity_struct | 0x1d22880 | 0x1d24020 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.98 |
| rva.impersonator | 0x1d22ae0 | 0x1d24280 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.99 |
| rva.capabilities_get | 0x1d22a20 | 0x1d241c0 | 0.75 | +0x17a0 | direct: seed16 probe+0x20 scored 224/256 (1 hits) |
| rva.tls_get | 0x6bb0 | 0x6bb0 | 0.99 | +0x0 | direct: seed32 probe+0x0 unique, window 0.99 |
| rva.instance_new | 0x42c7f80 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.push_instance | 0x4191e60 | 0x4193580 | 0.99 | +0x1720 | direct: seed32 probe+0x0 unique, window 0.96 |
| rva.cast_args | 0x4100cf0 | 0x4102410 | 0.95 | +0x1720 | direct: seed32 probe+0x20 unique, window 0.94 |
| rva.instance.find_first_child | 0x4fd9e0 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.instance.find_first_child_of_class | 0x4fa5b0 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.instance.find_first_ancestor_which_is_a | 0x4fa2d0 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.instance.get_children | 0x4fb5f0 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.instance.set_parent | 0x1d305b0 | 0x1d31d50 | 0.95 | +0x17a0 | direct: seed32 probe+0x10 unique, window 0.93 |
| rva.instance.hash_lookup | 0x2a5c4d0 | 0x2a5dc90 | 0.95 | +0x17c0 | direct: seed32 probe+0x10 unique, window 0.95 |
| rva.instance.get_property | 0x1d20c00 | 0x1d223a0 | 0.95 | +0x17a0 | direct: seed32 probe+0x70 unique, window 0.98 |
| rva.instance.get_property_data | 0x1d24490 | 0x1d25c30 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 1.00 |
| rva.instance.get_values | 0x40fea60 | 0x4100180 | 0.60 | +0x1720 | ref: 1/2 sites agree (call) |
| rva.instance.index | 0x418d840 | 0x418ef60 | 0.95 | +0x1720 | direct: seed32 probe+0x30 unique, window 0.95 |
| rva.instance.userdata_index | 0x418f6f0 | 0x4190e10 | 0.95 | +0x1720 | direct: seed32 probe+0x30 unique, window 0.94 |
| rva.sc_resume | 0x4256c10 | 0x4258330 | 0.95 | +0x1720 | direct: seed32 probe+0x50 unique, window 0.98 |
| rva.sc_resume_parallel_waiting_scripts | 0x42cfce0 | 0x42d1400 | 0.99 | +0x1720 | direct: seed32 probe+0x0 unique, window 0.93 |
| rva.sc_task_queue | 0x43125b0 | 0x4313cd0 | 0.99 | +0x1720 | direct: seed32 probe+0x0 unique, window 0.92 |
| rva.whjs_step | 0x428c8c0 | 0x428dfe0 | 0.99 | +0x1720 | direct: seed32 probe+0x0 unique, window 0.91 |
| rva.rbx_spawn | 0x425eae0 | — | FAIL | ref: no relocated site (2 sites seen) |
| rva.luau.load | 0x269cfe0 | — | FAIL | ref: no relocated site (10 sites seen) |
| rva.luau.execute | 0x265db10 | 0x265f2b0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.97 |
| rva.luau.execute_false | 0x266bf80 | 0x266d720 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.95 |
| rva.luau.execute_true | 0x265e310 | 0x265fab0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.96 |
| rva.luau.load_module | 0x41a1ef0 | 0x41a3610 | 0.95 | +0x1720 | direct: seed32 probe+0x20 unique, window 0.98 |
| rva.luau.raw_run_protected | 0x262c5f0 | 0x262dd90 | 0.95 | +0x17a0 | direct: seed32 probe+0x20 unique, window 0.94 |
| rva.luau.throw | 0x262c620 | 0x262ddc0 | 0.95 | +0x17a0 | direct: seed32 probe+0x70 unique, window 0.95 |
| rva.luau.exception | 0x262c490 | 0x262dc30 | 0.95 | +0x17a0 | direct: seed32 probe+0x10 unique, window 0.96 |
| rva.luau.prepare_finalize | 0x262dfb0 | 0x262f750 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.97 |
| rva.luau.run_finalizers | 0x262e040 | 0x262f7e0 | 0.95 | +0x17a0 | direct: seed32 probe+0x20 unique, window 0.98 |
| rva.luau.clock | 0x26855e0 | 0x2686d80 | 0.85 | +0x17a0 | direct: seed16 probe+0x0 scored 226/256 (337 hits) |
| rva.luau.index2addr | 0x26180b0 | 0x2619850 | 0.95 | +0x17a0 | direct: seed32 probe+0x10 unique, window 0.98 |
| rva.luau.checkstack | 0x2618190 | 0x2619930 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 1.00 |
| rva.luau.pseudo2addr | 0x2617fe0 | 0x2619780 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.98 |
| rva.luau.pushfstring | 0x2655f70 | 0x2657710 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 1.00 |
| rva.luau.pushvfstring | 0x2619560 | 0x261ad00 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 1.00 |
| rva.luau.pushfstringL | 0x26195d0 | 0x261ad70 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.99 |
| rva.luau.pushvfstring_v | 0x2655760 | 0x2656f00 | 0.95 | +0x17a0 | direct: seed32 probe+0x20 unique, window 0.99 |
| rva.luau.get_type_name | 0x2618cf0 | 0x261a490 | 0.95 | +0x17a0 | direct: seed32 probe+0x50 unique, window 0.96 |
| rva.luau.register_userdata | 0x261cf10 | 0x261e6b0 | 0.95 | +0x17a0 | direct: seed32 probe+0x10 unique, window 0.96 |
| rva.luau.new_userdata_tagged | 0x261beb0 | 0x261d650 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.99 |
| rva.luau.new_proto | 0x2657550 | 0x2658cf0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.99 |
| rva.luau.free_proto | 0x2657c20 | 0x26593c0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 1.00 |
| rva.luau.nil_object | 0x667d848 | 0x667f848 | 0.95 | +0x2000 | direct: seed32 probe+0x30 unique, window 0.92 |
| rva.luau.dummy_node | 0x667d2e8 | 0x667f2e8 | 0.95 | +0x2000 | direct: seed32 probe+0x40 unique, window 0.92 |
| rva.luau.create_table | 0x14ff390 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.luau.get_table | 0x26356a0 | 0x2636e40 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.96 |
| rva.luau.set_table | 0x26380c0 | 0x2639860 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.95 |
| rva.luau.lua_error | 0x261bea0 | 0x261d640 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.99 |
| rva.luau.luaL_error | 0x2621b60 | 0x2623300 | 0.95 | +0x17a0 | ref: 11/48 sites agree (call) |
| rva.luau.luaL_argerrorL | 0x2620f10 | 0x26226b0 | 0.95 | +0x17a0 | ref: 3/12 sites agree (call) |
| rva.luau.luaL_typeerrorL | 0x2620f90 | 0x2622730 | 0.95 | +0x17a0 | ref: 10/64 sites agree (call) |
| rva.luau.luaL_requiref | 0x26255c0 | 0x2626d60 | 0.95 | +0x17a0 | ref: 4/55 sites agree (call) |
| rva.luau.luaL_tolstring | 0x262a810 | 0x262bfb0 | 0.60 | +0x17a0 | ref: 1/3 sites agree (call) |
| rva.luau.luaL_typename | 0x2628aa0 | — | FAIL | ref: no relocated site (2 sites seen) |
| rva.luau.get_func | 0x267ad50 | 0x267c4f0 | 0.95 | +0x17a0 | direct: seed32 probe+0x20 unique, window 0.99 |
| rva.luau.call_binTM | 0x263c320 | 0x263dac0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.98 |
| rva.luau.gc_step | 0x2642b60 | 0x2644300 | 0.95 | +0x17a0 | direct: seed32 probe+0x10 unique, window 0.99 |
| rva.luau.gc_init | 0x265c6b0 | 0x265de50 | 0.95 | +0x17a0 | direct: seed32 probe+0x20 unique, window 0.98 |
| rva.luau.gc_visit_gco | 0x265c250 | 0x265d9f0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.97 |
| rva.luau.rawrunprotected | 0x262c5f0 | 0x262dd90 | 0.95 | +0x17a0 | direct: seed32 probe+0x20 unique, window 0.94 |
| rva.luau.current_func_name | 0x2620e90 | — | FAIL | ref: no relocated site (0 sites seen) |
| rva.luau.set_thread_finalizer | 0x261b850 | 0x261cff0 | 0.99 | +0x17a0 | direct: seed32 probe+0x0 unique, window 0.98 |
| rva.luau.shared_string_create | 0x49e09d0 | 0x49e20f0 | 0.95 | +0x1720 | direct: seed32 probe+0x10 unique, window 0.99 |
| rva.luau.fire_mouse_click | 0x3bcf940 | — | FAIL | ref: no relocated site (0 sites seen) |
| rva.luau.fire_right_mouse_click | 0x3bcfae0 | — | FAIL | ref: no relocated site (0 sites seen) |
| rva.luau.fire_mouse_hover | 0x3bd0f30 | — | FAIL | ref: no relocated site (0 sites seen) |
| rva.luau.fire_mouse_hover_leave | 0x3bd10d0 | — | FAIL | ref: no relocated site (0 sites seen) |
| rva.luau.fire_proximity_prompt | 0x30cff60 | 0x30d1720 | 0.60 | +0x17c0 | ref: 1/2 sites agree (call) |
| rva.luau.signal.disconnect | 0x4169ee0 | 0x416b600 | 0.99 | +0x1720 | direct: seed32 probe+0x0 unique, window 0.96 |
| rva.luau.signal.fire_touch_interest | 0x15205c0 | — | FAIL | ref: no relocated site (2 sites seen) |
| rva.luau.appdata_info | 0x14e1ed0 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.luau.is_legal_send_event | 0x46f90a0 | — | FAIL | ref: no relocated site (1 sites seen) |
| rva.luau.crash_ptr | 0x8c88450 | 0x8c8a680 | 0.75 | +0x2230 | direct: seed16 probe+0x40 scored 226/256 (3 hits) |
| rva.luau.crash_lock_violation_script | 0x888f4a8 | 0x88916d8 | 0.75 | +0x2230 | direct: seed16 probe+0x70 scored 208/256 (2 hits) |
| rva.luau.crash_lock_violation_instance | 0x893c6e8 | — | FAIL | ref: no relocated site (4 sites seen) |
| rva.roblox.print | 0x1ce4150 | 0x1ce58f0 | 0.95 | +0x17a0 | ref: 38/64 sites agree (call) |

## skipped

- `rva.hyperion.bitmap` = 0x202830 — hyperion module (unused by engine)
- `rva.hyperion.control_flow_guard` = 0x5c4320 — hyperion module (unused by engine)
