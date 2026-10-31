-- The execution milestone: `return 41 + 1` must come back as the number 42.
--
-- The private thread the executor builds is not sandboxed: it inherits the
-- parent's metatable, so `print`, `game` and `_G` do not resolve on it. A
-- script that touches any of those fails with "attempt to call nil" before it
-- can return anything, which says nothing about whether the chunk ran. So this
-- milestone is pure arithmetic -- no name lookup at all.
--
-- The value is returned (not printed), so the engine reads it back off the
-- thread's stack and logs it: `exec: chunk=hello.lua ok=1 value="42"`. The
-- bridge route returns the same thing as `{"ok":true,"value":"42"}`, and
-- `Vesper.exe --exec tests\hello.lua` prints it.

return 41 + 1
