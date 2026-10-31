// Vesper -- fault guard.
//
// MinGW has no `__try`/`__except`, and the engine calls into Roblox at addresses
// taken from a table. A stale table must degrade to "this strategy did not
// validate" rather than taking the client down, so risky calls run inside a
// vectored exception handler that unwinds back to the caller.
//
// Contract for `guarded`: the callable must publish its result through memory it
// owns (a static, a heap object) and must not rely on its own locals after the
// guard fires -- setjmp semantics make those indeterminate.
#pragma once

#include <windows.h>

#include <csetjmp>

#include <vesper/stage.hpp>

namespace vesper {

constexpr int kGuardDepth = 8;

namespace detail {

extern thread_local jmp_buf g_guard_jmp[kGuardDepth];
extern thread_local int g_guard_depth;

void install_guard_once();
LONG CALLBACK guard_handler(EXCEPTION_POINTERS* info);

}  // namespace detail

template <typename Fn>
bool guarded(Fn&& fn) {
    // 'X' in the stage file turns the vectored handler OFF for this process.
    //
    // Why it exists: `guard_handler` is process-wide and runs before the client's own
    // handlers. While a guarded call is in flight it longjmps out of *any* access violation
    // (including a Hyperion trap or a Luau error the client would have handled itself),
    // skipping the client's own exception dispatch, its `__except` cleanup and any lock it
    // was holding. A client that cannot recover from its own faults is a client that dies
    // or freezes on the first one. With 'X' the call runs unprotected instead: a genuinely
    // bad pointer still crashes, but nothing hijacks the client's own exception handling.
    if (vesper::stage_skips('X')) {
        fn();
        return true;
    }

    if (detail::g_guard_depth >= kGuardDepth) return false;
    detail::install_guard_once();
    if (setjmp(detail::g_guard_jmp[detail::g_guard_depth]) != 0) return false;
    ++detail::g_guard_depth;
    fn();
    --detail::g_guard_depth;
    return true;
}

}  // namespace vesper
