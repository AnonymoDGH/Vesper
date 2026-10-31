#include <vesper/common.hpp>
#include <vesper/guard.hpp>

namespace vesper {

namespace detail {

thread_local std::jmp_buf g_guard_jmp[kGuardDepth];
thread_local int g_guard_depth = 0;

namespace {
PVOID g_guard_handle = nullptr;
}  // namespace

LONG CALLBACK guard_handler(EXCEPTION_POINTERS* info) {
    if (g_guard_depth <= 0) return EXCEPTION_CONTINUE_SEARCH;

    const DWORD code = info->ExceptionRecord->ExceptionCode;
    switch (code) {
        case EXCEPTION_ACCESS_VIOLATION:
        case EXCEPTION_IN_PAGE_ERROR:
        case EXCEPTION_ILLEGAL_INSTRUCTION:
        case EXCEPTION_PRIV_INSTRUCTION:
        case EXCEPTION_INT_DIVIDE_BY_ZERO:
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:
            break;
        default:
            return EXCEPTION_CONTINUE_SEARCH;
    }

    std::longjmp(g_guard_jmp[--g_guard_depth], 1);
}

void install_guard_once() {
    if (g_guard_handle != nullptr) return;
    g_guard_handle = AddVectoredExceptionHandler(1, guard_handler);
}

}  // namespace detail

static const char* level_name(Level level) {
    switch (level) {
        case Level::Trace: return "TRACE";
        case Level::Debug: return "DEBUG";
        case Level::Info:  return "INFO ";
        case Level::Warn:  return "WARN ";
        case Level::Error: return "ERROR";
    }
    return "?????";
}

void log_line(Level level, const char* text) {
    SYSTEMTIME st{};
    GetLocalTime(&st);

    char line[2240];
    const int written = snprintf(line, sizeof(line), "[%02u:%02u:%02u.%03u][%s][%lu] %s\r\n",
                                 st.wHour, st.wMinute, st.wSecond, st.wMilliseconds,
                                 level_name(level), GetCurrentThreadId(), text);
    if (written <= 0) return;
    const std::size_t len = static_cast<std::size_t>(written) < sizeof(line)
                                ? static_cast<std::size_t>(written)
                                : sizeof(line) - 1;

    // A terminated thread must never be able to wedge the engine's logging. Hyperion
    // does terminate threads that are not its own, and the tick thread logs every
    // 250 ms, so a thread killed between Enter and Leave would leave this critical
    // section owned forever: the log freezes, the bridge stops answering, and the
    // client keeps running -- exactly the shape of the "engine dies a few seconds
    // after attach" symptom. So try the lock, and if it is held write the line anyway:
    // a short append to a FILE_APPEND_DATA handle is atomic enough, and losing strict
    // ordering beats losing the engine.
    const bool locked = TryEnterCriticalSection(&detail::log_lock()) != 0;

    const HANDLE handle = detail::log_handle();
    if (handle != INVALID_HANDLE_VALUE && handle != nullptr) {
        DWORD ignored = 0;
        WriteFile(handle, line, static_cast<DWORD>(len), &ignored, nullptr);
    }
    if (GetConsoleWindow() != nullptr) {
        fputs(line, level >= Level::Warn ? stderr : stdout);
    }

    if (locked) LeaveCriticalSection(&detail::log_lock());
}

}  // namespace vesper
