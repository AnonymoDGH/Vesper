// A deliberately boring DLL used to isolate one question: will the client's
// loader accept an unsigned module whose imports are all satisfied by modules it
// already has? Nothing here does anything except exist and export one function.
#include <windows.h>

extern "C" __declspec(dllexport) int PlainValue(void) {
    return 7;
}

BOOL APIENTRY DllMain(HMODULE, DWORD, LPVOID) {
    return TRUE;
}
