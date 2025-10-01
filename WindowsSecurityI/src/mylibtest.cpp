#include <windows.h>
#include <iostream>

int main() 
{
    // Explicitly load the DLL
    HMODULE hDll = LoadLibrary(TEXT("mylib.dll"));
    if (!hDll) {
        std::cerr << "Failed to load DLL.\n";
        return 1;
    }

    // Dont call anything in the DLL

    // Clean up
    FreeLibrary(hDll);
    return 0;
}