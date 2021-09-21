#include <windows.h>
#include <iostream>

#include <detours.h> // include MS Detours header
#include <peconv.h> // include libPeConv header

size_t g_PESize = 0;
BYTE *g_PEBuf = NULL;

int (WINAPI *pMessageBoxA)(HWND hWnd, LPCSTR lpText, LPCSTR lpCaption, UINT uType) = ::MessageBoxA;

int WINAPI my_MessageBoxA(
    _In_opt_ HWND hWnd,
    _In_opt_ LPCSTR lpText,
    _In_opt_ LPCSTR lpCaption,
    _In_ UINT uType)
{
    std::cout << "TITLE: [" << lpCaption << "]" << std::endl;
    std::cout << "MESSAGE: [" << lpText << "]" << std::endl;
    return pMessageBoxA(hWnd, lpText, lpCaption, uType);
}

void hook_apis()
{
    //initialize hooking:
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    // the APIs that we want to hook:
    DetourAttach(&(PVOID&)pMessageBoxA, my_MessageBoxA);

    //finalize hooking:
    DetourTransactionCommit();
}

BYTE* load_pe(const LPCSTR pe_path)
{
    // manually load the PE file using libPeConv:
    size_t v_size = 0;
#ifdef LOAD_FROM_PATH
    //if the PE is dropped on the disk, you can load it from the file:
    BYTE* my_pe = peconv::load_pe_executable(pe_path, v_size);
#else
    size_t bufsize = 0;
    BYTE *buffer = peconv::load_file(pe_path, bufsize);

    // if the file is NOT dropped on the disk, you can load it directly from a memory buffer:
    BYTE* my_pe = peconv::load_pe_executable(buffer, bufsize, v_size);
#endif
    if (!my_pe) {
        return NULL;
    }
    
    // set the loaded PE in the global variables:
    g_PESize = v_size;
    g_PEBuf = my_pe;

    // if the loaded PE needs to access resources, you may need to connect it to the PEB:
    peconv::set_main_module_in_peb((HMODULE)my_pe);
    return g_PEBuf;
}

int run_pe_entrypoint(BYTE *my_pe)
{
    //calculate the Entry Point of the manually loaded module
    DWORD ep_rva = peconv::get_entry_point_rva(my_pe);
    if (!ep_rva) {
        return -2;
    }
    ULONG_PTR ep_va = ep_rva + (ULONG_PTR)my_pe;
    //assuming that the payload is an EXE file (not DLL) this will be the simplest prototype of the main:
    int(*new_main)() = (int(*)())ep_va;
    //call the Entry Point of the manually loaded PE:
    return new_main();
}

int main(int argc, char *argv[])
{
    if (argc < 2) {
        std::cout << "Args: <path to the exe>" << std::endl;
        return 0;
    }
    const LPCSTR pe_path = argv[1];

    // manually load an EXE with libPEConv:
    if (!load_pe(pe_path)) {
        std::cout << "[-] Loading the PE: "<< pe_path << " failed!\n";
        return -1;
    }

    hook_apis();
    MessageBoxA(NULL, "Message Box Hooked", "OK", MB_OK);

    // run the manually loaded EXE:
    int res = run_pe_entrypoint(g_PEBuf);
    system("pause");
    return res;
}
