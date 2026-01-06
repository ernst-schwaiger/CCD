#include <iostream>
#include <Windows.h>

using namespace std;

// Returns eax after cpuid was invoked, with eax_val in eax register
uint32_t cpuid_vmflags() {
    __asm {
        mov eax, 1
        cpuid
        mov eax, ecx
        // eax now contains the vm flags (which is the return val in the windows ABI)
    }
}

uint32_t cpuid_vmids() {
    __asm {
        mov eax, 0x40000000
        cpuid
    }
}

__declspec(naked) unsigned __int32 get_ecx(void)
{
    __asm {
        mov eax, ecx   ; return ECX in EAX
        ret
    }
}

__declspec(naked) unsigned __int32 get_edx(void)
{
    __asm {
        mov eax, edx   ; return ECX in EAX
        ret
    }
}

static bool isVMPresent(void)
{
    uint32_t cpu_id = cpuid_vmflags();
    return ((cpu_id & (0x80000000)) > 0);
}

void serialize4BytesLE(uint32_t val, char *buf)
{
    buf[0] = (char)(val & 0xff);
    buf[1] = (char)((val >> 8) & 0xff);
    buf[2] = (char)((val >> 16) & 0xff);
    buf[3] = (char)((val >> 24) & 0xff);
}


static void getHypervisorId(char *buf)
{
    uint32_t eax = cpuid_vmids();
    uint32_t ecx = get_ecx();
    uint32_t edx = get_edx();

    serialize4BytesLE(ecx, &buf[0]);
    serialize4BytesLE(edx, &buf[4]);
    serialize4BytesLE(eax, &buf[8]);
    buf[12] = '\0';
}

unsigned __int64 __readgsqword(unsigned long);

int main()
{
    // Detect if a debugger is attached
    cout << "I am" << (IsDebuggerPresent() ? "" : " not") << " running in a Debugger!\n";

    bool vmPresent = isVMPresent();
    // Check whether process is running in VM
    cout << "I am" << (vmPresent ? "" : " not") << " running in a VM!\n";

    char vmIdBuf[13];
    getHypervisorId(vmIdBuf);
    cout << "CPU Hypervisor Id :" << vmIdBuf << "\n";

    return 0;
}