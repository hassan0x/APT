---
title: "Kernel Callbacks — How EDRs See Every Process, Thread, and Image"
date: 2026-08-22
categories: [Windows Internals, Kernel]
tags: [kernel, callbacks, windbg, windows, edr]
---

Before an EDR can block anything, it has to know something happened. In user-mode, EDRs hook NTDLL syscall stubs. But those hooks are trivially bypassed — load a clean copy of ntdll from disk and the hooks disappear. The second line of defense lives in the kernel: **notify callbacks**. This post explains what they are, the exact kernel structures that store them, and how to enumerate and disable each type using WinDbg.

---

## What Are Kernel Callbacks?

The Windows kernel exposes several registration APIs that let drivers subscribe to system-wide events:

![Kernel callback types overview](/assets/images/callbacks-types-overview.svg)

| API | Events received |
|-----|----------------|
| `PsSetCreateProcessNotifyRoutineEx` | Every process creation and exit |
| `PsSetCreateThreadNotifyRoutineEx` | Every thread creation and exit |
| `PsSetLoadImageNotifyRoutineEx` | Every DLL/EXE load into any process |
| `ObRegisterCallbacks` | Every handle open/duplicate on Process or Thread objects |
| `CmRegisterCallbackEx` | Every registry operation |

Windows Defender's `WdFilter.sys` registers all five. When your code does `CreateProcess`, the kernel fires Process callbacks before the new process runs a single instruction. When you `LoadLibrary`, Image callbacks fire before the DLL's `DllMain`. This is why behavioral EDR detection works even against completely novel, signature-free malware — the kernel tells the EDR about every interesting operation.

Understanding how these callbacks are stored makes it possible to enumerate exactly who is watching and remove specific observers.

---

## The EX_FAST_REF Encoding

![EX_FAST_REF pointer encoding](/assets/images/callbacks-exfastref.svg)

Before diving into each callback type, there is one concept that appears everywhere: **EX_FAST_REF**.

The kernel stores callback pointers in an array, but instead of storing a raw pointer it stores an `EX_FAST_REF` — a pointer with the **low 4 bits repurposed as a reference count**. This means every raw slot value you read from a callback array has its lowest nibble set to a small integer, not zero.

To recover the actual pointer to the `_EX_CALLBACK_ROUTINE_BLOCK` structure, mask off the low nibble:

```
actual_ptr = raw_value & 0xFFFFFFFFFFFFFFF0
```

The `_EX_CALLBACK_ROUTINE_BLOCK` structure:
```
+0x000  RundownProtect   — synchronization guard (0x20 = active)
+0x008  Function         — the actual callback function pointer
+0x010  Context          — arbitrary context value passed at registration
```

The callback function is always at `+0x008`. Once you have the function address, `lm a <address>` resolves which driver registered it.

---

# Process Notify Callbacks

Every driver that wants notification of process creation/exit calls `PsSetCreateProcessNotifyRoutineEx`. The kernel stores all registered callbacks in `PspCreateProcessNotifyRoutine` — a **64-slot array** inside `ntoskrnl`. Each slot is an `EX_FAST_REF` pointer as described above.

When a new process is created, the kernel walks this array, dereferences each non-null slot, strips the low nibble, and calls the `Function` at `+0x008`. The callback receives a pointer to the `_EPROCESS` of the new process and can inspect or block it.

![Callback array to function resolution chain](/assets/images/callbacks-array-chain.svg)

## Step 1 — Dump the Array

```
dp nt!PspCreateProcessNotifyRoutine
```

`dp` dumps pointer-sized values starting at this symbol. The array has 64 slots; in practice only a handful are populated. Zero values are empty — stop when you see a run of zeros.

**Example output:**
```
fffff804`b0b04b80  ffffbf0f`e4dfb52f  ffffbf0f`e823bb5f
fffff804`b0b04b90  ffffbf0f`e823b82f  ffffbf0f`e823b8ef
fffff804`b0b04ba0  ffffbf0f`e823b64f  ffffbf0f`e84e888f
fffff804`b0b04bb0  00000000`00000000  00000000`00000000   ← empty
```

Save the array base (`fffff804b0b04b80`) — you'll use it in Step 4 to compute which address to zero.

## Step 2 — Decode a Slot

```
dq (ffffbf0f`e823bb5f & 0xfffffffffffffff0)
```

Strip the low nibble to get the `_EX_CALLBACK_ROUTINE_BLOCK` pointer, then read its fields. The callback function is at `+0x008`.

**Example output:**
```
ffffbf0f`e823bb50  00000000`00000020   ← +0x00 RundownProtect (0x20 = active)
ffffbf0f`e823bb58  fffff804`42fdaa60   ← +0x08 Function (save this)
ffffbf0f`e823bb60  00000000`00000006   ← +0x10 Context
```

## Step 3 — Identify the Driver

```
lm a fffff804`42fdaa60
```

Resolves the module that owns the function address. Run `.reload /f` first if the output is empty — symbols may not be loaded yet.

**Example output:**
```
start             end                 module name
fffff804`42f80000 fffff804`4301b000   WdFilter   ← Windows Defender
```

## Step 4 — Remove the Callback

```
ep fffff804`b0b04b88 0
```

`ep` = edit pointer-sized value. The second slot in the array is at `array_base + 0x8` (slot index 1, each slot is 8 bytes). Writing zero to it removes that callback — the kernel skips null slots when walking the array, so this callback function will never be called again.

**Verify:**
```
dp nt!PspCreateProcessNotifyRoutine
fffff804`b0b04b80  ffffbf0f`e4dfb52f  00000000`00000000   ← zeroed ✓
```

To enumerate and print all slots automatically:
```
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspCreateProcessNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```

---

# Thread Notify Callbacks

Registered via `PsSetCreateThreadNotifyRoutineEx`. The kernel fires these on every thread creation and exit in the system. Structure and disabling method are **identical** to Process callbacks — the only difference is the symbol name.

Practical use for EDRs: thread callbacks fire before a newly injected thread runs, giving the EDR a chance to inspect the thread's start address. If the start address points to shellcode in a non-module region (no `lm` entry), the EDR flags it.

```
dp nt!PspCreateThreadNotifyRoutine
```

Decode, identify, and zero the same way as Process callbacks. Replace the symbol name in the automation script too:

```
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspCreateThreadNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```

---

# Image Load Notify Callbacks

Registered via `PsSetLoadImageNotifyRoutineEx`. The kernel fires these whenever an executable image (EXE or DLL) is mapped into any process's address space — before the image's entry point runs.

This is what lets EDRs intercept DLL injection. Even if you inject a DLL by mapping it manually (without `LoadLibrary`), the moment the section is mapped the kernel fires image load callbacks. The EDR's callback sees the image path and base address, scans the PE, and can block or alert.

```
dp nt!PspLoadImageNotifyRoutine
```

Same decode and disable method as Process and Thread callbacks:

```
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspLoadImageNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```

To get the fixed RVA for any callback array (survives reboots — KASLR changes the base but not the layout):
```
? nt!PspCreateProcessNotifyRoutine - nt
? nt!PspCreateThreadNotifyRoutine  - nt
? nt!PspLoadImageNotifyRoutine     - nt
```

---

# ObRegisterCallbacks — Handle Stripping

`ObRegisterCallbacks` is the most powerful callback type. A driver registers a pre-operation callback for Process or Thread object handles — meaning it gets called every time **any process tries to open a handle** to a protected target.

The callback receives the requested `ACCESS_MASK` and can **strip rights from it** before the handle is returned. For example, Defender strips `PROCESS_VM_READ` from any handle opened to its own process — even if you call `OpenProcess(PROCESS_ALL_ACCESS, MsMpEng_pid)` as SYSTEM, the returned handle has VM read removed.

Callbacks are stored per object type in a **linked list** inside `_OBJECT_TYPE`. Unlike the array-based callbacks above, this is a true doubly-linked list with no fixed size.

### How Windows Doubly-Linked Lists Work

Windows uses a **circular doubly-linked list** (`LIST_ENTRY`) throughout the kernel. Every node has two pointers:

- **Flink** ("Forward Link") — points to the **next** node
- **Blink** ("Back Link") — points to the **previous** node

The list is circular: the last node's Flink points back to the head, and the first node's Blink points back to the head. This means the head is always in the loop.

```
HEAD (at type_addr + 0xC8)
  Flink → node1       Blink → node2 (last)

node1:
  Flink → node2       Blink → HEAD

node2 (last):
  Flink → HEAD        Blink → node1
```

**Empty list:** HEAD.Flink == HEAD.Blink == address of HEAD itself — it loops to itself.

**Single node:** node.Flink == node.Blink == address of HEAD — the one node points back to the head in both directions.

**Walking the list:** start at HEAD.Flink, follow Flink at each node, stop when Flink equals the HEAD address again.

### Key Structure Offsets

`_OBJECT_TYPE` (the kernel's type object for "Process" or "Thread"):
```
+0x010  Name             — UNICODE_STRING (e.g. "Process")
+0x028  Index            — type index (7 = Process, 8 = Thread)
+0x0C8  CallbackList     — LIST_ENTRY head of all registered callbacks
```

`CALLBACK_ENTRY_ITEM` (each node in the list):
```
+0x000  EntryItemList        — LIST_ENTRY (Flink/Blink to navigate)
+0x010  Operations           — DWORD: 1=create handle, 2=duplicate, 3=both
+0x014  Active               — DWORD: 1=enabled, 0=disabled  ← patch this
+0x018  CallbackRegistration — pointer to parent registration block
+0x020  ObjectType           — pointer back to owning _OBJECT_TYPE
+0x028  PreOperation         — callback function address
+0x030  PostOperation        — callback function address (or NULL)
```

![ObRegisterCallbacks linked list — CALLBACK_ENTRY_ITEM chain with Active field](/assets/images/callbacks-ob-linked-list.svg)

## Step 1 — Find the Object Type

```
dp nt!ObTypeIndexTable
```

`ObTypeIndexTable` is an array of `_OBJECT_TYPE*` pointers indexed by type number. Process = index 7, Thread = index 8. Read the pointer at each index.

**Example output:**
```
fffff804`b0bc6830  ffffbf0f`e469c650   ← [7] Process type object
fffff804`b0bc6840  ffffbf0f`e468b450   ← [8] Thread type object
```

To list all type names:
```
.for (r $t0 = 1; @$t0 < 50; r $t0 = @$t0 + 1) { r $t1 = poi(nt!ObTypeIndexTable + (@$t0 * 8)); .if (@$t1 != 0) { .printf "Index %d: %p  ", @$t0, @$t1; dt nt!_OBJECT_TYPE @$t1 Name } }
```

## Step 2 — Check the Callback List

```
dt nt!_OBJECT_TYPE ffff8c03`bac8d0c0
dt nt!_OBJECT_TYPE ffff8c03`bac9f7a0
```

Look at `+0xC8 CallbackList`. The list is a standard Windows doubly-linked circular list. The head is the `CallbackList` field itself, embedded inside `_OBJECT_TYPE` at `type_addr + 0xC8`. An empty list points to itself — `Flink == Blink == type_addr + 0xC8`.

**Example output — Process (non-empty):**
```
dt nt!_OBJECT_TYPE ffff8c03`bac8d0c0
   +0x010 Name         : _UNICODE_STRING "Process"
   +0x028 Index        : 0x7
   +0x0c8 CallbackList : _LIST_ENTRY [ 0xffffa180`7454c980 - 0xffffa180`7454c980 ]
```
`ffff8c03bac8d0c0 + 0xC8 = ffff8c03bac8d188`. Flink is `ffffa1807454c980` — different from `ffff8c03bac8d188` → **non-empty**, one callback node at `ffffa1807454c980`. Save that address.

**Example output — Thread (empty):**
```
dt nt!_OBJECT_TYPE ffff8c03`bac9f7a0
   +0x010 Name         : _UNICODE_STRING "Thread"
   +0x028 Index        : 0x8
   +0x0c8 CallbackList : _LIST_ENTRY [ 0xffff8c03`bac9f868 - 0xffff8c03`bac9f868 ]
```
`ffff8c03bac9f7a0 + 0xC8 = ffff8c03bac9f868`. Flink equals that address → **empty**, no callbacks registered for Thread on this system. Stop here for Thread.

> **Trap:** Do not dump `dq type_addr+0xC8 L7` when the list is empty. Doing so reads straight into adjacent `_OBJECT_TYPE` fields beyond the `CallbackList` LIST_ENTRY. Those pointers look like addresses but are unrelated structure data — `lm a` will return nothing because they are not callback functions.

## Step 3 — Read the Callback Node

```
dq ffffa180`7454c980 L7
```

Maps directly onto `CALLBACK_ENTRY_ITEM` offsets:

```
ffffa180`7454c980  ffff8c03`bac8d188 ffff8c03`bac8d188   ← +0x000 Flink, +0x008 Blink
                                                            both = head → only 1 node in list
ffffa180`7454c990  00000001`00000003 ffffa180`7454c960   ← +0x010 Ops=3, +0x014 Active=1
                                                            +0x018 CallbackRegistration*
ffffa180`7454c9a0  ffff8c03`bac8d0c0 fffff805`42ee2ea0   ← +0x020 ObjectType*, +0x028 PreOperation
ffffa180`7454c9b0  00000000`00000000                     ← +0x030 PostOperation = NULL
```

Note that `Flink == Blink == ffff8c03bac8d188` here means this is the **only node** and it points back to the head — not that the list is empty. The empty check applies to the **head** (inside `_OBJECT_TYPE`), not to nodes.

`+0x10` is a QWORD: the lower DWORD (`00000003`) is `Operations`, the upper DWORD (`00000001`) is `Active`. The `lm a fffff80542ee2ea0` → WdFilter confirms Defender's handle-stripping callback.

## Step 4 — Identify and Disable

```
lm a fffff805`42ee2ea0
```

Identifies the driver that owns this callback (WdFilter). Then write `0` to the `Active` field at `node + 0x14`:

```
eb (ffffa180`7454c980 + 0x14) 0
```

The kernel checks `Active` before invoking `PreOperation`. Setting it to `0` disables the callback without removing the node — the list remains intact, no crash risk.

Walk to the next node by following `Flink` at `+0x000` of each node. Stop when `Flink` equals `type_addr + 0xC8` (the head address) — you have gone around the full list.

---

# Registry Callbacks — CmRegisterCallback

Registered via `CmRegisterCallbackEx`. These fire on every registry operation: `NtCreateKey`, `NtSetValueKey`, `NtQueryValueKey`, etc. The callback can return a non-success NTSTATUS to block the operation entirely.

EDRs use registry callbacks to protect their own keys (preventing deletion of Defender's registry configuration), monitor for persistence (run keys, services), and detect tamper attempts.

All registered callbacks live in a linked list rooted at `CallbackListHead`. Each node is a `_CMREG_CALLBACK`:

```
+0x000  Flink     — next node
+0x008  Blink     — previous node
+0x028  Function  — callback function address
```

**Important:** Unlike `CALLBACK_ENTRY_ITEM`, there is no `Active` field. The only way to disable a registry callback is to **unlink the node** from the list.

## Step 1 — Find the List Head

```
dq nt!CallbackListHead
```

Reads the `LIST_ENTRY` head. `Flink` is the first node. If `Flink == CallbackListHead address`, no callbacks are registered.

**Example output:**
```
fffff806`92cf7290  ffff8f88`086c8d50  ffff8f88`0bce8150
#                  ↑ Flink (first node)    ↑ Blink (last node)
```

Save both the head address (`fffff80692cf7290`) and the first node address.

## Step 2 — Read a Node

```
dq ffff8f88`086c8d50
```

**Example output:**
```
ffff8f88`086c8d50  ffff8f88`0bce3bf0  fffff806`92cf7290   ← Flink (next), Blink (prev=head)
ffff8f88`086c8d70  00000000`00000000  fffff806`2526aec0   ← +0x28 Function (save this)
```

## Step 3 — Identify the Driver

```
lm a fffff806`2526aec0
```

## Step 4 — Unlink the Node

![Cm callback node unlinking — before and after](/assets/images/callbacks-cm-unlink.svg)

To remove the node `ffff8f88086c8d50` (whose Blink is the head and Flink is `ffff8f880bce3bf0`):

```
eq (fffff806`92cf7290 + 0x00) ffff8f88`0bce3bf0   ← PREV.Flink = NEXT
eq (ffff8f88`0bce3bf0 + 0x08) fffff806`92cf7290   ← NEXT.Blink = PREV
```

`eq` writes a full 8-byte QWORD. After these two writes, the node is bypassed — anything walking the list will skip it entirely and the callback will never fire.

**Verify:**
```
dq nt!CallbackListHead
fffff806`92cf7290  ffff8f88`0bce3bf0  ffff8f88`0bce3bf0   ← head points to next node ✓
```

Walk the full list by following `Flink` at `+0x000` of each node. Stop when `Flink == CallbackListHead address`.

---

## Key Points

- **EX_FAST_REF** is used for Process, Thread, and Image callbacks — always strip the low nibble before dereferencing.
- **Array-based** (Ps* callbacks): zero the slot at `array_base + (slot_index × 8)`. The kernel skips null slots.
- **List-based** (ObRegisterCallbacks): set `Active` field to `0`. Disables the callback without structural changes.
- **List-based** (CmRegisterCallback): no `Active` field — must unlink the node with two `eq` writes.
- All writes require a full kernel debugging session. LiveKD is read-only.
- Offsets (`+0x6FA`, `+0x0C8`, `+0x28`, etc.) are build-specific for some structures — always verify with `dt` on your target build before hardcoding them into a tool.
