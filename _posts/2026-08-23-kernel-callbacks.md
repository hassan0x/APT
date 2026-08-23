---
title: "Kernel Callbacks — Enumeration and Removal"
date: 2026-08-23
categories: [Windows Internals, Kernel]
tags: [kernel, callbacks, windbg, windows]
---

# Process Notify Callbacks

Drivers register via `PsSetCreateProcessNotifyRoutineEx` to get notified on every process creation/exit. The kernel stores all registered callbacks in `PspCreateProcessNotifyRoutine` — a 64-slot array inside `ntoskrnl.exe`. Each slot is an `EX_FAST_REF` pointer with the low 4 bits used as refcount. Strip them to get the real `_EX_CALLBACK_ROUTINE_BLOCK` pointer, which holds the actual callback function at `+0x08`.

---

## Step 1 — Dump the Callback Array

```text
dp nt!PspCreateProcessNotifyRoutine
```text

Dumps all 64 slots. Non-zero = active callback. Zero = empty, skip.

**Example output:**
```text
fffff804`b0b04b80  ffffbf0f`e4dfb52f  ffffbf0f`e823bb5f
fffff804`b0b04b90  ffffbf0f`e823b82f  ffffbf0f`e823b8ef
fffff804`b0b04ba0  ffffbf0f`e823b64f  ffffbf0f`e84e888f
fffff804`b0b04bb0  00000000`00000000  00000000`00000000   ← empty, stop
```text

> Save the array base address (`fffff804b0b04b80`) for Step 4.

---

## Step 2 — Inspect a Slot

```text
dq (ffffbf0f`e823bb5f & 0xfffffffffffffff0)
```text

Strips the low nibble (refcount) to get the `_EX_CALLBACK_ROUTINE_BLOCK` pointer, then reads its fields. The callback function is at `+0x08`.

**Example output:**
```text
ffffbf0f`e823bb50  00000000`00000020   ← +0x00 RundownProtect (0x20 = active)
ffffbf0f`e823bb58  fffff804`42fdaa60   ← +0x08 Function ← save this
ffffbf0f`e823bb60  00000000`00000006   ← +0x10 Context
```text

---

## Step 3 — Identify the Driver

```text
lm a fffff804`42fdaa60
```text

`fffff80442fdaa60` = `Function` from Step 2. Resolves which driver owns this callback. Run `.reload /f` first if nothing shows.

**Example output:**
```text
start             end                 module name
fffff804`42f80000 fffff804`4301b000   WdFilter
```text

---

## Step 4 — Disable the Callback

```text
ep fffff804`b0b04b88 0
```text

`fffff804b0b04b80` (array base from Step 1) `+ 0x8` = slot index 1. Zeros that slot — the kernel skips null slots, so this callback never fires again.

**Verify:**
```text
dp nt!PspCreateProcessNotifyRoutine
fffff804`b0b04b80  ffffbf0f`e4dfb52f  00000000`00000000   ← Slot 1 zeroed ✓
fffff804`b0b04b90  ffffbf0f`e823b82f  ffffbf0f`e823b8ef
```text

---

**Automate:**
```text
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspCreateProcessNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```text

---

# Thread Notify Callbacks

Drivers register via `PsSetCreateThreadNotifyRoutineEx` to get notified on every thread creation/exit. Works identically to Process Notify Callbacks — same slot format, same `EX_FAST_REF` stripping, same zeroing method. Only the symbol name changes.

---

## Step 1 — Dump the Callback Array

```text
dp nt!PspCreateThreadNotifyRoutine
```text

Dumps all 64 slots. Non-zero = active callback. Zero = empty, skip.

**Example output:**
```text
fffff804`b0b03a20  ffffbf0f`e4dfb56f  ffffbf0f`e823bc1f
fffff804`b0b03a30  ffffbf0f`e84e891f  00000000`00000000   ← empty, stop
fffff804`b0b03a40  00000000`00000000  00000000`00000000
```text

> Save the array base address (`fffff804b0b03a20`) for Step 4.

---

## Step 2 — Inspect a Slot

```text
dq (ffffbf0f`e823bc1f & 0xfffffffffffffff0)
```text

Strips the low nibble (refcount) to get the `_EX_CALLBACK_ROUTINE_BLOCK` pointer. The callback function is at `+0x08`.

**Example output:**
```text
ffffbf0f`e823bc10  00000000`00000020   ← +0x00 RundownProtect (0x20 = active)
ffffbf0f`e823bc18  fffff804`42fdb130   ← +0x08 Function ← save this
ffffbf0f`e823bc20  00000000`00000000   ← +0x10 Context
```text

---

## Step 3 — Identify the Driver

```text
lm a fffff804`42fdb130
```text

`fffff80442fdb130` = `Function` from Step 2. Resolves the owning driver.

**Example output:**
```text
start             end                 module name
fffff804`42f80000 fffff804`4301b000   WdFilter
```text

---

## Step 4 — Disable the Callback

```text
ep fffff804`b0b03a28 0
```text

`fffff804b0b03a20` (array base from Step 1) `+ 0x8` = slot index 1. Zeros that slot — the kernel skips null slots, so this callback never fires again.

**Verify:**
```text
dp nt!PspCreateThreadNotifyRoutine
fffff804`b0b03a20  ffffbf0f`e4dfb56f  00000000`00000000   ← Slot 1 zeroed ✓
fffff804`b0b03a30  ffffbf0f`e84e891f  00000000`00000000
```text

---

**Automate:**
```text
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspCreateThreadNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```text

---

# Image Load Notify Callbacks

Drivers register via `PsSetLoadImageNotifyRoutineEx` to get notified whenever a DLL or executable is mapped into memory. Works identically to Process and Thread callbacks — same slot format, same stripping, same zeroing.

---

## Step 1 — Dump the Callback Array

```text
dp nt!PspLoadImageNotifyRoutine
```text

Dumps all 64 slots. Non-zero = active callback. Zero = empty, skip.

**Example output:**
```text
fffff804`b0b03c20  ffffbf0f`e4dfb5af  ffffbf0f`e823bcff
fffff804`b0b03c30  ffffbf0f`e84e896f  ffffbf0f`ea68db2f
fffff804`b0b03c40  00000000`00000000  00000000`00000000   ← empty, stop
```text

> Save the array base address (`fffff804b0b03c20`) for Step 4.

---

## Step 2 — Inspect a Slot

```text
dq (ffffbf0f`e823bcff & 0xfffffffffffffff0)
```text

Strips the low nibble (refcount) to get the `_EX_CALLBACK_ROUTINE_BLOCK` pointer. The callback function is at `+0x08`.

**Example output:**
```text
ffffbf0f`e823bcf0  00000000`00000020   ← +0x00 RundownProtect (0x20 = active)
ffffbf0f`e823bcf8  fffff804`42fdc880   ← +0x08 Function ← save this
ffffbf0f`e823bd00  00000000`00000000   ← +0x10 Context
```text

---

## Step 3 — Identify the Driver

```text
lm a fffff804`42fdc880
```text

`fffff80442fdc880` = `Function` from Step 2. Resolves the owning driver.

**Example output:**
```text
start             end                 module name
fffff804`42f80000 fffff804`4301b000   WdFilter
```text

---

## Step 4 — Disable the Callback

```text
ep fffff804`b0b03c28 0
```text

`fffff804b0b03c20` (array base from Step 1) `+ 0x8` = slot index 1. Zeros that slot — the kernel skips null slots, so this callback never fires again.

**Verify:**
```text
dp nt!PspLoadImageNotifyRoutine
fffff804`b0b03c20  ffffbf0f`e4dfb5af  00000000`00000000   ← Slot 1 zeroed ✓
fffff804`b0b03c30  ffffbf0f`e84e896f  ffffbf0f`ea68db2f
```text

---

**Automate:**
```text
.for (r $t0 = 0; @$t0 < 14; r $t0 = @$t0 + 1) { r $t1 = poi(nt!PspLoadImageNotifyRoutine + (@$t0 * 8)); .if (@$t1 != 0) { r $t2 = poi((@$t1 & 0xfffffffffffffff0) + 8); .printf "Slot %d: fn=%p\n", @$t0, @$t2; lm a @$t2 } }
```text

---

**Get RVA for a callback array:**
```text
? nt!PspCreateProcessNotifyRoutine - nt
? nt!PspCreateThreadNotifyRoutine  - nt
? nt!PspLoadImageNotifyRoutine     - nt
```text
nt = kernel base. Result = fixed RVA for this build. Survives reboots (KASLR only changes base, not layout).

---

# ObRegisterCallbacks

Drivers register via `ObRegisterCallbacks` to intercept handle operations (open/duplicate) on process or thread objects. The pre-operation callback receives the requested `ACCESS_MASK` and can strip rights — for example removing `PROCESS_VM_READ` from any handle opened to LSASS. Callbacks are stored per object type in a linked list called `CallbackList` inside `_OBJECT_TYPE`.

---

### Key Structures

**`ObTypeIndexTable`** — array of `_OBJECT_TYPE*` pointers, indexed by type:

| Index | Type |
|-------|------|
| 7 | Process |
| 8 | Thread |

**`_OBJECT_TYPE` offsets (Win10 18363 x64):**
```text
+0x010  Name             (UNICODE_STRING)
+0x028  Index            (BYTE)
+0x0C8  CallbackList     (LIST_ENTRY head)   ← start here
```text

**`CALLBACK_ENTRY_ITEM` offsets (64 bytes total):**
```text
+0x000  EntryItemList   (LIST_ENTRY: Flink/Blink to next/prev node)
+0x010  Operations      (DWORD)  1=handle create, 2=duplicate, 3=both
+0x014  Active          (DWORD)  1=enabled, 0=disabled  ← patch this
+0x018  CallbackEntry   (PVOID)
+0x020  ObjectType      (PVOID)
+0x028  PreOperation    (PVOID)  ← callback function address
+0x030  PostOperation   (PVOID)  ← callback function address (or NULL)
+0x038  unk             (QWORD)
```text
---

## Step 1 — Dump ObTypeIndexTable

```text
dp nt!ObTypeIndexTable
```text

Dumps the array of `_OBJECT_TYPE*` pointers indexed by object type. Each entry is the address of an `_OBJECT_TYPE` structure. We care about **index 8 = Process**.

**Example output:**
```text
fffff804`b0bc6800  00000000`00000000  ffffe400`d7db9000   ← [0], [1]
fffff804`b0bc6810  ffffbf0f`e4691d90  ffffbf0f`e4698090   ← [2], [3]
fffff804`b0bc6820  ffffbf0f`e46adea0  ffffbf0f`e4698b90   ← [4], [5]
fffff804`b0bc6830  ffffbf0f`e4689080  ffffbf0f`e469c650   ← [6], [7] Process ← save this
fffff804`b0bc6840  ffffbf0f`e468b450   ← [8] Thread ← save this
```text

**List all object types with names:**
```text
.for (r $t0 = 1; @$t0 < 50; r $t0 = @$t0 + 1) { r $t1 = poi(nt!ObTypeIndexTable + (@$t0 * 8)); .if (@$t1 != 0) { .printf "Index %d: %p  ", @$t0, @$t1; dt nt!_OBJECT_TYPE @$t1 Name } }
```text

---

## Step 2 — Dump the Process/Thread `_OBJECT_TYPE`

```text
dt nt!_OBJECT_TYPE ffffbf0f`e469c650 //Process
dt nt!_OBJECT_TYPE ffffbf0f`e468b450 //Thread
```text

`ffffbf0fe469c650` = index 7 pointer from Step 1. Look at `+0xC8 CallbackList` — if `Flink == Blink == head address` the list is empty and no Ob callbacks are registered. Otherwise `Flink` is the first `CALLBACK_ENTRY_ITEM` node — save it.

**Example output:**
```text
nt!_OBJECT_TYPE @ ffffbf0f`e469c650
   +0x010 Name         : _UNICODE_STRING "Process" OR "Thread"
   +0x028 Index        : 0x8
   +0x0c8 CallbackList :
      Flink : ffffd380`a234f8c0   ← first CALLBACK_ENTRY_ITEM node (save this)
      Blink : ffffd380`a25f5a30
```text

---

## Step 3 — Dump the Callback Entry

```text
dq ffffd380`a234f8c0 L7
```text

`ffffd380a234f8c0` = `CallbackList.Flink` from Step 2. Reads the raw `CALLBACK_ENTRY_ITEM` (64 bytes). Key fields by offset:
- `+0x10` = Operations — `3` means handle create + duplicate
- `+0x14` = Active — `1` enabled, `0` disabled
- `+0x28` = PreOperation — callback function address (save for Step 4)
- `+0x30` = PostOperation — or NULL

**Example output:**
```text
ffffd380`a234f8c0  ffffbf0f`e468b518  ffffd380`a25f5a30   ← +0x00 Flink, Blink
ffffd380`a234f8d0  00000001`00000003  ffffd380`a234f8a0   ← +0x10 Active=1, Operations=3
ffffd380`a234f8e0  ffffbf0f`e468b450  fffff804`42faf2b0   ← +0x20 ObjectType, +0x28 PreOperation ← save
ffffd380`a234f8f0  00000000`00000000  00000000`00000000   ← +0x30 PostOperation = NULL
```text

---

## Step 4 — Identify the Driver

```text
lm a fffff804`42faf2b0
```text

`fffff80442faf2b0` = `PreOperation` from Step 3. Resolves the owning driver.

**Example output:**
```text
start             end                 module name
fffff804`42f80000 fffff804`4301b000   WdFilter
```text

---

## Step 5 — Disable the Callback

```text
eb (ffffd380`a234f8c0 + 0x14) 0
```text

`ffffd380a234f8c0` = node address from Step 2. `+0x14` = `Active` field. Writing `0` disables the callback — the kernel checks this flag before invoking Pre/PostOperation.

**Verify:**
```text
dq ffffd380`a234f8c0
ffffd380`a234f8d0  00000000`00000003  ffffd380`a234f8a0   ← Active=0 ✓, Operations=3
```text

Walk `Flink` to the next node and repeat Steps 3–5 until `Flink` points back to the `CallbackList` head — that means you've reached the end of the list.

---

**RVA for ObTypeIndexTable (Win10 18363 x64)**:
```text
? nt!ObTypeIndexTable - nt   →   0x572D80
```text

---

# Registry Callbacks

Drivers register via `CmRegisterCallbackEx` to monitor or block registry operations (key create, set, query, etc.). The callback receives the operation type and can return a non-success NTSTATUS to block it. All registered callbacks are stored in a linked list called `CallbackListHead` — each node is a `_CMREG_CALLBACK` with the function pointer at `+0x28`.

Unlike ObRegisterCallbacks there is **no Active field** — to disable a callback you must unlink the node from the list entirely.

---

## Step 1 — Dump the Callback List Head

```text
dq nt!CallbackListHead
```text

Reads the `LIST_ENTRY` head. `Flink` points to the first `_CMREG_CALLBACK` node. If `Flink == CallbackListHead address` the list is empty.

**Example output:**
```text
fffff806`92cf7290  ffff8f88`086c8d50  ffff8f88`0bce8150
#                  ↑ Flink = first node (save this)
#                                      ↑ Blink = last node
```text

> Save head address (`fffff80692cf7290`) and first node (`ffff8f88086c8d50`) for Steps 2 and 4.

---

## Step 2 — Dump a Callback Node

```text
dq ffff8f88`086c8d50
```text

`ffff8f88086c8d50` = `Flink` from Step 1. Reads the `_CMREG_CALLBACK` node. Key fields:
- `+0x00` = Flink → next node (follow this to walk the list)
- `+0x08` = Blink → previous node
- `+0x28` = Function → callback address (save for Step 3)

**Example output:**
```text
ffff8f88`086c8d50  ffff8f88`0bce3bf0  fffff806`92cf7290   ← +0x00 Flink (next), Blink (prev=head)
ffff8f88`086c8d60  00000000`00000000  01dbfff1`719185b6   ← Unknown fields
ffff8f88`086c8d70  00000000`00000000  fffff806`2526aec0   ← +0x28 Function ← save this
```text

---

## Step 3 — Identify the Driver

```text
lm a fffff806`2526aec0
```text

`fffff8062526aec0` = `Function` from Step 2. Resolves the owning driver.

**Example output:**
```text
start             end                 module name
fffff806`25240000 fffff806`252db000   WdFilter
```text

---

## Step 4 — Disable by Unlinking the Node

No `Active` flag exists — the only way to disable is to remove the node from the linked list so nothing walking the list can reach it.

```text
# NODE to remove : ffff8f88`086c8d50
# PREV (Blink)   : fffff806`92cf7290  (the head in this case)
# NEXT (Flink)   : ffff8f88`0bce3bf0

eq (fffff806`92cf7290 + 0x00) ffff8f88`0bce3bf0   ← PREV.Flink = NEXT
eq (ffff8f88`0bce3bf0 + 0x08) fffff806`92cf7290   ← NEXT.Blink = PREV
```text

`eq` writes a full 8-byte QWORD. After this the node is orphaned — anything walking the list skips it entirely.

**Verify:**
```text
dq nt!CallbackListHead
fffff806`92cf7290  ffff8f88`0bce3bf0  ffff8f88`0bce3bf0   ← head now points directly to next node ✓
```text

---

## Notes
- Follow `Flink` at `+0x00` of each node to walk the full list. Stop when `Flink` equals the `CallbackListHead` address.
- `Function` offset may be `+0x30` or `+0x38` on other builds — verify with `dt nt!_CMREG_CALLBACK` on your target.
- `eq` requires full kernel debugging — LiveKD is read-only.
