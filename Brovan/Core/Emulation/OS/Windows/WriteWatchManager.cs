using System;
using System.Collections.Generic;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// Tracks guest writes to memory regions allocated with <c>MEM_WRITE_WATCH</c> so that
    /// <c>NtGetWriteWatch</c> / <c>NtResetWriteWatch</c> (and thus kernel32's
    /// <c>GetWriteWatch</c> / <c>ResetWriteWatch</c>) report the correct set of dirtied pages.
    ///
    /// Opt-in by construction: a region is registered only when the guest asks for
    /// <c>MEM_WRITE_WATCH</c>, and its Unicorn write hook is <b>ranged</b> to that region, so a
    /// program that never uses the feature pays zero cost (the backend filters the hook range
    /// before any managed callback runs). Only actual guest STORE instructions dirty a page —
    /// host-side stub writes go through <c>uc_mem_write</c>, which does not trigger memory hooks,
    /// matching real Windows where a failed API that never wrote the OUT buffer records no dirty
    /// page (al-khaser's write-watch "API calls" probe relies on exactly this).
    ///
    /// Single-threaded: the write hook and the syscall handlers all run on the emulation thread,
    /// so no locking is needed.
    /// </summary>
    public sealed class WriteWatchManager
    {
        private const ulong PageSize = 0x1000;
        private const ulong PageMask = PageSize - 1;

        /// <summary>WRITE_WATCH_FLAG_RESET — when passed to NtGetWriteWatch, reset the returned pages.</summary>
        public const ulong WriteWatchFlagReset = 0x01;

        private sealed class Watched
        {
            public ulong Base;                 // page-aligned start
            public ulong End;                  // page-aligned end (exclusive)
            public IntPtr Hook;                // ranged write hook handle
            public MemoryHookCallback Callback; // kept alive for the hook's lifetime
            public readonly SortedSet<ulong> Dirty = new SortedSet<ulong>();
        }

        private readonly BinaryEmulator _emu;
        private readonly List<Watched> _regions = new List<Watched>();

        public WriteWatchManager(BinaryEmulator emulator)
        {
            _emu = emulator;
        }

        /// <summary>Register a region allocated with MEM_WRITE_WATCH and install its ranged write hook.</summary>
        public void Register(ulong baseAddress, ulong size)
        {
            if (size == 0)
                return;

            ulong start = baseAddress & ~PageMask;
            ulong end = (baseAddress + size + PageMask) & ~PageMask;
            if (end <= start)
                return;

            // Re-registration of the same base (e.g. a MEM_COMMIT over an existing MEM_RESERVE
            // write-watch region) is a no-op — the existing hook + dirty set stay live.
            if (FindByBase(start) != null)
                return;

            Watched w = new Watched { Base = start, End = end };
            w.Callback = (type, address, sz, val) =>
            {
                if (address >= w.Base && address < w.End)
                    w.Dirty.Add(address & ~PageMask);
                return true;
            };

            // Ranged hook over [start, end-1] inclusive: near-zero cost when writes miss the range.
            w.Hook = _emu._emulator.AddMemoryHook(start, end - 1, BackendHookType.MemoryWrite, w.Callback);

            // If the write hook could not be installed (e.g. NoHooks diagnostic mode, where
            // UC_HOOK_MEM_WRITE is not whitelisted), do NOT register the region: a live region
            // with no hook would never dirty a page, so GetWriteWatch would falsely report zero
            // writes after a genuine store — a detectable tell. Leaving it unregistered makes a
            // later query return STATUS_INVALID_PARAMETER instead (an honest "not tracked").
            if (w.Hook == IntPtr.Zero)
                return;

            _regions.Add(w);
        }

        /// <summary>Remove a write-watch region (on MEM_RELEASE) and delete its hook.</summary>
        public void Unregister(ulong baseAddress)
        {
            ulong start = baseAddress & ~PageMask;
            for (int i = _regions.Count - 1; i >= 0; i--)
            {
                if (_regions[i].Base != start)
                    continue;

                if (_regions[i].Hook != IntPtr.Zero)
                    _emu._emulator.RemoveHook(_regions[i].Hook);
                _regions.RemoveAt(i);
            }
        }

        /// <summary>
        /// Collect the dirtied page addresses inside [baseAddress, baseAddress+size), ascending,
        /// up to <paramref name="maxEntries"/>. Returns false when the range is not a write-watch
        /// region (the caller maps that to STATUS_INVALID_PARAMETER, as real Windows does). When
        /// <paramref name="reset"/> is set, the returned pages are cleared from the dirty set.
        /// </summary>
        public bool TryGetWrites(ulong baseAddress, ulong size, ulong maxEntries, bool reset, out List<ulong> pages)
        {
            pages = null;
            Watched w = FindContaining(baseAddress);
            if (w == null)
                return false;

            ulong qStart = baseAddress & ~PageMask;
            // Guard the range end against address-space wrap (baseAddress + size overflow),
            // which would otherwise make the [qStart, qEnd) filter match nothing.
            ulong qEnd = baseAddress > ulong.MaxValue - size ? ulong.MaxValue : baseAddress + size;
            pages = new List<ulong>();

            foreach (ulong page in w.Dirty)
            {
                if (page < qStart || page >= qEnd)
                    continue;
                if ((ulong)pages.Count >= maxEntries)
                    break;
                pages.Add(page);
            }

            // WRITE_WATCH_FLAG_RESET resets ONLY the pages actually returned (MSDN), so a
            // subsequent GetWriteWatch with an ample buffer still retrieves any pages that were
            // truncated by maxEntries this call.
            if (reset)
            {
                foreach (ulong page in pages)
                    w.Dirty.Remove(page);
            }

            return true;
        }

        /// <summary>Clear the dirty set inside [baseAddress, baseAddress+size). Returns false when not a write-watch region.</summary>
        public bool Reset(ulong baseAddress, ulong size)
        {
            Watched w = FindContaining(baseAddress);
            if (w == null)
                return false;

            ulong qStart = baseAddress & ~PageMask;
            ulong qEnd = baseAddress > ulong.MaxValue - size ? ulong.MaxValue : baseAddress + size;
            List<ulong> toRemove = new List<ulong>();
            foreach (ulong page in w.Dirty)
            {
                if (page >= qStart && page < qEnd)
                    toRemove.Add(page);
            }

            foreach (ulong page in toRemove)
                w.Dirty.Remove(page);

            return true;
        }

        private Watched FindByBase(ulong start)
        {
            foreach (Watched w in _regions)
            {
                if (w.Base == start)
                    return w;
            }
            return null;
        }

        private Watched FindContaining(ulong address)
        {
            foreach (Watched w in _regions)
            {
                if (address >= w.Base && address < w.End)
                    return w;
            }
            return null;
        }
    }
}
