using System.Collections.Generic;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    /// <summary>
    /// NtGetWriteWatch (SSN 0xFB on 19041/19044). Backs kernel32/kernelbase's
    /// <c>GetWriteWatch</c>. Returns the set of pages that have been written since the
    /// MEM_WRITE_WATCH region was allocated (or since the last reset), in ascending order.
    ///
    /// <code>
    /// NTSTATUS NtGetWriteWatch(
    ///   HANDLE ProcessHandle,        // arg0
    ///   ULONG  Flags,                // arg1  (WRITE_WATCH_FLAG_RESET = 1)
    ///   PVOID  BaseAddress,          // arg2
    ///   SIZE_T RegionSize,           // arg3
    ///   PVOID *UserAddressArray,     // arg4  (OUT: page addresses)
    ///   PULONG_PTR EntriesInArray,   // arg5  (IN: capacity, OUT: count written)
    ///   PULONG Granularity)          // arg6  (OUT: page size)
    /// </code>
    ///
    /// Only guest STORE instructions dirty a page (host-side stub writes bypass Unicorn's
    /// write hook), so a probe that hands the buffer to a failing API and expects a zero
    /// hit-count gets it, while a real <c>buffer[0]=x</c> store yields exactly one page —
    /// which is what al-khaser's four write-watch anti-debug checks verify.
    /// </summary>
    internal class NtGetWriteWatch : IWinSyscall
    {
        private const ulong PageSize = 0x1000;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong Flags = Instance.WinHelper.GetArg64(1);
            ulong BaseAddress = Instance.WinHelper.GetArg64(2);
            ulong RegionSize = Instance.WinHelper.GetArg64(3);
            ulong UserAddressArray = Instance.WinHelper.GetArg64(4);
            ulong EntriesInArrayPtr = Instance.WinHelper.GetArg64(5);
            ulong GranularityPtr = Instance.WinHelper.GetArg64(6);

            if (ProcessHandle != ulong.MaxValue)
            {
                if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                    return NTSTATUS.STATUS_INVALID_HANDLE;

                WinProcess Proc = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMOperation);
                if (Proc == null || Proc.PID != Instance.WinHelper.PID)
                    return NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (BaseAddress == 0 || RegionSize == 0 || UserAddressArray == 0 || EntriesInArrayPtr == 0 || GranularityPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(EntriesInArrayPtr, 8) || !Instance.IsRegionMapped(GranularityPtr, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong Capacity = Instance.ReadMemoryULong(EntriesInArrayPtr);

            bool Reset = (Flags & WriteWatchManager.WriteWatchFlagReset) != 0;

            // Validate range membership BEFORE any reset side-effect.
            if (Instance.WriteWatch == null ||
                !Instance.WriteWatch.TryGetWrites(BaseAddress, RegionSize, Capacity, Reset, out List<ulong> Pages))
            {
                // The range was not allocated with MEM_WRITE_WATCH — real Windows rejects it.
                return NTSTATUS.STATUS_INVALID_PARAMETER;
            }

            if (Pages.Count > 0 && !Instance.IsRegionMapped(UserAddressArray, (ulong)Pages.Count * 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            for (int i = 0; i < Pages.Count; i++)
            {
                if (!Instance._emulator.WriteMemory(UserAddressArray + (ulong)i * 8, Pages[i], 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
            }

            if (!Instance._emulator.WriteMemory(EntriesInArrayPtr, (ulong)Pages.Count, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (!Instance._emulator.WriteMemory(GranularityPtr, (uint)PageSize, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
