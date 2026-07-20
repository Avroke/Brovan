using System;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtReadVirtualMemory : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
            ulong BaseAddress = Instance.WinHelper.GetArg64(1);
            ulong Buffer = Instance.WinHelper.GetArg64(2);
            ulong NumberOfBytesToRead = Instance.WinHelper.GetArg64(3);
            ulong NumberOfBytesReadPtr = Instance.WinHelper.GetArg64(4);

        current_process:
            if (Instance.WinHelper.IsCurrentProcessPseudoHandle(ProcessHandle))
            {
                if (NumberOfBytesToRead == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (BaseAddress == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (Instance.IsRegionFreed(BaseAddress, true))
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                if (!Instance.IsRegionMapped(BaseAddress, NumberOfBytesToRead))
                    return NTSTATUS.STATUS_MEMORY_NOT_ALLOCATED;

                if (Buffer == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (Instance.IsRegionFreed(Buffer, true))
                {
                    if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                        Instance.TriggerEventMessage($"[!!] Tried reading into a freed buffer at 0x{Buffer:X} while using NtReadVirtualMemory.", LogFlags.Issues);
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                }

                if (!Instance.IsRegionMapped(Buffer, NumberOfBytesToRead))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                byte[] value = Instance.ReadMemory(BaseAddress, (uint)NumberOfBytesToRead);
                if (value.Length == 0)
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (!Instance.WriteMemory(Buffer, value))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                if (NumberOfBytesReadPtr != 0 && Instance.IsRegionMapped(NumberOfBytesReadPtr, (uint)Instance.GuestPointerSize))
                    Instance.WritePointer(NumberOfBytesReadPtr, (ulong)value.Length);

                return NTSTATUS.STATUS_SUCCESS;
            }

            if (!Instance.WinHelper.HandleExists(ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessVMOperation | AccessMask.ProcessVMRead);
            if (Process == null)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            if (Process.PID == Instance.WinHelper.PID)
            {
                ProcessHandle = Instance.GuestPointerSize == 8 ? ulong.MaxValue : 0xFFFFFFFFUL;
                goto current_process;
            }

            if (BaseAddress == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (Buffer == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (NumberOfBytesToRead == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.WriteMemory(Buffer, Instance.WinHelper.GenerateRandomData((int)NumberOfBytesToRead)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            if (NumberOfBytesReadPtr != 0 && Instance.IsRegionMapped(NumberOfBytesReadPtr, (uint)Instance.GuestPointerSize))
                Instance.WritePointer(NumberOfBytesReadPtr, NumberOfBytesToRead);

            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                Instance.TriggerEventMessage($"[+] The emulated process tried to read the memory of process \"{Process.Name}\", random data was generated for it.", LogFlags.Syscall);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
