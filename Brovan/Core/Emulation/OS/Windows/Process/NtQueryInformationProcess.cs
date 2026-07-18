using System.IO;
using System.Runtime.CompilerServices;
using System.Text;
using System.Buffers.Binary;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtQueryInformationProcess : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong ProcessHandle = Instance.WinHelper.GetArg64(0);
                PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.WinHelper.GetArg64(1);
                ulong OutBufferPtr = Instance.WinHelper.GetArg64(2);
                uint OutBufferLength = (uint)Instance.WinHelper.GetArg64(3);
                ulong ReturnLengthPtr = Instance.WinHelper.GetArg64(4);
                void SetReturnLength(uint Len)
                {
                    if (ReturnLengthPtr == 0)
                        return;
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return;
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Len);
                }
                bool CurrentProcess = ProcessHandle == ulong.MaxValue;
                switch (InfoClass)
                {
                    case PROCESSINFOCLASS.ProcessBasicInformation:
                        if (OutBufferLength < 48)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 48);
                            WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                            WriteUInt64(PBIBuffer, 8, Instance.PEB);
                            WriteUInt64(PBIBuffer, 16, (ulong)Environment.ProcessorCount);
                            WriteUInt64(PBIBuffer, 24, (ulong)Instance.WinHelper.CurrentPriority);
                            WriteUInt64(PBIBuffer, 32, Instance.WinHelper.PID);
                            WriteUInt64(PBIBuffer, 40, Instance.WinHelper.PPID);

                            if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            SetReturnLength(48);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own PROCESS_BASIC_INFORMATION (PEB = 0x{Instance.PEB:X}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation | AccessMask.ProcessQueryLimitedInformation);

                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }

                                Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 48);
                                WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                                WriteUInt64(PBIBuffer, 8, Instance.PEB);
                                WriteUInt64(PBIBuffer, 16, (ulong)Environment.ProcessorCount);
                                WriteUInt64(PBIBuffer, 24, 0x8UL);
                                WriteUInt64(PBIBuffer, 32, Process.PID);
                                WriteUInt64(PBIBuffer, 40, Process.PPID);

                                if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength(48);
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried PROCESS_BASIC_INFORMATION of process \"{Process.Name}\" (PID={Process.PID}).", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                    case PROCESSINFOCLASS.ProcessTimes:
                        {
                            NTSTATUS Status = QueryProcessTimes(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                            if (Status == NTSTATUS.STATUS_SUCCESS)
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessTimes.", LogFlags.Syscall);
                            return Status;
                        }
                    case PROCESSINFOCLASS.ProcessBreakOnTermination:
                        if (OutBufferLength < 1)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteByte(OutBufferPtr, 0))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength(1);
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own ProcessBreakOnTermination.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteByte(OutBufferPtr, Process.Critical ? (byte)1 : (byte)0))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength(1);
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessBreakOnTermination for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessDebugPort:
                        if (OutBufferLength >= 8)
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried own debug port.", LogFlags.Syscall);
                                SetReturnLength(8);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength(8);
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried debug port for process \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                        else
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                    case PROCESSINFOCLASS.ProcessDebugObjectHandle:
                        if (CurrentProcess)
                        {
                            if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried own debug object handle.", LogFlags.Syscall);
                            SetReturnLength(8);
                            return NTSTATUS.STATUS_PORT_NOT_SET;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation);
                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }

                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                SetReturnLength(8);
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[!] NtQueryInformationProcess: Queried debug object handle for process \"{Process.Name}\".", LogFlags.Syscall);
                                return NTSTATUS.STATUS_PORT_NOT_SET;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                        break;
                    case PROCESSINFOCLASS.ProcessWow64Information:
                        if (OutBufferLength < 8)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance._emulator.WriteMemory(OutBufferPtr, (ulong)(Instance._binary.Architecture == BinaryArchitecture.x64 ? 0 : 1), 8))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own Wow64 status.", LogFlags.Syscall);
                                SetReturnLength(8);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance._emulator.WriteMemory(OutBufferPtr, Process.Arch == BinaryArchitecture.x64 ? 0u : 1u, 4))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    SetReturnLength(8);
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried Wow64 status of process \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessImageFileName:
                        if (OutBufferLength < 16)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            // NT device form of the guest image path (\Device\HarddiskVolume1\...),
                            // NOT the raw host location. WinModules[0] is the main image (same
                            // convention ProcessImageFileNameWin32 uses); its Path is the synthetic
                            // guest DOS path. A sample that normalises this against QueryDosDevice
                            // ("C:") -> \Device\HarddiskVolume1 (e.g. al-khaser's injected-DLL check)
                            // needs both to agree, so we route through DosPathToNtDevicePath.
                            string GuestDos = Instance.WinHelper.WinModules.Count > 0 && !string.IsNullOrEmpty(Instance.WinHelper.WinModules[0].Path)
                                ? Instance.WinHelper.WinModules[0].Path
                                : Instance._binary.Location;
                            string Path = Instance.WinHelper.DosPathToNtDevicePath(GuestDos);
                            int PathByteCount = Encoding.Unicode.GetByteCount(Path);
                            Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
                            Encoding.Unicode.GetBytes(Path.AsSpan(), PathBytes);
                            ulong AllocatedImageMem = Instance.MapUniqueAddress((uint)PathByteCount, MemoryProtection.ReadWrite);
                            if (AllocatedImageMem == 0)
                                return NTSTATUS.STATUS_NO_MEMORY;
                            if (!Instance.WriteMemory(AllocatedImageMem, PathBytes.Slice(0, PathByteCount)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            UNICODE_STRING64 Unicode = new UNICODE_STRING64
                            {
                                Length = (ushort)PathByteCount,
                                MaximumLength = (ushort)PathByteCount,
                                Buffer = AllocatedImageMem
                            };

                            if (StructSerializer.WriteStruct(Instance, OutBufferPtr, Unicode) != WriteStructResult.Ok)
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(16);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried own ProcessImageFileName = \"{Path}\".", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }
                                string Path = Instance.WinHelper.DosPathToNtDevicePath(Process.Path);
                                int PathByteCount = Encoding.Unicode.GetByteCount(Path);
                                Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
                                Encoding.Unicode.GetBytes(Path.AsSpan(), PathBytes);
                                ulong AllocatedImageMem = Instance.MapUniqueAddress((uint)PathByteCount, MemoryProtection.ReadWrite);

                                if (AllocatedImageMem == 0)
                                    return NTSTATUS.STATUS_NO_MEMORY;

                                if (!Instance.WriteMemory(AllocatedImageMem, PathBytes.Slice(0, PathByteCount)))
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                UNICODE_STRING64 Unicode = new UNICODE_STRING64
                                {
                                    Length = (ushort)PathByteCount,
                                    MaximumLength = (ushort)PathByteCount,
                                    Buffer = AllocatedImageMem
                                };

                                if (StructSerializer.WriteStruct(Instance, OutBufferPtr, Unicode) != WriteStructResult.Ok)
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                                SetReturnLength(16);
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried the process \"{Process.Name}\" ProcessImageFileName = \"{Path}\".", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                        }
                        break;
                    case PROCESSINFOCLASS.ProcessCookie:
                        {
                            if (OutBufferLength < 4)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (Instance.ProcessCookie == 0)
                            {
                                // Deterministic per emulation: the process cookie feeds the guest CRT's
                                // stack-cookie derivation, so a host-random value perturbs every downstream
                                // GS canary run-over-run. Route through the emulator's seeded RNG.
                                Instance.ProcessCookie = (uint)Instance.SeededRandom.Next(1, int.MaxValue);
                            }

                            if (!Instance._emulator.WriteMemory(OutBufferPtr, Instance.ProcessCookie, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(4);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessCookie = 0x{Instance.ProcessCookie:X}.", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessImageInformation:
                        {
                            uint StructSize = 0x40;

                            if (OutBufferLength < StructSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            ulong EntryPoint = Instance.WinHelper.WinModules[0].MappedBase + (ulong)Instance._binary.PE.OptionalHeader64.AddressOfEntryPoint;

                            ulong TransferAddress = EntryPoint;
                            uint ZeroBits = 0;

                            ulong MaximumStackSize = Instance.StackSize;
                            ulong CommittedStackSize = Instance.StackSize;

                            uint SubSystemType = (uint)Instance._binary.PE.OptionalHeader64.Subsystem;

                            uint SubSystemVersion = ((uint)Instance._binary.PE.OptionalHeader64.MinorSubsystemVersion << 16) |
                                                    (uint)Instance._binary.PE.OptionalHeader64.MajorSubsystemVersion;

                            uint GpValue = 0;

                            ushort ImageCharacteristics = (ushort)Instance._binary.PE.FileHeader.Characteristics;
                            ushort DllCharacteristics = (ushort)Instance._binary.PE.OptionalHeader64.DllCharacteristics;

                            ushort Machine = (ushort)Instance._binary.PE.FileHeader.Machine;

                            byte ImageContainsCode = 1;
                            byte ImageFlags = 0;

                            uint LoaderFlags = 0;
                            uint ImageFileSize = 0;
                            uint CheckSum = 0;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);

                            WriteUInt64(Buffer, 0x00, TransferAddress);
                            WriteUInt64(Buffer, 0x08, ZeroBits);
                            WriteUInt64(Buffer, 0x10, MaximumStackSize);
                            WriteUInt64(Buffer, 0x18, CommittedStackSize);
                            WriteUInt32(Buffer, 0x20, SubSystemType);
                            WriteUInt32(Buffer, 0x24, SubSystemVersion);
                            WriteUInt32(Buffer, 0x28, GpValue);
                            WriteUInt16(Buffer, 0x2C, ImageCharacteristics);
                            WriteUInt16(Buffer, 0x2E, DllCharacteristics);
                            WriteUInt16(Buffer, 0x30, Machine);
                            Buffer[0x32] = ImageContainsCode;
                            Buffer[0x33] = ImageFlags;
                            WriteUInt32(Buffer, 0x34, LoaderFlags);
                            WriteUInt32(Buffer, 0x38, ImageFileSize);
                            WriteUInt32(Buffer, 0x3C, CheckSum);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(0x40);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: Queried ProcessImageInformation (TransferAddress=0x{TransferAddress:X}).", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessImageFileNameWin32:
                        return QueryProcessImageFileNameWin32(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                    case PROCESSINFOCLASS.ProcessDefaultHardErrorMode:
                        {
                            // Default hard-error mode: the process-wide SEM_* flags controlling
                            // whether critical errors pop a system-error dialog. Real Windows
                            // reports 0 for a normal process (SEM_FAILCRITICALERRORS not set,
                            // default critical-error handling). Called by ntdll's process-init
                            // code path; returning SUCCESS+0 matches, silences the init noise.
                            if (OutBufferLength < 4)
                            {
                                SetReturnLength(4);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }
                            if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            if (!Instance._emulator.WriteMemory(OutBufferPtr, 0u, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(4);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDebugFlags:
                        {
                            // NoDebugInherit flag (DWORD): 1 = normal (no debugger), 0 = debugger
                            // is attached with inherit-debug. Al-khaser's ProcessDebugFlags probe
                            // treats (STATUS_SUCCESS && buffer==0) as detected — so returning
                            // SUCCESS+1 is both the honest "no debugger" answer and the value
                            // al-khaser expects to see GOOD. The old NOT_SUPPORTED response
                            // worked only by accident (probe treated a failed call as GOOD too).
                            if (OutBufferLength < 4)
                            {
                                SetReturnLength(4);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            if (!Instance._emulator.WriteMemory(OutBufferPtr, 1u, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(4);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case (PROCESSINFOCLASS)52:
                        {
                            uint StructSize = 0x20;

                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint Policy = (uint)(Instance.ReadMemoryULong(OutBufferPtr) & 0xFFFFFFFF);

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            WriteUInt32(Buffer, 0, Policy);

                            uint UnionFlags = 0;
                            uint UnionExtra = 0;

                            if (Policy == 0)
                            {
                                UnionFlags = 1;
                                UnionExtra = 0;
                            }
                            else if (Policy == 2)
                            {
                                UnionFlags = 0;
                                UnionExtra = 0;
                            }

                            WriteUInt32(Buffer, 4, UnionFlags);
                            WriteUInt32(Buffer, 8, UnionExtra);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(StructSize);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess: ProcessMitigationPolicy ({Policy})", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    default:
                        Helpers.Utils.PrintHighlight($"[!] NtQueryInformationProcess: InfoClass 0x{InfoClass:X} is not implemented");
                        return Instance.WinUnimplemented;
                }
                Helpers.Utils.PrintHighlight($"[!] NtQueryInformationProcess: InfoClass 0x{InfoClass:X} is not implemented");
                return Instance.WinUnimplemented;
            }
            else
            {
                uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
                uint ProcessHandle = Instance.ReadMemoryUInt(ESP + 4);
                PROCESSINFOCLASS InfoClass = (PROCESSINFOCLASS)Instance.ReadMemoryUInt(ESP + 8);
                uint OutBufferPtr = Instance.ReadMemoryUInt(ESP + 12);
                uint OutBufferLength = Instance.ReadMemoryUInt(ESP + 16);
                uint ReturnLengthPtr = Instance.ReadMemoryUInt(ESP + 20);
                void SetReturnLength(uint Len)
                {
                    if (ReturnLengthPtr == 0)
                        return;
                    if (!Instance.IsRegionMapped(ReturnLengthPtr, 4))
                        return;
                    Instance._emulator.WriteMemory(ReturnLengthPtr, Len);
                }
                bool CurrentProcess = ProcessHandle == uint.MaxValue;
                switch (InfoClass)
                {
                    case PROCESSINFOCLASS.ProcessBasicInformation:
                        if (OutBufferLength < 24)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }

                        if (CurrentProcess)
                        {
                            Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 24);
                            WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                            WriteUInt32(PBIBuffer, 4, (uint)Instance.PEB);
                            WriteUInt32(PBIBuffer, 8, (uint)Environment.ProcessorCount);
                            WriteUInt32(PBIBuffer, 12, Instance.WinHelper.CurrentPriority);
                            WriteUInt32(PBIBuffer, 16, Instance.WinHelper.PID);
                            WriteUInt32(PBIBuffer, 20, Instance.WinHelper.PPID);

                            if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                            {
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            }
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried own PROCESS_BASIC_INFORMATION.", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                        else
                        {
                            if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                            {
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryInformation | AccessMask.ProcessQueryLimitedInformation);

                                if (Process == null)
                                {
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                }

                                Span<byte> PBIBuffer = GetSharedWriteBuffer(Instance, 24);
                                WriteUInt32(PBIBuffer, 0, (uint)NTSTATUS.STATUS_PENDING);
                                WriteUInt32(PBIBuffer, 4, (uint)Instance.PEB);
                                WriteUInt32(PBIBuffer, 8, (uint)Environment.ProcessorCount);
                                WriteUInt32(PBIBuffer, 12, 0x8u);
                                WriteUInt32(PBIBuffer, 16, Process.PID);
                                WriteUInt32(PBIBuffer, 20, Process.PPID);

                                if (!Instance.WriteMemory(OutBufferPtr, PBIBuffer))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried PROCESS_BASIC_INFORMATION of process \"{Process.Name}\".", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            }
                        }
                    case PROCESSINFOCLASS.ProcessTimes:
                        {
                            NTSTATUS Status = QueryProcessTimes(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);
                            if (Status == NTSTATUS.STATUS_SUCCESS)
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried ProcessTimes.", LogFlags.Syscall);
                            return Status;
                        }
                    case PROCESSINFOCLASS.ProcessBreakOnTermination:
                        if (OutBufferLength < 1)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteByte(OutBufferPtr, 0))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried own ProcessBreakOnTermination.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteByte(OutBufferPtr, Process.Critical ? (byte)1 : (byte)0))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried ProcessBreakOnTermination for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessDebugPort:
                        if (OutBufferLength >= 4)
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 4))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[!] NtQueryInformationProcess (x86): Queried own debug port.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 8))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[!] NtQueryInformationProcess (x86): Queried debug port of \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                        else
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                    case PROCESSINFOCLASS.ProcessDebugObjectHandle:
                        // WOW64: the debug-object HANDLE is pointer-sized (4 bytes on x86). A process that is
                        // not being debugged has no debug object, so ntdll writes a NULL handle and returns
                        // STATUS_PORT_NOT_SET (mirrors the x64 branch above). al-khaser's ProcessDebugObjectHandle
                        // probe reads (SUCCESS && handle!=0) as "debugger present"; more importantly
                        // kernel32!UnhandledExceptionFilter queries this class to decide whether a debugger is
                        // attached — leaving it unimplemented made UEF believe a debugger was present, skip the
                        // SetUnhandledExceptionFilter-registered filter, and let the UnhandledExcepFilterTest
                        // exception go unhandled → process terminated with STATUS_FLOAT_DIVIDE_BY_ZERO.
                        if (OutBufferLength < 4)
                        {
                            SetReturnLength(4);
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        if (!CurrentProcess)
                        {
                            if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                return NTSTATUS.STATUS_INVALID_HANDLE;
                            if (Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation) == null)
                                return NTSTATUS.STATUS_ACCESS_DENIED;
                        }
                        if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        SetReturnLength(4);
                        if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                            Instance.TriggerEventMessage($"[!] NtQueryInformationProcess (x86): Queried debug object handle.", LogFlags.Syscall);
                        return NTSTATUS.STATUS_PORT_NOT_SET;
                    case PROCESSINFOCLASS.ProcessDebugFlags:
                        // NoDebugInherit flag (DWORD): 1 = normal (no debugger), 0 = debugger with inherit set.
                        // al-khaser treats (SUCCESS && value==0) as detected, so SUCCESS+1 is the honest answer
                        // and matches the x64 branch.
                        if (OutBufferLength < 4)
                        {
                            SetReturnLength(4);
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        if (!Instance._emulator.WriteMemory(OutBufferPtr, 1u, 4))
                            return NTSTATUS.STATUS_ACCESS_VIOLATION;
                        SetReturnLength(4);
                        return NTSTATUS.STATUS_SUCCESS;
                    case PROCESSINFOCLASS.ProcessWow64Information:
                        if (OutBufferLength < 4)
                        {
                            return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                        }
                        else
                        {
                            if (CurrentProcess)
                            {
                                if (!Instance._emulator.WriteMemory(OutBufferPtr, Instance._binary.Architecture == BinaryArchitecture.x64 ? 0u : 1u, 4))
                                {
                                    return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                }
                                if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                    Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried own Wow64 info.", LogFlags.Syscall);
                                return NTSTATUS.STATUS_SUCCESS;
                            }
                            else
                            {
                                if (Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                {
                                    WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                    if (Process == null)
                                    {
                                        return NTSTATUS.STATUS_ACCESS_DENIED;
                                    }

                                    if (!Instance._emulator.WriteMemory(OutBufferPtr, Process.Arch == BinaryArchitecture.x64 ? 0u : 1u, 4))
                                    {
                                        return NTSTATUS.STATUS_ACCESS_VIOLATION;
                                    }
                                    if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                        Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): Queried Wow64 info for \"{Process.Name}\".", LogFlags.Syscall);
                                    return NTSTATUS.STATUS_SUCCESS;
                                }
                                else
                                {
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                }
                            }
                        }
                    case PROCESSINFOCLASS.ProcessCookie:
                        {
                            // 4-byte DWORD on both bitnesses. The loader queries it early to seed
                            // RtlEncodePointer; without it LdrpInitialize fails and raises a hard error.
                            if (OutBufferLength < 4)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            if (!Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            if (Instance.ProcessCookie == 0)
                                Instance.ProcessCookie = (uint)Instance.SeededRandom.Next(1, int.MaxValue);
                            if (!Instance._emulator.WriteMemory(OutBufferPtr, Instance.ProcessCookie, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(4);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessDefaultHardErrorMode:
                        {
                            // ULONG on both bitnesses. Default hard-error mode = 1 (SEM enabled).
                            if (OutBufferLength < 4)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            if (!Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            if (!Instance._emulator.WriteMemory(OutBufferPtr, 1u, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(4);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessExecuteFlags:
                        {
                            // ULONG MEM_EXECUTE_OPTION flags. The loader (LdrpInitializeExecutionOptions)
                            // queries this to decide NX policy. 0 = no special flags (DEP default), which keeps
                            // the loader on its normal path.
                            if (OutBufferLength < 4)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            if (!Instance.IsRegionMapped(OutBufferPtr, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            if (!Instance._emulator.WriteMemory(OutBufferPtr, 0u, 4))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(4);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case PROCESSINFOCLASS.ProcessImageInformation:
                        {
                            // x86 SECTION_IMAGE_INFORMATION — 0x30 bytes (the three pointer fields
                            // TransferAddress / MaximumStackSize / CommittedStackSize are 4 wide). The loader
                            // queries it to validate the main image; a failure here NULL-derefs LdrpInitialize.
                            const uint StructSize = 0x30;
                            if (OutBufferLength < StructSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            var Pe = Instance._binary.PE;
                            uint TransferAddress = (uint)(Instance.WinHelper.WinModules[0].MappedBase + Instance._binary.EntryPoint);
                            uint SubSystemVersion = ((uint)Pe.OptionalHeader32.MinorSubsystemVersion << 16) | (uint)Pe.OptionalHeader32.MajorSubsystemVersion;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            WriteUInt32(Buffer, 0x00, TransferAddress);                 // TransferAddress
                            WriteUInt32(Buffer, 0x04, 0u);                              // ZeroBits
                            WriteUInt32(Buffer, 0x08, (uint)Instance.StackSize);        // MaximumStackSize
                            WriteUInt32(Buffer, 0x0C, (uint)Instance.StackSize);        // CommittedStackSize
                            WriteUInt32(Buffer, 0x10, (uint)Pe.OptionalHeader32.Subsystem); // SubSystemType
                            WriteUInt32(Buffer, 0x14, SubSystemVersion);                // SubSystemVersion
                            WriteUInt32(Buffer, 0x18, 0u);                              // GpValue
                            WriteUInt16(Buffer, 0x1C, (ushort)Pe.FileHeader.Characteristics);        // ImageCharacteristics
                            WriteUInt16(Buffer, 0x1E, (ushort)Pe.OptionalHeader32.DllCharacteristics); // DllCharacteristics
                            WriteUInt16(Buffer, 0x20, (ushort)Pe.FileHeader.Machine);   // Machine
                            Buffer[0x22] = 1;                                           // ImageContainsCode
                            Buffer[0x23] = 0;                                           // ImageFlags
                            WriteUInt32(Buffer, 0x24, 0u);                              // LoaderFlags
                            WriteUInt32(Buffer, 0x28, 0u);                              // ImageFileSize
                            WriteUInt32(Buffer, 0x2C, 0u);                              // CheckSum

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(StructSize);
                            return NTSTATUS.STATUS_SUCCESS;
                        }
                    case (PROCESSINFOCLASS)52:
                        {
                            // ProcessMitigationPolicy — PROCESS_MITIGATION_POLICY_INFORMATION is
                            // { PROCESS_MITIGATION_POLICY Policy; <policy union> }, 8 bytes on x86 (the WOW64
                            // loader / GetProcessMitigationPolicy pass len=0x8 with the policy id in the first
                            // DWORD). The kernel fills the union with the process's current policy word. Report
                            // the sandbox's realistic state: DEP permanently enabled (policy 0), every other
                            // mitigation at its default (0) — mirrors the x64 class-52 handler above.
                            const uint StructSize = 8;
                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            uint Policy = Instance.ReadMemoryUInt(OutBufferPtr);
                            uint PolicyFlags = Policy == 0 ? 1u : 0u; // ProcessDEPPolicy: DEP permanently on; others default/off.

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            WriteUInt32(Buffer, 0, Policy);
                            WriteUInt32(Buffer, 4, PolicyFlags);

                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            SetReturnLength(StructSize);
                            if ((Instance.Settings.Flags & LogFlags.Syscall) != 0)
                                Instance.TriggerEventMessage($"[+] NtQueryInformationProcess (x86): ProcessMitigationPolicy ({Policy})", LogFlags.Syscall);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessImageFileNameWin32:
                        // Bitness-aware helper (uses StructSerializer.GetStructSize<UNICODE_STRING64> which
                        // returns 8 bytes on x86). Same output shape and semantics as the x64 branch above.
                        return QueryProcessImageFileNameWin32(Instance, ProcessHandle, OutBufferPtr, OutBufferLength, SetReturnLength);

                    case PROCESSINFOCLASS.ProcessQuotaLimits:
                        {
                            // QUOTA_LIMITS on x86: 5 * SIZE_T (4) + LARGE_INTEGER (8) = 28 bytes (0x1C).
                            // Fields: PagedPoolLimit / NonPagedPoolLimit / MinimumWorkingSetSize /
                            // MaximumWorkingSetSize / PagefileLimit / TimeLimit. A real Win10 desktop
                            // process reports "unlimited" pool/pagefile limits (SIZE_T max value),
                            // 200-page min working set, ~1345-page max, TimeLimit=0. al-khaser's
                            // Generic-Sandbox/VM check looks for anomalies — returning honest
                            // "unlimited/default" values keeps it on the not-detected path.
                            const uint StructSize = 0x1C;
                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }
                            if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
                            Buffer.Slice(0, (int)StructSize).Clear();
                            const uint SizeMax = 0xFFFFFFFFu;   // "unlimited" on 32-bit
                            const uint MinWs   = 200 * 4096;    // 200 pages
                            const uint MaxWs   = 1345 * 4096;   // 1345 pages (standard Win10 default)
                            WriteUInt32(Buffer, 0x00, SizeMax); // PagedPoolLimit
                            WriteUInt32(Buffer, 0x04, SizeMax); // NonPagedPoolLimit
                            WriteUInt32(Buffer, 0x08, MinWs);   // MinimumWorkingSetSize
                            WriteUInt32(Buffer, 0x0C, MaxWs);   // MaximumWorkingSetSize
                            WriteUInt32(Buffer, 0x10, SizeMax); // PagefileLimit
                            // TimeLimit (LARGE_INTEGER at +0x14): left zero — "no CPU time limit".
                            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(StructSize);
                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessImageFileName:
                        {
                            // 32-bit UNICODE_STRING is 8 bytes (Length 2, Max 2, Buffer 4). Callers query with
                            // OutBufferPtr=NULL first to get the required length, so a null buffer + non-zero
                            // length is legitimate. Mirrors the x64 branch above but uses UNICODE_STRING32 and
                            // a pointer-sized Buffer.
                            const uint HeaderSize = 8;
                            if (OutBufferLength < HeaderSize)
                            {
                                SetReturnLength(HeaderSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }

                            string GuestDos;
                            if (CurrentProcess)
                            {
                                GuestDos = Instance.WinHelper.WinModules.Count > 0 && !string.IsNullOrEmpty(Instance.WinHelper.WinModules[0].Path)
                                    ? Instance.WinHelper.WinModules[0].Path
                                    : Instance._binary.Location;
                            }
                            else
                            {
                                if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                                    return NTSTATUS.STATUS_INVALID_HANDLE;
                                WinProcess Process = Instance.WinHelper.GetProcessByHandle(ProcessHandle, AccessMask.ProcessQueryLimitedInformation | AccessMask.ProcessQueryInformation);
                                if (Process == null)
                                    return NTSTATUS.STATUS_ACCESS_DENIED;
                                GuestDos = Process.Path;
                            }

                            string Path = Instance.WinHelper.DosPathToNtDevicePath(GuestDos ?? string.Empty);
                            int PathByteCount = Encoding.Unicode.GetByteCount(Path);
                            uint TotalSize = HeaderSize + (uint)PathByteCount;
                            SetReturnLength(TotalSize);

                            if (OutBufferLength < TotalSize)
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, TotalSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            // Convention on WOW64: the caller passes a single flat buffer; the kernel puts the
                            // UNICODE_STRING at buffer[0..8) with Buffer pointing at buffer+8 where the string
                            // bytes live. Mirrors what NtQueryInformationProcess/ProcessImageFileNameWin32 does
                            // for a query-into-user-buffer.
                            ulong StringBufferAddr = OutBufferPtr + HeaderSize;
                            Instance._emulator.WriteMemory(OutBufferPtr + 0, (ushort)PathByteCount, 2);
                            Instance._emulator.WriteMemory(OutBufferPtr + 2, (ushort)PathByteCount, 2);
                            Instance._emulator.WriteMemory(OutBufferPtr + 4, (uint)StringBufferAddr, 4);

                            Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
                            Encoding.Unicode.GetBytes(Path.AsSpan(), PathBytes);
                            if (!Instance.WriteMemory(StringBufferAddr, PathBytes.Slice(0, PathByteCount)))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;

                            return NTSTATUS.STATUS_SUCCESS;
                        }

                    case PROCESSINFOCLASS.ProcessEnclaveInformation:
                        {
                            // A PROCESS_ENCLAVE_INFORMATION struct is 0x28 bytes on x86 and describes the
                            // enclave a process runs in (SGX / VBS). A non-enclave process — Brovan's default —
                            // returns STATUS_NOT_FOUND with the caller's buffer left zero-initialised. combase's
                            // CoInitializeSecurity probes this class during its VBS-security path and treats
                            // STATUS_NOT_SUPPORTED as "kernel too old, bail" (leaves an internal singleton NULL
                            // and later NULL-derefs); STATUS_NOT_FOUND is "kernel understood the query, the
                            // process just isn't in an enclave" and takes the normal (non-enclave) path.
                            const uint StructSize = 0x28;
                            if (OutBufferLength < StructSize)
                            {
                                SetReturnLength(StructSize);
                                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;
                            }
                            if (OutBufferPtr == 0 || !Instance.IsRegionMapped(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            if (!Instance.WinHelper.WriteZeroMemory(OutBufferPtr, StructSize))
                                return NTSTATUS.STATUS_ACCESS_VIOLATION;
                            SetReturnLength(StructSize);
                            return NTSTATUS.STATUS_NOT_FOUND;
                        }

                    default:
                        Instance.TriggerEventMessage($"[!] NtQueryInformationProcess (x86): InfoClass {InfoClass} (0x{(int)InfoClass:X}) not implemented", LogFlags.Issues);
                        return Instance.WinUnimplemented;
                }
            }
        }


        private static NTSTATUS QueryProcessImageFileNameWin32(BinaryEmulator Instance, ulong ProcessHandle, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            NTSTATUS Status = ResolveProcessForQuery(Instance, ProcessHandle, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            bool CurrentProcess = ProcessHandle == HandleManager.CurrentProcess || ProcessHandle == uint.MaxValue;
            string FullPath = CurrentProcess ? Instance.WinHelper.WinModules[0].Path : Process.Path;
            if (string.IsNullOrEmpty(FullPath))
                FullPath = Process.Path ?? string.Empty;

            uint StructSize = StructSerializer.GetStructSize<UNICODE_STRING64>(Instance);
            int PathByteCount = Encoding.Unicode.GetByteCount(FullPath) + 2;
            Span<byte> PathBytes = Instance.WinHelper.Shared.GetSpan((uint)PathByteCount);
            Encoding.Unicode.GetBytes(FullPath.AsSpan(), PathBytes);
            PathBytes[PathByteCount - 2] = 0;
            PathBytes[PathByteCount - 1] = 0;

            ushort Length = checked((ushort)(PathByteCount - 2));
            ushort MaximumLength = checked((ushort)PathByteCount);

            uint RequiredSize = StructSize + (uint)PathByteCount;
            SetReturnLength(RequiredSize);


            if (OutBufferLength < RequiredSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, RequiredSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            ulong BufferPtr = OutBufferPtr + StructSize;

            if (!Instance._emulator.WriteMemory(BufferPtr, PathBytes.Slice(0, PathByteCount)))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            UNICODE_STRING64 Unicode = new UNICODE_STRING64()
            {
                Length = Length,
                MaximumLength = MaximumLength,
                Buffer = BufferPtr
            };

            if (!StructSerializer.WriteStruct(Instance, OutBufferPtr, Unicode).Success)
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static Span<byte> GetSharedWriteBuffer(BinaryEmulator Instance, uint Size)
        {
            Span<byte> Buffer = Instance.WinHelper.Shared.GetSpan(Size);
            Buffer.Clear();
            return Buffer;
        }

        private static void WriteUInt16(Span<byte> Buffer, int Offset, ushort Value)
        {
            BinaryPrimitives.WriteUInt16LittleEndian(Buffer.Slice(Offset, 2), Value);
        }

        private static void WriteUInt32(Span<byte> Buffer, int Offset, uint Value)
        {
            BinaryPrimitives.WriteUInt32LittleEndian(Buffer.Slice(Offset, 4), Value);
        }

        private static void WriteUInt64(Span<byte> Buffer, int Offset, ulong Value)
        {
            BinaryPrimitives.WriteUInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private static void WriteInt64(Span<byte> Buffer, int Offset, long Value)
        {
            BinaryPrimitives.WriteInt64LittleEndian(Buffer.Slice(Offset, 8), Value);
        }

        private static NTSTATUS QueryProcessTimes(BinaryEmulator Instance, ulong ProcessHandle, ulong OutBufferPtr, uint OutBufferLength, Action<uint> SetReturnLength)
        {
            const uint StructSize = 0x20;

            SetReturnLength(StructSize);

            if (OutBufferLength < StructSize)
                return NTSTATUS.STATUS_INFO_LENGTH_MISMATCH;

            if (!Instance.IsRegionMapped(OutBufferPtr, StructSize))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            NTSTATUS Status = ResolveProcessForQuery(Instance, ProcessHandle, out WinProcess Process);
            if (Status != NTSTATUS.STATUS_SUCCESS)
                return Status;

            Instance.WinHelper.UpdateProcessTimes(Process);

            Span<byte> Buffer = GetSharedWriteBuffer(Instance, StructSize);
            WriteInt64(Buffer, 0x00, Process.CreationTime);
            WriteInt64(Buffer, 0x08, Process.ExitTime);
            WriteInt64(Buffer, 0x10, Process.KernelTime);
            WriteInt64(Buffer, 0x18, Process.UserTime);

            if (!Instance.WriteMemory(OutBufferPtr, Buffer))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }

        private static NTSTATUS ResolveProcessForQuery(BinaryEmulator Instance, ulong ProcessHandle, out WinProcess Process)
        {
            Process = null;

            if (ProcessHandle == HandleManager.CurrentProcess || ProcessHandle == uint.MaxValue)
            {
                Process = Instance.WinHelper.WinProcesses.FirstOrDefault(p => p.PID == Instance.WinHelper.PID);
                return Process != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
            }

            if (!Instance.WinHelper.ValidProcessHandle(ProcessHandle))
                return NTSTATUS.STATUS_INVALID_HANDLE;

            AccessMask GrantedAccess = Instance.WinHelper.HandleManager.GetPermissionsByHandle(ProcessHandle);
            bool CanQuery = GrantedAccess == AccessMask.GiveTemp ||
                            (GrantedAccess & AccessMask.GenericAll) != 0 ||
                            (GrantedAccess & AccessMask.ProcessAllAccess) == AccessMask.ProcessAllAccess ||
                            (GrantedAccess & AccessMask.ProcessQueryInformation) != 0 ||
                            (GrantedAccess & AccessMask.ProcessQueryLimitedInformation) != 0;

            if (!CanQuery)
                return NTSTATUS.STATUS_ACCESS_DENIED;

            Process = Instance.WinHelper.HandleManager.GetObjectByHandle<WinProcess>(ProcessHandle);
            return Process != null ? NTSTATUS.STATUS_SUCCESS : NTSTATUS.STATUS_INVALID_HANDLE;
        }

    }
}
