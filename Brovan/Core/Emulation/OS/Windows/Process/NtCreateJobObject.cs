using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal class NtCreateJobObject : IWinSyscall
    {
        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                ulong JobHandlePtr = Instance.WinHelper.GetArg64(0);
                ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
                ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);

                if (JobHandlePtr == 0)
                    return NTSTATUS.STATUS_INVALID_PARAMETER;

                if (!Instance.IsRegionMapped(JobHandlePtr, 8))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                string Name = string.Empty;
                if (ObjectAttributesPtr != 0)
                {
                    if (!Instance.IsRegionMapped(ObjectAttributesPtr, 0x30))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (!StructSerializer.ParseStruct(Instance, ObjectAttributesPtr, out OBJECT_ATTRIBUTES64 ObjectAttrs))
                        return NTSTATUS.STATUS_ACCESS_VIOLATION;

                    if (ObjectAttrs.ObjectName != 0 && !Instance.WinHelper.TryReadUnicodeString64(ObjectAttrs.ObjectName, out Name, out NTSTATUS NameStatus))
                        return NameStatus;
                }

                WinHandle Handle = Instance.WinHelper.CreateJobHandle(Name, (AccessMask)(uint)DesiredAccess);
                if (!Instance._emulator.WriteMemory(JobHandlePtr, Handle.Handle))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                return NTSTATUS.STATUS_SUCCESS;
            }

            uint SP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
            uint JobHandlePtr32 = Instance.ReadMemoryUInt(SP + 4);
            uint DesiredAccess32 = Instance.ReadMemoryUInt(SP + 8);
            uint ObjectAttributesPtr32 = Instance.ReadMemoryUInt(SP + 12);

            if (JobHandlePtr32 == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(JobHandlePtr32, 4))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string Name32 = string.Empty;
            if (ObjectAttributesPtr32 != 0)
            {
                if (!Instance.IsRegionMapped(ObjectAttributesPtr32, 0x18))
                    return NTSTATUS.STATUS_ACCESS_VIOLATION;

                uint ObjectNamePtr32 = Instance.ReadMemoryUInt(ObjectAttributesPtr32 + 0x08);
                if (ObjectNamePtr32 != 0 && !Instance.WinHelper.TryReadUnicodeString32(ObjectNamePtr32, out Name32, out NTSTATUS NameStatus32))
                    return NameStatus32;
            }

            WinHandle Handle32 = Instance.WinHelper.CreateJobHandle(Name32, (AccessMask)DesiredAccess32);
            if (!Instance._emulator.WriteMemory(JobHandlePtr32, (uint)Handle32.Handle))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
