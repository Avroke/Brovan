using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.OS.Windows
{
    // NtCreateNamedPipeFile(PHANDLE FileHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES,
    //   PIO_STATUS_BLOCK, ULONG ShareAccess, ULONG CreateDisposition, ULONG CreateOptions,
    //   ULONG NamedPipeType, ULONG ReadMode, ULONG CompletionMode, ULONG MaximumInstances,
    //   ULONG InboundQuota, ULONG OutboundQuota, PLARGE_INTEGER DefaultTimeout).
    // The .NET runtime creates the diagnostics IPC pipe (\\.\pipe\dotnet-diagnostic-<pid>) on a
    // background thread during startup. Return a valid server-end handle so the runtime proceeds;
    // no client ever connects in the sandbox (the diagnostic server just waits), which is benign.
    internal class NtCreateNamedPipeFile : IWinSyscall
    {
        private const ulong FILE_CREATED = 2;

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
                return Instance.WinUnimplemented;

            ulong FileHandlePtr = Instance.WinHelper.GetArg64(0);
            ulong DesiredAccess = (uint)Instance.WinHelper.GetArg64(1);
            ulong ObjectAttributesPtr = Instance.WinHelper.GetArg64(2);
            ulong IoStatusBlockPtr = Instance.WinHelper.GetArg64(3);

            if (FileHandlePtr == 0 || IoStatusBlockPtr == 0)
                return NTSTATUS.STATUS_INVALID_PARAMETER;

            if (!Instance.IsRegionMapped(FileHandlePtr, 8) || !Instance.IsRegionMapped(IoStatusBlockPtr, 8))
                return NTSTATUS.STATUS_ACCESS_VIOLATION;

            string PipeName = null;
            if (ObjectAttributesPtr != 0 &&
                Instance.WinHelper.TryReadObjectAttributesName64(ObjectAttributesPtr, out _, out _, out string FullName, out _))
                PipeName = FullName;

            WinFile PipeObj = new WinFile
            {
                Path = PipeName,
                Device = true,   // pipe is a device-like object, not a real filesystem file
                Real = false,
                Directory = false,
                Position = 0,
                Handler = null,
                FileStream = null
            };

            Instance.WinHelper.WinFiles.Add(PipeObj);

            AccessMask Permissions = (AccessMask)(uint)DesiredAccess;
            WinHandle Handle = Instance.WinHelper.HandleManager.AddHandle(PipeObj, Permissions);
            Instance.WinHelper.AddWinHandle(Handle);

            Instance._emulator.WriteMemory(FileHandlePtr, (ulong)Handle.Handle);
            Instance.WinHelper.WriteIoStatusBlock64(Instance, IoStatusBlockPtr, NTSTATUS.STATUS_SUCCESS, FILE_CREATED);

            return NTSTATUS.STATUS_SUCCESS;
        }
    }
}
