using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Reflection.PortableExecutable;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using Brovan.Core.Emulation.OS.Windows;
using Brovan.Core.Helpers;
using static Brovan.Core.Emulation.OS.Windows.WinSysHelper;
using static Brovan.Core.Helpers.BinaryHelpers;

namespace Brovan.Core.Emulation.Guests
{
    public enum WindowsBlobLaunchMode
    {
        Ntdll = 1,
        Direct = 2
    }

    internal class WindowsGuest : IGuestEnvironment
    {
        public GuestOsKind Os => GuestOsKind.Windows;

        public ulong StackSize { get; private set; }
        public ulong PEB { get; internal set; }
        public ulong ProcessParams { get; internal set; }
        public ulong ApiSetMap { get; internal set; }
        public ulong LdrInitializeThunk { get; internal set; }
        public ulong RtlUserThreadStart { get; internal set; }
        public WinSysHelper WinHelper { get; internal set; }

        private readonly BlobData _blob;
        private readonly WindowsBlobLaunchMode _blobLaunchMode;
        // Deterministic RNG for synthetic guest identity (username, computer name). Points at the
        // emulator's per-sample seeded stream once Initialize runs; the fallback keeps a param-less
        // access before init still deterministic. Was new Random() + crypto RNG -> a random-LENGTH
        // username every run, whose variable length rippled into path/env/compare work and made the
        // instruction stream (and thus depth) non-reproducible run-to-run.
        private Random _identityRandom;
        private IReadOnlyDictionary<uint, WinSyscallEntry> WinSyscallTable = new Dictionary<uint, WinSyscallEntry>();
        private WinModule _ntdllModule;

        // Guest address of the WOW64 system-call trampoline (see SetupWow64SyscallTransition). A 32-bit
        // ntdll routes every syscall through this address instead of executing a native `syscall`; the
        // trampoline runs a `sysenter` that Brovan intercepts and dispatches through TryHandleSyscall.
        // 0 for x64 guests (which use the real `syscall` instruction) and until it is set up.
        private ulong _wow64SyscallTrampoline;

        // Guest address of the process-wide WOW64INFO structure (see SetupWow64Info). On a real WOW64
        // process wow64.dll allocates this block and stores a pointer to it in every thread's TEB at
        // TlsSlots[WOW64_TLS_WOW64INFO] (offset 0xE38 on the 32-bit TEB) BEFORE the 32-bit ntdll runs;
        // ntdll's CPU-feature init then dereferences it (NativeSystemPageSize@0x00, CpuFlags@0x04,
        // NativeMachine@0x20, EmulatedMachine@0x22) with no NULL guard. The pure-32-bit model has no
        // wow64.dll, so Brovan synthesises the block once per process. 0 for x64 guests / until set up.
        private ulong _wow64InfoPtr;
        // 32-bit TEB offset of TlsSlots[WOW64_TLS_WOW64INFO]. TlsSlots is at TEB+0xE10 (64 * 4 bytes);
        // WOW64_TLS_WOW64INFO == 10, so the slot sits at 0xE10 + 10*4 = 0xE38. (On the 64-bit TEB the
        // same slot is TEB64+0x1480 + 10*8 = 0x14D0 — the offset ntdll's dual-TEB path reads.)
        private const uint Wow64InfoTebSlotOffset32 = 0xE38;

        // Guest address of the 32-bit GDT used to give FS a per-thread base = TEB. MODE_32 Unicorn ignores the
        // FS_BASE pseudo-register, so the FS base must come from a real GDT descriptor (selector 0x53). Set up
        // lazily on the first 32-bit context load; the FS descriptor's base is rewritten per thread switch.
        private ulong _gdt32Base;
        // Selectors are DPL0 / RPL0. Real WOW64 uses ring-3 selectors (CS 0x23, SS/DS 0x2B, FS 0x53), but a
        // ring-3 selector can only be loaded at CPL 3, and Unicorn's reg-write of CS does not perform the far
        // transfer that would raise CPL — so RPL-3 loads #GP. DPL0/RPL0 keeps the loads consistent with the
        // default CPL 0 while still giving FS the correct TEB base (all fs:[X] accesses resolve). The visible
        // selector VALUES differ from a real WOW64 process; that is a known cosmetic gap, not a functional one.
        private const int Wow64FsSelector = 0x50;      // GDT index 10, RPL 0 — FS → TEB
        private const int Wow64FsGdtIndex = 10;
        private const int Wow64DataSelector = 0x28;    // GDT index 5,  RPL 0 — flat SS/DS/ES
        private const int Wow64DataGdtIndex = 5;
        private const int Wow64CodeGdtIndex = 4;       // GDT index 4 — flat code (CS left at default flat)

        // A sample is loaded from an arbitrary host location (e.g. /tmp/.../al-khaser_x64.exe
        // on a Linux analysis host). That host path must never be exposed to the guest — the
        // PEB ImagePathName, GetModuleFileName, NtQueryVirtualMemory(MemorySectionName) and
        // std::filesystem::equivalent would all read back a non-Windows path and either
        // mis-fingerprint the process or fail to resolve. We present the sample under a
        // realistic per-run guest path (C:\Users\<user>\Desktop\<leaf>) and keep the username
        // stable so the process parameters and the environment block agree. Cached so every
        // consumer sees one coherent identity.
        private string _guestUserName;
        private string _guestImagePath;

        private bool UsesDirectBlobStartup => IsBlob && _blobLaunchMode == WindowsBlobLaunchMode.Direct;

        /// <summary>
        /// Indicates whether the Windows guest should treat the input as a raw blob instead of a PE image.
        /// </summary>
        internal bool IsBlob { get; }

        internal ulong BlobMappedBase => _blob?.MappedBase ?? 0;

        /// <summary>
        /// Mapped base of the main PE image, published so consumers can identify the main
        /// module without matching on <see cref="BinaryFile.Location"/> (which is the host
        /// path, whereas the module now advertises a synthetic guest path).
        /// </summary>
        internal ulong MainModuleBase { get; private set; }

        private const ulong TebSameTebFlagsOffset64 = 0x17EE;
        private const ushort TEB_SAME_TEB_FLAG_SKIP_THREAD_ATTACH = 0x0008;
        private const ushort TEB_SAME_TEB_FLAG_INITIAL_THREAD = 0x0400;
        private const ushort TEB_SAME_TEB_FLAG_LOADER_WORKER = 0x2000;
        private const ushort TEB_SAME_TEB_FLAG_SKIP_LOADER_INIT = 0x4000;
        internal const uint THREAD_CREATE_FLAGS_CREATE_SUSPENDED = 0x1;
        internal const uint THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH = 0x2;
        internal const uint THREAD_CREATE_FLAGS_HIDE_FROM_DEBUGGER = 0x4;
        internal const uint THREAD_CREATE_FLAGS_LOADER_WORKER = 0x10;
        internal const uint THREAD_CREATE_FLAGS_SKIP_LOADER_INIT = 0x20;

        /// <summary>
        /// Creates a Windows guest for a PE image or, when blob data is supplied, a raw Windows blob.
        /// </summary>
        /// <param name="Blob">Optional raw blob mapping information.</param>
        /// <param name="BlobLaunchMode">Startup path to use for raw blobs.</param>
        public WindowsGuest(BlobData Blob = null!, WindowsBlobLaunchMode BlobLaunchMode = WindowsBlobLaunchMode.Ntdll)
        {
            _blob = Blob;
            _blobLaunchMode = BlobLaunchMode;
            IsBlob = Blob != null;
        }

        public ulong GetCurrentTeb(BinaryEmulator Instance)
        {
            WindowsThreadState State = WinEmulatedThread.TryGetState(Instance.CurrentThread);
            if (State == null)
                return 0;

            return State.Teb;
        }

        public void Initialize(BinaryEmulator Instance, BinaryFile Binary)
        {
            if (!Instance.IsArchX86Guest)
                throw new Exception("Windows guest supports only x86/x64.");

            // Publish the ambient WOW64 file-system view before any DLL / syscall-table resolution runs:
            // a 32-bit guest sources its system images from the SysWOW64 sub-view. Set for both bitnesses so
            // the flag always tracks the current guest (a prior x64 run leaves it false again).
            GeneralHelper.Wow64GuestView = Instance._binary.Architecture == BinaryArchitecture.x86;

            _identityRandom = Instance.SeededRandom;

            if (Binary.FileFormat != BinaryFormat.PE)
            {
                if (!IsBlob)
                    return;

                InitializeBlob(Instance, Binary);
                return;
            }

            StackSize = Binary.Architecture == BinaryArchitecture.x64 ? Binary.PE.OptionalHeader64.SizeOfStackReserve : Binary.PE.OptionalHeader32.SizeOfStackReserve / 2;
            ulong ImageBase = Binary.PE.ImageBase;
            ReadOnlySpan<byte> BinaryData = Binary.GetBinaryData();
            ulong ImageSize = Instance.AlignToPageSize(Binary.PE.SizeOfImage != 0 ? Binary.PE.SizeOfImage : (uint)Binary.BinarySize);
            ulong HeaderSizeUlong = Binary.PE.SizeOfHeaders;
            if (HeaderSizeUlong > (ulong)BinaryData.Length)
                HeaderSizeUlong = (ulong)BinaryData.Length;

            int HeaderSize = HeaderSizeUlong > int.MaxValue ? int.MaxValue : (int)HeaderSizeUlong;
            ulong BaseAddress = Instance.MapWinMemoryRegion(ImageBase, (ulong)HeaderSize, MemoryProtection.ReadWrite, SpecialProtections.None, AllocationType.Image, ImageBase);

            if (HeaderSize != 0)
            {
                int HeaderBytes = Math.Min(HeaderSize, BinaryData.Length);
                if (HeaderBytes != 0)
                    Instance._emulator.WriteMemory(BaseAddress, BinaryData.Slice(0, HeaderBytes));
            }

            WinModule Module = new WinModule();

            foreach (PortableBinarySection Section in Binary.PE.Sections)
            {
                if (Section.VirtualAddress == 0)
                    continue;

                ulong VirtualSpan = Section.VirtualSize != 0 ? Section.VirtualSize : Section.RawSize;
                if (VirtualSpan == 0)
                    continue;

                ulong SectionSize = Instance.AlignToPageSize(VirtualSpan);
                ulong SectionAddr = ImageBase + (ulong)Section.VirtualAddress;

                if (Instance.MapWinMemoryRegion(SectionAddr, SectionSize, Instance.GetMemoryProtection(Section.Characteristics), SpecialProtections.None, AllocationType.Image, ImageBase) == 0)
                    continue;

                bool Ok = true;
                if (Section.RawSize > 0 && Section.RawSize <= int.MaxValue)
                {
                    long RawOffsetLong = Section.RawOffset;
                    if (RawOffsetLong >= 0 && RawOffsetLong < BinaryData.Length)
                    {
                        int RawOffset = (int)RawOffsetLong;
                        int RawSize = (int)Section.RawSize;
                        int MaxReadable = BinaryData.Length - RawOffset;
                        int BytesToWrite = Math.Min(RawSize, MaxReadable);
                        if (BytesToWrite != 0)
                            Ok = Instance._emulator.WriteMemory(SectionAddr, BinaryData.Slice(RawOffset, BytesToWrite));
                    }
                }

                if (Ok)
                    Module.Sections.TryAdd(SectionAddr, Section);
            }

            string GuestImagePath = ResolveGuestImagePath(Binary);
            if (!string.IsNullOrWhiteSpace(GuestImagePath))
            {
                Module.Name = GeneralHelper.IO.WindowsLeafName(GuestImagePath);
                Module.Path = GuestImagePath;

                // Back the sample bytes in the virtual C: drive so the guest can open, stat and
                // read its own image (GetModuleFileName + CreateFile on self,
                // std::filesystem::equivalent) and drop siblings such as log.txt next to it.
                GeneralHelper.IO.SeedGuestImageFile(GuestImagePath, Binary.GetBinaryData());
            }

            Module.OriginalBase = Binary.PE.ImageBase;
            Module.MappedBase = BaseAddress;
            Module.SizeOfImage = ImageSize;
            Module.EntryPoint = Module.MappedBase + Binary.EntryPoint;
            Module.Architecture = Binary.Architecture;
            MainModuleBase = BaseAddress;

            PrepareWinEnvironment(Instance, Module);
        }

        /// <summary>
        /// Maps a raw Windows blob and prepares it as the main module for the Windows guest.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="Binary">The raw blob binary wrapper.</param>
        private void InitializeBlob(BinaryEmulator Instance, BinaryFile Binary)
        {
            ReadOnlySpan<byte> Data = Binary.GetBinaryData();
            ulong BlobSize = Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 1));
            ulong RequestedBase = _blob?.LoadAddress ?? 0;
            ulong MappedBase;

            if (RequestedBase == 0 || Instance.IsRegionMapped(RequestedBase, BlobSize))
                MappedBase = Instance.MapWinUniqueAddress(BlobSize, MemoryProtection.All, SpecialProtections.None, AllocationType.Image);
            else
                MappedBase = Instance.MapWinMemoryRegion(RequestedBase, BlobSize, MemoryProtection.All, SpecialProtections.None, AllocationType.Image, RequestedBase);

            if (MappedBase == 0)
                throw new InvalidOperationException("Failed to map the Windows blob image.");

            if (Data.Length != 0)
                Instance._emulator.WriteMemory(MappedBase, Data);

            if (_blob != null)
                _blob.MappedBase = MappedBase;

            StackSize = (_blob?.StackSize).GetValueOrDefault();
            if (StackSize == 0)
                StackSize = Binary.Architecture == BinaryArchitecture.x64 ? 0x200000UL : 0x100000UL;

            ulong GuestEntry = MappedBase;
            if (_blob != null && _blob.EntryAddress != 0)
            {
                ulong EntryAddress = _blob.EntryAddress;
                if (_blob.LoadAddress != 0 && EntryAddress >= _blob.LoadAddress && EntryAddress < _blob.LoadAddress + BlobSize)
                    GuestEntry = MappedBase + (EntryAddress - _blob.LoadAddress);
                else
                    GuestEntry = EntryAddress;
            }

            if (MappedBase != 0 && GuestEntry >= MappedBase && GuestEntry - MappedBase <= uint.MaxValue)
                Binary.EntryPoint = (uint)(GuestEntry - MappedBase);

            WinModule Module = new WinModule
            {
                Architecture = Binary.Architecture,
                MappedBase = MappedBase,
                OriginalBase = RequestedBase != 0 ? RequestedBase : MappedBase,
                SizeOfImage = BlobSize,
                EntryPoint = GuestEntry,
                Name = !string.IsNullOrWhiteSpace(Binary.Location) ? Path.GetFileName(Binary.Location) : "blob.bin",
                Path = Binary.Location
            };

            PrepareWinEnvironment(Instance, Module);
        }

        public void Start(BinaryEmulator Instance)
        {
            if (WinHelper == null || WinHelper.WinModules.Count == 0)
                return;

            ulong TID = CreateInitialThread(Instance);
            if (!Instance.Threads.TryGetValue((uint)TID, out EmulatedThread Thread) || Thread == null)
                return;

            Instance.LoadContext(Thread);
            Instance.RunMlfqScheduler();
        }

        public void OnThreadContextLoaded(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return;

            ulong Teb = WinEmulatedThread.GetState(Thread).Teb;
            if (Teb == 0)
                return;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_GS_BASE, Teb);
            else
                // Every 32-bit guest (WOW64 PE or raw blob) addresses its TEB through FS, so the FS segment
                // base must track the current thread's TEB — this is what makes fs:[0x18]/fs:[0x30]/fs:[0xC0]
                // (Self / PEB / WOW64 transition) resolve. MODE_32 ignores the FS_BASE pseudo-register, so the
                // base is installed through a GDT descriptor (selector 0x53) instead — see SetupWow64Segments.
                SetupWow64Segments(Instance, Teb);
        }

        public bool HasPendingGuestWork(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return false;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.DispatchException)
                return true;

            return WinHelper != null && WinHelper.CanDispatchUserApc(Thread);
        }

        public bool IsHandleSignaled(BinaryEmulator Instance, ulong Handle)
        {
            if (WinHelper == null)
                return false;

            IHandleObject Obj = WinHelper.HandleManager.GetObjectByHandle(Handle);
            if (Obj == null)
                return false;

            if (Obj is WinEvent Event)
                return Event.Signaled;

            if (Obj is WinMutex Mutex)
                return Mutex.Signaled;

            if (Obj is EmulatedThread Thread)
                return Thread.State == EmulatedThreadState.Terminated;

            if (Obj is WinTimer Timer)
                return Timer.Signaled;

            if (Obj is WinWorkerFactory Factory)
                return IsWorkerFactoryReady(Instance, Factory);

            return false;
        }


        public void OnThreadWaitSatisfied(BinaryEmulator Instance, EmulatedThread Thread)
        {
            if (Thread == null)
                return;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            if (State.WorkerFactoryWaitActive)
            {
                CompleteWorkerFactoryWait(Instance, Thread, State);
                return;
            }

            NTSTATUS WaitStatus = State.WaitStatus;
            if (WaitStatus == NTSTATUS.STATUS_PENDING)
                WaitStatus = NTSTATUS.STATUS_SUCCESS;

            if (Thread.WaitTimedOut)
            {
                WaitStatus = NTSTATUS.STATUS_TIMEOUT;
                if (!State.AlertByThreadIdWaitActive && Thread.WaitHandles == null)
                    WaitStatus = NTSTATUS.STATUS_SUCCESS;
            }
            else if (State.AlertByThreadIdWaitActive)
                WaitStatus = NTSTATUS.STATUS_ALERTED;
            else if (Thread.WaitSatisfiedIndex >= 0 && WaitStatus == NTSTATUS.STATUS_SUCCESS)
                WaitStatus = (NTSTATUS)(uint)Thread.WaitSatisfiedIndex;

            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            ulong ResumeRip = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : (State.WaitResumeRIP != 0 ? State.WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)(uint)WaitStatus;

            State.WaitCompleted = false;
            State.WaitStatus = WaitStatus;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;
            State.AlertByThreadIdWaitActive = false;
            State.AlertByThreadIdAddress = 0;
            State.MsgWaitActive = false;
            State.MsgWaitMask = 0;
            State.GetMessageWaitActive = false;
            Thread.WaitTimedOut = false;
            Thread.WaitSatisfiedIndex = -1;

            if (Instance.CurrentThread == Thread)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        private static uint GetWorkerFactoryPacketSize(BinaryArchitecture Architecture)
        {
            return Architecture == BinaryArchitecture.x64 ? 0x20u : 0x10u;
        }

        private bool IsWorkerFactoryReady(BinaryEmulator Instance, WinWorkerFactory Factory)
        {
            if (Factory == null)
                return false;

            if (Factory.Shutdown)
                return true;

            Instance.MaterializeSignaledWaitPackets(Factory.IoCompletionHandle);
            WinIoCompletion Completion = WinHelper?.HandleManager.GetObjectByHandle<WinIoCompletion>(Factory.IoCompletionHandle);
            if (Completion == null)
                return false;

            return Completion.Entries.Count > 0;
        }

        private void CompleteWorkerFactoryWait(BinaryEmulator Instance, EmulatedThread Thread, WindowsThreadState State)
        {
            NTSTATUS WaitStatus = NTSTATUS.STATUS_SUCCESS;
            WinWorkerFactory Factory = WinHelper?.HandleManager.GetObjectByHandle<WinWorkerFactory>(State.WorkerFactoryHandle);

            if (Instance.IsEmulatedDeadlineExpired(Thread.WaitDeadline))
            {
                WaitStatus = NTSTATUS.STATUS_TIMEOUT;
                if (State.WorkerFactoryPacketsReturned != 0)
                {
                    if (Instance._binary.Architecture == BinaryArchitecture.x64)
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, 0u, 4);
                    else
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, 0u);
                }
            }
            else if (Factory != null)
            {
                uint Removed = 0;
                if (State.WorkerFactoryReservedEntries != null && State.WorkerFactoryReservedEntries.Count > 0)
                {
                    uint PacketSize = GetWorkerFactoryPacketSize(Instance._binary.Architecture);
                    foreach (WinIoCompletionEntry Entry in State.WorkerFactoryReservedEntries)
                    {
                        ulong Address = State.WorkerFactoryMiniPackets + ((ulong)Removed * PacketSize);

                        if (Instance._binary.Architecture == BinaryArchitecture.x64)
                        {
                            Instance._emulator.WriteMemory(Address + 0x0, Entry.KeyContext, 8);
                            Instance._emulator.WriteMemory(Address + 0x8, Entry.ApcContext, 8);
                            Instance._emulator.WriteMemory(Address + 0x10, unchecked((ulong)(long)(int)Entry.IoStatus), 8);
                            Instance._emulator.WriteMemory(Address + 0x18, Entry.IoStatusInformation, 8);
                        }
                        else
                        {
                            Instance._emulator.WriteMemory(Address + 0x0, (uint)Entry.KeyContext);
                            Instance._emulator.WriteMemory(Address + 0x4, (uint)Entry.ApcContext);
                            Instance._emulator.WriteMemory(Address + 0x8, (uint)Entry.IoStatus);
                            Instance._emulator.WriteMemory(Address + 0xC, (uint)Entry.IoStatusInformation);
                        }

                        Removed++;
                    }
                }

                if (State.WorkerFactoryPacketsReturned != 0)
                {
                    if (Instance._binary.Architecture == BinaryArchitecture.x64)
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, Removed, 4);
                    else
                        Instance._emulator.WriteMemory(State.WorkerFactoryPacketsReturned, Removed);
                }
            }

            if (Thread.Context == null)
                Thread.Context = new CpuContext();

            ulong ResumeRip = State.WaitReturnRIP != 0 ? State.WaitReturnRIP : (State.WaitResumeRIP != 0 ? State.WaitResumeRIP + 2 : Thread.Context.RIP);
            Thread.Context.RIP = ResumeRip;
            Thread.Context.RAX = (ulong)(uint)WaitStatus;

            State.WorkerFactoryWaitActive = false;
            State.WorkerFactoryHandle = 0;
            State.WorkerFactoryMiniPackets = 0;
            State.WorkerFactoryPacketsReturned = 0;
            State.WorkerFactoryMaxPackets = 0;
            State.WorkerFactoryReservedEntries?.Clear();
            State.WaitCompleted = false;
            State.WaitStatus = WaitStatus;
            State.WaitResumeRIP = 0;
            State.WaitReturnRIP = 0;
            State.WaitAlertable = false;
            State.WaitObjects = null;
            State.ApcAlertable = false;

            if (Instance.CurrentThread == Thread)
            {
                Instance.WriteRegister(Registers.UC_X86_REG_RIP, Thread.Context.RIP);
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, Thread.Context.RAX);
            }
        }

        public bool ExecuteThreadSlice(BinaryEmulator Instance, EmulatedThread Thread, uint QuantumInstructions, out bool State)
        {
            State = false;
            if (Thread == null)
                return false;

            if (WinHelper != null && WinHelper.CanDispatchUserApc(Thread))
                WinHelper.DispatchNextUserApc(Thread);

            WindowsThreadState ThreadState = WinEmulatedThread.GetState(Thread);
            if (ThreadState.DispatchException)
            {
                if (ThreadState.ExceptionInformation == null)
                    ThreadState.ExceptionInformation = new ExceptionInformation();

                WinHelper?.InvokeException(ThreadState.ExceptionInformation.Status, ThreadState.ExceptionInformation);

                ThreadState.DispatchException = false;

                State = Instance._emulator.Emulate(Instance.ReadRegister(Instance.IPRegister), 0, 0, QuantumInstructions);
                return true;
            }

            State = Instance._emulator.Emulate(Thread.Context.RIP, 0, 0, QuantumInstructions);
            if (!State && Instance._emulator.GetLastError() == BackendError.Exception)
            {
                ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);
                if ((EFlags & (ulong)CPUFlags.TF) != 0 && !ThreadState.DispatchException)
                {
                    QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP);
                    State = true;
                }
            }

            if (Instance.CurrentThread != null && WinEmulatedThread.GetState(Instance.CurrentThread).DispatchException)
                State = true;
            return true;
        }

        private static ulong[] ReadWindowsSyscallArguments(BinaryEmulator Instance, int Count)
        {
            if (Count <= 0)
                return Array.Empty<ulong>();

            ulong[] Args = new ulong[Count];
            try
            {
                if (Instance._binary.Architecture == BinaryArchitecture.x64)
                {
                    ulong RSP = Instance.ReadRegister(Registers.UC_X86_REG_RSP);
                    for (int i = 0; i < Count; i++)
                    {
                        if (i == 0) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_RCX);
                        else if (i == 1) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_RDX);
                        else if (i == 2) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_R8);
                        else if (i == 3) Args[i] = Instance.ReadRegister(Registers.UC_X86_REG_R9);
                        else Args[i] = Instance.ReadMemoryULong(RSP + 0x20 + (ulong)((i - 4) * 8));
                    }
                }
                else
                {
                    uint ESP = Instance.ReadRegister32(Registers.UC_X86_REG_ESP);
                    for (int i = 0; i < Count; i++)
                        Args[i] = Instance.ReadMemoryUInt(ESP + (uint)(4 * (i + 1)));
                }
            }
            catch
            {
            }

            return Args;
        }

        public bool TryHandleSyscall(BinaryEmulator Instance)
        {
            try
            {
                uint Syscall = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? Instance.ReadRegister32(Registers.UC_X86_REG_RAX)
                    : Instance.ReadRegister32(Registers.UC_X86_REG_EAX);
                SyscallAbi Abi = Instance._binary.Architecture == BinaryArchitecture.x64 ? SyscallAbi.X64 : SyscallAbi.X86;
                ulong Rip = Instance.ReadRegister(Instance.IPRegister);
                bool CaptureSyscallHistory = Instance.Syscalls?.TraceEnabled == true;
                ulong[] HistoryArgs = CaptureSyscallHistory ? ReadWindowsSyscallArguments(Instance, 6) : Array.Empty<ulong>();

                WinSyscallTable.TryGetValue(Syscall, out WinSyscallEntry Entry);
                string HandlerName = Entry.Name;
                bool IsImplemented = Entry.Handler != null;

                SyscallRule Rule = null;
                if (Instance.Syscalls.HasRules)
                    Instance.Syscalls.TryMatchRule(Syscall, HandlerName, out Rule);

                if (Rule != null)
                {
                    int MaxArgs = Rule.ArgsCount;
                    ulong[] Args = Array.Empty<ulong>();
                    if (MaxArgs > 0)
                    {
                        if (CaptureSyscallHistory && MaxArgs <= HistoryArgs.Length)
                        {
                            Args = new ulong[MaxArgs];
                            Array.Copy(HistoryArgs, Args, MaxArgs);
                        }
                        else
                        {
                            Args = ReadWindowsSyscallArguments(Instance, MaxArgs);
                        }
                    }

                    SyscallContext Ctx = Instance.Syscalls.HandleSyscall(Syscall, HandlerName, Args, Rule);
                    if (Ctx.Handled)
                    {
                        if (!Instance.SuppressSyscallStatusWrite)
                        {
                            SetLastWinErrorRegister(Instance, (NTSTATUS)Ctx.ReturnValue);
                            Instance.SuppressSyscallStatusWrite = false;
                        }

                        if (CaptureSyscallHistory)
                            Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, Ctx.Args, Ctx.ReturnValue, Rip, IsImplemented, true);
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[SYSCALL MANAGER] Syscall 0x{Syscall:X} handled, returned 0x{Ctx.ReturnValue:X}.", LogFlags.General);
                        return true;
                    }
                }

                if (IsImplemented)
                {
                    Instance.WinHelper.BeginSyscall();
                    NTSTATUS Status;
                    try
                    {
                        Status = Entry.Handler.Handle(Instance);
                    }
                    finally
                    {
                        Instance.WinHelper.EndSyscall();
                    }
                    if (Instance.Settings.SyscallNotificationCallback != null)
                    {
                        Instance.Settings.SyscallNotificationCallback.Invoke(Instance.ReadRegister(Instance.IPRegister), Syscall, HandlerName, (ulong)(uint)Status);
                    }
                    else
                    {
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[+] Syscall {HandlerName} (0x{Syscall:X}) executed, returned {Status}.", LogFlags.General);
                    }

                    if (CaptureSyscallHistory)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, HistoryArgs, (ulong)(uint)Status, Rip, true);

                    bool SuppressStatusWrite = Instance.SuppressSyscallStatusWrite;
                    Instance.SuppressSyscallStatusWrite = false;

                    if (!SuppressStatusWrite)
                        SetLastWinErrorRegister(Instance, Status);
                }
                else
                {
                    if (Instance.Settings.SyscallNotificationCallback != null)
                    {
                        Instance.Settings.SyscallNotificationCallback.Invoke(Instance.ReadRegister(Instance.IPRegister), Syscall, null, (ulong)(uint)Instance.WinUnimplemented);
                    }
                    else
                    {
                        if ((Instance.Settings.Flags & LogFlags.General) != 0)
                            Instance.TriggerEventMessage($"[!] Syscall 0x{Syscall:X} not implemented. returned {Instance.WinUnimplemented}.", LogFlags.General);
                    }

                    if (CaptureSyscallHistory)
                        Instance.Syscalls.RecordSyscall(GuestOsKind.Windows, Abi, Syscall, HandlerName, HistoryArgs, (ulong)(uint)Instance.WinUnimplemented, Rip, false);

                    bool SuppressStatusWrite = Instance.SuppressSyscallStatusWrite;
                    Instance.SuppressSyscallStatusWrite = false;

                    if (!SuppressStatusWrite)
                        SetLastWinErrorRegister(Instance, Instance.WinUnimplemented);
                }

                return true;
            }
            catch (Exception ex)
            {
                Utils.LogError($"[-] [TryHandleWinSyscall] ERROR: {ex.Message}\nStackTrace:\n\n{ex.StackTrace}");
                if ((Instance.Settings.Flags & LogFlags.Issues) != 0)
                    Instance.TriggerEventMessage($"[-] Error while handling a Windows Syscall: {ex.Message}", LogFlags.Issues);
                return true;
            }
        }

        public void HandlePrivilegedInstruction(BinaryEmulator Instance)
        {
            QueueUserModeException(Instance, NTSTATUS.STATUS_PRIVILEGED_INSTRUCTION);
        }

        public void HandleInvalidInstruction(BinaryEmulator Instance)
        {
            QueueUserModeException(Instance, NTSTATUS.STATUS_ILLEGAL_INSTRUCTION);
        }

        private static ExceptionType MapMemoryTypeToExceptionType(BackendMemoryAccessType Type)
        {
            switch (Type)
            {
                case BackendMemoryAccessType.ReadUnmapped:
                case BackendMemoryAccessType.ReadProtected:
                    return ExceptionType.Read;

                case BackendMemoryAccessType.WriteUnmapped:
                case BackendMemoryAccessType.WriteProtected:
                    return ExceptionType.Write;

                case BackendMemoryAccessType.FetchUnmapped:
                case BackendMemoryAccessType.FetchProtected:
                    return ExceptionType.Execute;

                default:
                    return ExceptionType.Read;
            }
        }

        public bool TryRescueDecommittedMemory(BinaryEmulator Instance, BackendMemoryAccessType Type, ulong Address)
        {
            return Instance.TryRescueDecommittedRead(Type, Address);
        }

        public bool HandleInvalidMemory(BinaryEmulator Instance, BackendMemoryAccessType Type, ulong Address, uint Size, ulong Value)
        {
            if (Instance._binary == null || (!IsBlob && Instance._binary.FileFormat != BinaryFormat.PE))
                return false;

            ExceptionType ExType = MapMemoryTypeToExceptionType(Type);
            ExceptionInformation ExInfo = new ExceptionInformation
            {
                Address = Address,
                Type = ExType,
                Status = NTSTATUS.STATUS_ACCESS_VIOLATION
            };

            QueueUserModeException(Instance, NTSTATUS.STATUS_ACCESS_VIOLATION, ExInfo);
            return false;
        }

        public bool TryHandleInterrupt(BinaryEmulator Instance, uint InterruptNumber)
        {
            switch (InterruptNumber)
            {
                case 1:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_SINGLE_STEP);
                    return true;
                case 3:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_BREAKPOINT);
                    return true;
                case 0x2D:
                    // KiDebugService (int 2D). On real Windows without a kernel debugger the
                    // kernel raises STATUS_BREAKPOINT and the CPU/kernel already advanced RIP
                    // past the CD 2D opcode by the time the VEH runs — al-khaser's Interrupt_0x2d
                    // probe VEH observes STATUS_BREAKPOINT with RIP already past the opcode and
                    // returns EXCEPTION_CONTINUE_EXECUTION without adjusting RIP.
                    QueueUserModeException(Instance, NTSTATUS.STATUS_BREAKPOINT);
                    return true;
                case 0x29:
                    if ((Instance.Settings.Flags & LogFlags.General) != 0)
                        Instance.TriggerEventMessage($"[!] The Emulated Program asked to Fast-Fail at 0x{Instance.ReadRegister(Instance.IPRegister):X}.", LogFlags.General);
                    Instance.StopEmulation();
                    return true;
                case 0x2E:
                    QueueUserModeException(Instance, NTSTATUS.STATUS_ILLEGAL_INSTRUCTION);
                    return true;
                default:
                    return false;
            }
        }


        public ulong CreateInitialThread(BinaryEmulator Instance)
        {
            if (WinHelper == null || WinHelper.WinModules.Count == 0)
                return 0;

            ulong EntryPoint = WinHelper.WinModules[0].EntryPoint;
            EmulatedThread Thread = UsesDirectBlobStartup
                ? CreateDirectEmulatedThread(Instance, EntryPoint, "InitialBlobStart", 0, null, 8, 0, true)
                : CreateEmulatedThread(Instance, EntryPoint, "InitialThreadStart", 0, null, 8, 0, true);

            return Thread?.ThreadId ?? 0;
        }

        public void QueueUserModeException(BinaryEmulator Instance, NTSTATUS Status, ExceptionInformation Info = null!)
        {
            if (Instance._binary == null || (!IsBlob && Instance._binary.FileFormat != BinaryFormat.PE))
                return;

            if (Status == NTSTATUS.STATUS_SINGLE_STEP)
            {
                ulong EFlags = Instance.ReadRegister(Registers.UC_X86_REG_EFLAGS);
                Instance.WriteRegister(Registers.UC_X86_REG_EFLAGS, EFlags & ~(ulong)CPUFlags.TF);

                ulong Dr6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
                Instance.WriteRegister(Registers.UC_X86_REG_DR6, Dr6 | (1UL << 14));
            }

            uint ThreadId = (uint)Instance.CurrentThreadId;
            if (!Instance.Threads.TryGetValue(ThreadId, out EmulatedThread Thread) || Thread == null)
                return;

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);

            ExceptionInformation ExceptionInfo = Info ?? new ExceptionInformation();
            ExceptionInfo.Status = Status;
            Thread.State = EmulatedThreadState.Exception;
            State.DispatchException = true;
            State.ExceptionInformation = ExceptionInfo;
            Instance.Threads[ThreadId] = Thread;
            Instance._emulator.StopEmulation();
        }

        public void SetLastWinError(BinaryEmulator Instance, uint LastError)
        {
            ulong Teb = GetCurrentTeb(Instance);
            if (Teb == 0)
                return;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                Instance._emulator.WriteMemory(Teb + 0x68, LastError);
            else
                Instance._emulator.WriteMemory(Teb + 0x34, LastError);
        }

        public void SetLastWinErrorRegister(BinaryEmulator Instance, NTSTATUS Status)
        {
            SetLastWinError(Instance, (uint)Status);
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                Instance.WriteRegister(Registers.UC_X86_REG_RAX, (ulong)Status);
            else
                Instance.WriteRegister32(Registers.UC_X86_REG_EAX, (uint)Status);
        }

        public ulong AllocateAndInitializeTEB(BinaryEmulator Instance, EmulatedThread Thread, uint CreateFlags = 0, bool InitialThread = false)
        {
            ulong Teb = Instance.MapUniqueAddress(0x2000, MemoryProtection.ReadWrite);
            if (Instance._binary.Architecture != BinaryArchitecture.x64)
            {
                // 32-bit TEB (NT_TIB layout). Built for every 32-bit guest now — not just the raw-blob path —
                // so a real WOW64 PE gets a valid TEB. Field offsets are the documented x86 TEB layout.
                Instance._emulator.WriteMemoryByte(Teb, 0, 0x2000);
                Instance._emulator.WriteMemory(Teb + 0x00, 0xFFFFFFFFu);                                  // NtTib.ExceptionList (SEH head sentinel)
                Instance._emulator.WriteMemory(Teb + 0x04, (uint)(Thread.StackAddress + Thread.StackSize)); // NtTib.StackBase
                Instance._emulator.WriteMemory(Teb + 0x08, (uint)Thread.StackAddress);                     // NtTib.StackLimit
                Instance._emulator.WriteMemory(Teb + 0x18, (uint)Teb);                                     // NtTib.Self
                Instance._emulator.WriteMemory(Teb + 0x20, WinHelper.PID);                                 // ClientId.UniqueProcess
                Instance._emulator.WriteMemory(Teb + 0x24, Thread.ThreadId);                               // ClientId.UniqueThread
                Instance._emulator.WriteMemory(Teb + 0x30, (uint)PEB);                                     // ProcessEnvironmentBlock
                Instance._emulator.WriteMemory(Teb + 0x34, 0u);                                            // LastErrorValue

                // WOW32Reserved (fs:[0xC0]) — the WOW64 system-call transition pointer. A 32-bit ntdll Nt*
                // stub reaches the kernel through `call fs:[0xC0]` (or the sibling `jmp [Wow64Transition]`).
                // Point it at our syscall trampoline so the transition dispatches to the C# handler.
                if (_wow64SyscallTrampoline != 0)
                    Instance._emulator.WriteMemory(Teb + 0xC0, (uint)_wow64SyscallTrampoline);

                Instance._emulator.WriteMemory(Teb + 0xC4, (uint)0x0409u);                                 // CurrentLocale

                // TlsSlots[WOW64_TLS_WOW64INFO] — a pointer to the process-wide WOW64INFO block. wow64.dll
                // sets this on a real WOW64 process before the 32-bit ntdll runs; the pure-32-bit model
                // populates it here so ntdll's CPU-feature init doesn't dereference a NULL slot. See
                // SetupWow64Info for the structure layout and why each field matters.
                if (_wow64InfoPtr != 0)
                    Instance._emulator.WriteMemory(Teb + Wow64InfoTebSlotOffset32, (uint)_wow64InfoPtr);

                return Teb;
            }

            Instance._emulator.WriteMemoryByte(Teb, 0, 0x2000);
            Instance._emulator.WriteMemory(Teb, ulong.MaxValue, 8);
            Instance._emulator.WriteMemory(Teb + 0x8, Thread.StackAddress + Thread.StackSize);
            Instance._emulator.WriteMemory(Teb + 0x10, Thread.StackAddress);
            Instance._emulator.WriteMemory(Teb + 0x18, 0UL, 8);
            Instance._emulator.WriteMemory(Teb + 0x20, 0UL, 8);
            Instance._emulator.WriteMemory(Teb + 0x28, 0UL, 8);
            Instance._emulator.WriteMemory(Teb + 0x30, Teb, 8);
            Instance._emulator.WriteMemory(Teb + 0x40, WinHelper.PID, 8);
            Instance._emulator.WriteMemory(Teb + 0x48, Thread.ThreadId);
            Instance._emulator.WriteMemory(Teb + 0x60, PEB, 8);
            Instance._emulator.WriteMemory(Teb + 0x68, (uint)0u);
            Instance._emulator.WriteMemory(Teb + 0x108, (uint)0x0409u);
            Instance._emulator.WriteMemory(Teb + 0x1760, (uint)0u);
            Instance._emulator.WriteMemory(Teb + 0x179C, (uint)1u);
            Instance._emulator.WriteMemory(Teb + 0x17A0, (ulong)0ul);
            ushort SameTebFlags = 0;
            if (InitialThread)
                SameTebFlags |= TEB_SAME_TEB_FLAG_INITIAL_THREAD;
            if ((CreateFlags & THREAD_CREATE_FLAGS_SKIP_THREAD_ATTACH) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_SKIP_THREAD_ATTACH;
            if ((CreateFlags & THREAD_CREATE_FLAGS_LOADER_WORKER) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_LOADER_WORKER;
            if ((CreateFlags & THREAD_CREATE_FLAGS_SKIP_LOADER_INIT) != 0)
                SameTebFlags |= TEB_SAME_TEB_FLAG_SKIP_LOADER_INIT;
            Instance._emulator.WriteMemory(Teb + TebSameTebFlagsOffset64, SameTebFlags, 2);
            Instance._emulator.WriteMemory(Teb + 0x180C, (uint)0u);
            return Teb;
        }

        public void ResolveLdrInitializeThunk(BinaryEmulator Instance)
        {
            if (LdrInitializeThunk != 0)
                return;

            if (_ntdllModule == null)
                throw new Exception("ntdll.dll is not loaded.");

            LdrInitializeThunk = Instance.TranslateVirtualAddress(_ntdllModule.ExportsByName["LdrInitializeThunk"], "ntdll.dll");
        }

        public void ResolveRtlUserThreadStart(BinaryEmulator Instance)
        {
            if (RtlUserThreadStart != 0)
                return;

            if (_ntdllModule == null)
                throw new Exception("ntdll.dll is not loaded.");

            RtlUserThreadStart = Instance.TranslateVirtualAddress(_ntdllModule.ExportsByName["RtlUserThreadStart"], "ntdll.dll");
        }

        /// <summary>
        /// Creates a Windows thread that starts directly at the requested address without entering ntdll's user-thread startup path.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        /// <param name="StartAddress">Guest address to execute first.</param>
        /// <param name="Name">Optional thread name.</param>
        /// <param name="Parameter">Optional thread parameter.</param>
        /// <param name="StackSizeOverride">Optional stack size override.</param>
        /// <param name="BasePriority">Base scheduler priority.</param>
        /// <param name="CreateFlags">Thread creation flags used for TEB state.</param>
        /// <param name="InitialThread">Whether this is the initial process thread.</param>
        /// <returns>The created emulated thread.</returns>
        internal EmulatedThread CreateDirectEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name, ulong Parameter, ulong? StackSizeOverride, int BasePriority, uint CreateFlags, bool InitialThread)
        {
            ulong ThreadStackSize = StackSizeOverride ?? StackSize;
            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = WinHelper.GenerateRandomPID(),
                Name = Name,
                State = EmulatedThreadState.Ready,
                BasePriority = BasePriority,
                DynamicBoost = 0,
                QueueLevel = 0,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = StartAddress,
                Parameter = Parameter,
                StackSize = ThreadStackSize,
                StackAddress = Instance.AllocateThreadStack(ThreadStackSize),
                GuestState = new WindowsThreadState()
            };

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.Name ??= $"Thread_{Thread.ThreadId}";

            State.ImpersonationToken = new WinToken
            {
                IsElevated = false,
                IsRestricted = false,
                OwningProcessId = WinHelper.PID,
                OwningThreadId = Thread.ThreadId,
                Type = TokenType.Primary,
                SessionId = 1
            };

            State.Teb = AllocateAndInitializeTEB(Instance, Thread, CreateFlags, InitialThread);

            ulong InitialStack = (Thread.StackAddress + Thread.StackSize) & ~0xFUL;
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                InitialStack -= 8;
                Instance._emulator.WriteMemory(InitialStack, 0UL, 8);
                InitialStack -= 0x20;
                Thread.Context.RCX = Parameter;
            }
            else
            {
                InitialStack -= 4;
                Instance._emulator.WriteMemory(InitialStack, (uint)Parameter);
                InitialStack -= 4;
                Instance._emulator.WriteMemory(InitialStack, 0u);
            }

            Thread.Context.RIP = StartAddress;
            Thread.Context.RSP = InitialStack;
            Thread.Context.RFLAGS = 0x202;
            Thread.Context.MXCSR = Instance.ReadRegister(Registers.UC_X86_REG_MXCSR);
            Thread.Context.CS = Instance.ReadRegister(Registers.UC_X86_REG_CS);
            Thread.Context.DS = Instance.ReadRegister(Registers.UC_X86_REG_DS);
            Thread.Context.ES = Instance.ReadRegister(Registers.UC_X86_REG_ES);
            Thread.Context.FS = Instance.ReadRegister(Registers.UC_X86_REG_FS);
            Thread.Context.GS = Instance.ReadRegister(Registers.UC_X86_REG_GS);
            Thread.Context.SS = Instance.ReadRegister(Registers.UC_X86_REG_SS);
            Thread.Context.DR0 = Instance.ReadRegister(Registers.UC_X86_REG_DR0);
            Thread.Context.DR1 = Instance.ReadRegister(Registers.UC_X86_REG_DR1);
            Thread.Context.DR2 = Instance.ReadRegister(Registers.UC_X86_REG_DR2);
            Thread.Context.DR3 = Instance.ReadRegister(Registers.UC_X86_REG_DR3);
            Thread.Context.DR6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
            Thread.Context.DR7 = Instance.ReadRegister(Registers.UC_X86_REG_DR7);

            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }

        public EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name = null!, ulong Parameter = 0, ulong? StackSizeOverride = null, int BasePriority = 8)
        {
            return CreateEmulatedThread(Instance, StartAddress, Name, Parameter, StackSizeOverride, BasePriority, 0, false);
        }

        internal EmulatedThread CreateEmulatedThread(BinaryEmulator Instance, ulong StartAddress, string Name, ulong Parameter, ulong? StackSizeOverride, int BasePriority, uint CreateFlags, bool InitialThread)
        {
            ResolveLdrInitializeThunk(Instance);
            ResolveRtlUserThreadStart(Instance);

            ulong ThreadStackSize = StackSizeOverride ?? StackSize;
            EmulatedThread Thread = new EmulatedThread
            {
                Context = new CpuContext(),
                ThreadId = WinHelper.GenerateRandomPID(),
                Name = Name,
                State = EmulatedThreadState.Ready,
                BasePriority = BasePriority,
                DynamicBoost = 0,
                QueueLevel = 0,
                LastReadyTick = 0,
                LastRunTick = 0,
                StartAddress = StartAddress,
                Parameter = Parameter,
                StackSize = ThreadStackSize,
                StackAddress = Instance.AllocateThreadStack(ThreadStackSize),
                GuestState = new WindowsThreadState()
            };

            WindowsThreadState State = WinEmulatedThread.GetState(Thread);
            Thread.Name ??= $"Thread_{Thread.ThreadId}";

            State.ImpersonationToken = new WinToken
            {
                IsElevated = false,
                IsRestricted = false,
                OwningProcessId = WinHelper.PID,
                OwningThreadId = Thread.ThreadId,
                Type = TokenType.Primary,
                SessionId = 1
            };

            State.Teb = AllocateAndInitializeTEB(Instance, Thread, CreateFlags, InitialThread);

            ulong InitialRSP;
            ulong contextAddress;
            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                InitialRSP = (Thread.StackAddress + Thread.StackSize) & ~0xFUL;
                InitialRSP -= 8;
                Instance._emulator.WriteMemory(InitialRSP, 0UL, 8);
                InitialRSP -= 0x20;
                contextAddress = Instance.BuildInitialContext(RtlUserThreadStart, InitialRSP, StartAddress, Parameter);
            }
            else
            {
                // x86: ntdll's LdrInitializeThunk is entered stdcall-style with a CONTEXT pointer as its first
                // stack argument; on completion it NtContinue's to that CONTEXT, whose Eip is RtlUserThreadStart
                // (Eax = entry, Ebx = parameter — the x86 RtlUserThreadStart ABI). Lay out the entry frame:
                //   [ESP+0]=return sentinel  [ESP+4]=CONTEXT*  [ESP+8]=ntdll base
                ulong StackTop = (Thread.StackAddress + Thread.StackSize) & ~0xFUL;
                ulong RuntimeEsp = StackTop - 0x100;                 // ESP the thread runs on after NtContinue
                contextAddress = BuildInitialContext32(Instance, RtlUserThreadStart, RuntimeEsp, StartAddress, Parameter);

                InitialRSP = StackTop - 0x20;
                Instance._emulator.WriteMemory(InitialRSP + 0x0, 0u);                                   // return sentinel (LdrInitializeThunk never returns)
                Instance._emulator.WriteMemory(InitialRSP + 0x4, (uint)contextAddress);                 // arg1: PCONTEXT
                Instance._emulator.WriteMemory(InitialRSP + 0x8, (uint)(_ntdllModule?.MappedBase ?? 0)); // arg2: ntdll base
            }

            Thread.Context.RIP = LdrInitializeThunk;
            Thread.Context.RSP = InitialRSP;
            Thread.Context.MXCSR = Instance.ReadRegister(Registers.UC_X86_REG_MXCSR);
            Thread.Context.CS = Instance.ReadRegister(Registers.UC_X86_REG_CS);
            Thread.Context.DS = Instance.ReadRegister(Registers.UC_X86_REG_DS);
            Thread.Context.ES = Instance.ReadRegister(Registers.UC_X86_REG_ES);
            Thread.Context.FS = Instance.ReadRegister(Registers.UC_X86_REG_FS);
            Thread.Context.GS = Instance.ReadRegister(Registers.UC_X86_REG_GS);
            Thread.Context.SS = Instance.ReadRegister(Registers.UC_X86_REG_SS);
            Thread.Context.DR0 = Instance.ReadRegister(Registers.UC_X86_REG_DR0);
            Thread.Context.DR1 = Instance.ReadRegister(Registers.UC_X86_REG_DR1);
            Thread.Context.DR2 = Instance.ReadRegister(Registers.UC_X86_REG_DR2);
            Thread.Context.DR3 = Instance.ReadRegister(Registers.UC_X86_REG_DR3);
            Thread.Context.DR6 = Instance.ReadRegister(Registers.UC_X86_REG_DR6);
            Thread.Context.DR7 = Instance.ReadRegister(Registers.UC_X86_REG_DR7);

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Thread.Context.RCX = contextAddress;
                Thread.Context.RDX = _ntdllModule?.MappedBase ?? 0;
            }

            Instance.Threads[Thread.ThreadId] = Thread;
            Instance.ThreadOrder.Add((int)Thread.ThreadId);
            if (Instance.CurrentThreadId == -1)
                Instance.CurrentThreadId = (int)Thread.ThreadId;

            return Thread;
        }


        private string GenerateRandomUsername()
        {
            const string Alphabet =
                "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                "abcdefghijklmnopqrstuvwxyz" +
                "0123456789";
            Random RandomGen = _identityRandom ?? new Random(0);
            int RandomLen = RandomGen.Next(5, 12);

            char[] result = new char[RandomLen];
            for (int i = 0; i < RandomLen; i++)
                result[i] = Alphabet[RandomGen.Next(Alphabet.Length)];

            return new string(result);
        }

        /// <summary>
        /// The stable guest account name for this run. Generated once so the synthetic image
        /// path (<c>C:\Users\&lt;user&gt;\Desktop\...</c>) and the environment block
        /// (<c>USERNAME</c> / <c>USERPROFILE</c> / <c>TEMP</c>) all describe the same user.
        /// </summary>
        internal string GuestUserName => _guestUserName ??= GenerateRandomUsername();

        /// <summary>
        /// Resolves the guest-visible image path for the main module. The sample is loaded from
        /// an arbitrary host location; that path must not leak to the guest (see the field
        /// comment). Presents it under the current user's desktop and remembers the choice so
        /// the loader LDR entry, the PEB process parameters and NtQueryVirtualMemory all agree.
        /// A host location that is already an absolute Windows path (e.g. analysing a C:\ sample
        /// on a Windows host) is kept verbatim.
        /// </summary>
        private string ResolveGuestImagePath(BinaryFile Binary)
        {
            if (_guestImagePath != null)
                return _guestImagePath;

            string Location = Binary?.Location;

            // Already a real drive-letter Windows path: keep it (Windows analysis host).
            if (!string.IsNullOrWhiteSpace(Location))
            {
                string WinLocation = Location.Replace('/', '\\');
                if (WinLocation.Length >= 3 && char.IsLetter(WinLocation[0]) && WinLocation[1] == ':' && WinLocation[2] == '\\')
                {
                    _guestImagePath = WinLocation;
                    return _guestImagePath;
                }
            }

            // Extract the leaf with GeneralHelper.IO.WindowsLeafName — Path.GetFileName is
            // host-relative and does not treat '\\' as a separator on a Linux analysis host,
            // so it would return the whole backslashed host path as the "file name".
            string Leaf = null;
            if (!string.IsNullOrWhiteSpace(Location))
                Leaf = GeneralHelper.IO.WindowsLeafName(Location).Trim().TrimEnd('\0');
            if (string.IsNullOrWhiteSpace(Leaf))
                Leaf = Binary?.FileFormat == BinaryFormat.PE ? "sample.exe" : "blob.bin";

            _guestImagePath = $@"C:\Users\{GuestUserName}\Desktop\{Leaf}";
            return _guestImagePath;
        }

        /// <summary>
        /// Windows-semantics directory of a guest path (everything up to the last backslash,
        /// including the trailing separator). <see cref="Path.GetDirectoryName(string)"/> is
        /// host-relative and does not treat '\\' as a separator on Linux, so it cannot be used
        /// for a <c>C:\...</c> path on a non-Windows analysis host.
        /// </summary>
        private static string GuestDirectoryOf(string GuestPath)
        {
            if (string.IsNullOrEmpty(GuestPath))
                return "C:\\";

            int LastSep = GuestPath.LastIndexOf('\\');
            if (LastSep <= 0)
                return "C:\\";

            return GuestPath.Substring(0, LastSep + 1);
        }

        public byte[] BuildEnvironment(BinaryEmulator Instance, out ulong size)
        {
            size = 0;
            string Username = GuestUserName;
            string PcName = $"DESKTOP-{Instance.SeededRandom.Next(4, 10)}";
            Dictionary<string, string> Env = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
            {
                { "PROCESSOR_ARCHITECTURE", Instance._binary.Architecture == BinaryArchitecture.x64 ? "AMD64" : "x86" },
                { "OS", "Windows_NT" },
                { "NUMBER_OF_PROCESSORS", "8" },
                { "TEMP", @$"C:\Users\{Username}\AppData\Local\Temp" },
                { "TMP",  @$"C:\Users\{Username}\AppData\Local\Temp" },
                { "HOMEPATH", @$"\Users\{Username}" },
                { "HOMEDRIVE", "C:" },
                { "SYSTEMDRIVE", "C:" },
                { "OneDrive", @$"C:\Users\{Username}\OneDrive" },
                { "SESSIONNAME", "Console" },
                { "ALLUSERSPROFILE", @"C:\ProgramData" },
                { "PUBLIC", @"C:\Users\Public" },
                { "ProgramData", @"C:\ProgramData" },
                { "SYSTEMROOT", @"C:\WINDOWS" },
                { "CommonProgramFiles", @"C:\Program Files\Common Files" },
                { "CommonProgramFiles(x86)", @"C:\Program Files (x86)\Common Files" },
                { "CommonProgramW6432", @"C:\Program Files\Common Files" },
                { "WINDIR", @"C:\WINDOWS" },
                { "USERNAME", Username },
                { "USERPROFILE", @$"C:\Users\{Username}" },
                { "USERDOMAIN", PcName },
                { "USERDOMAIN_ROAMINGPROFILE", PcName },
                { "LOGONSERVER", @$"\\{PcName}" },
                { "PROCESSOR_IDENTIFIER", "Intel64 Family 6 Model 186 Stepping 2, GenuineIntel" },
                { "PROCESSOR_LEVEL", "6" },
                { "COMSPEC", @"C:\Windows\System32\cmd.exe" },
                { "PATHEXT", ".COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC" },
                { "PATH", @"C:\WINDOWS\system32;C:\WINDOWS;C:\WINDOWS\System32\Wbem;C:\WINDOWS\System32\WindowsPowerShell\v1.0\;C:\WINDOWS\System32\OpenSSH\" }
            };

            StringBuilder Builder = new StringBuilder(1024);
            foreach (var kv in Env)
            {
                Builder.Append(kv.Key).Append('=').Append(kv.Value).Append('\0');
            }
            Builder.Append('\0');

            byte[] EnvBytes = Encoding.Unicode.GetBytes(Builder.ToString());
            size = (ulong)EnvBytes.Length;
            return EnvBytes;
        }

        /// <summary>
        /// Ensures direct Windows blob startup has usable console standard handles before synthetic process parameters are written.
        /// </summary>
        private void EnsureDirectBlobStandardHandles()
        {
            if (WinHelper.ConsoleHandle == null)
            {
                WinFile Console = new WinFile
                {
                    Device = true,
                    Path = "\\Device\\ConDrv",
                    Handler = ConsoleServer.Handle
                };
                WinHelper.ConsoleHandle = WinHelper.HandleManager.AddHandle(Console, AccessMask.GenericRead | AccessMask.GenericWrite);
            }

            if (WinHelper.STD_IN == null)
            {
                WinFile StdIn = new WinFile
                {
                    Device = true,
                    Path = "\\Device\\ConDrv",
                    Handler = ConsoleServer.Handle
                };
                WinHelper.STD_IN = WinHelper.HandleManager.AddHandle(StdIn, AccessMask.FileReadData);
            }

            if (WinHelper.STD_OUT == null)
            {
                WinFile StdOut = new WinFile
                {
                    Device = true,
                    Path = "\\Device\\ConDrv",
                    Handler = ConsoleServer.Handle
                };
                WinHelper.STD_OUT = WinHelper.HandleManager.AddHandle(StdOut, AccessMask.FileWriteData);
            }
        }

        public void PrepareWinEnvironment(BinaryEmulator Instance, WinModule MainModule)
        {
            Instance.EnsureInstructionHook();

            bool IsPeImage = Instance._binary.FileFormat == BinaryFormat.PE;
            if (IsPeImage)
                Instance.ApplyPERelocations(MainModule, Instance._binary);

            WinHelper = new WinSysHelper(Instance);
            if (UsesDirectBlobStartup)
                EnsureDirectBlobStandardHandles();

            WinSyscallTable = HelperFunctions.BuildWinSyscallDictionary(Instance._binary.Architecture);

            ulong PageSize = 0x2000;
            PEB = Instance.MapUniqueAddress(PageSize, MemoryProtection.ReadWrite);
            byte[] ApiSetMapBlob = BinaryEmulator.GetApiSetMapBlob();
            if (ApiSetMapBlob.Length != 0)
            {
                ApiSetMap = Instance.MapUniqueAddress((ulong)ApiSetMapBlob.Length, MemoryProtection.Read);
                Instance._emulator.WriteMemory(ApiSetMap, ApiSetMapBlob);
            }

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
            {
                Instance._emulator.WriteMemory(PEB + 0x0, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x1, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x2, (byte)0, 1);
                Instance._emulator.WriteMemory(PEB + 0x8, 0xFFFFFFFFFFFFFFFFUL, 8);
                Instance._emulator.WriteMemory(PEB + 0x10, MainModule.MappedBase, 8);
                Instance._emulator.WriteMemory(PEB + 0x18, 0UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x30, 0UL, 8);
                Instance._emulator.WriteMemory(PEB + 0x68, ApiSetMap, 8);
                Instance._emulator.WriteMemory(PEB + 0xB8, 8, 4);
                Instance._emulator.WriteMemory(PEB + 0xBC, 0, 4);
                Instance._emulator.WriteMemory(PEB + 0x118, WindowsVersionInfo.MajorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0x11C, WindowsVersionInfo.MinorVersion, 4);
                Instance._emulator.WriteMemory(PEB + 0x120, WindowsVersionInfo.BuildNumberShort, 2);
                Instance._emulator.WriteMemory(PEB + 0x122, (ushort)0, 2);
                Instance._emulator.WriteMemory(PEB + 0x124, WindowsVersionInfo.PlatformIdWin32Nt, 4);

                if (IsPeImage)
                {
                    Instance._emulator.WriteMemory(PEB + 0xC8, Instance._binary.PE.OptionalHeader64.SizeOfHeapReserve);
                    Instance._emulator.WriteMemory(PEB + 0xD0, Instance._binary.PE.OptionalHeader64.SizeOfHeapCommit);
                }
                else if (UsesDirectBlobStartup)
                {
                    Instance._emulator.WriteMemory(PEB + 0xC8, 0x100000UL);
                    Instance._emulator.WriteMemory(PEB + 0xD0, 0x10000UL);
                }

                if (IsPeImage || UsesDirectBlobStartup)
                {
                    // Guest-visible image path (C:\Users\<user>\Desktop\<leaf>) rather than the
                    // raw host location — see ResolveGuestImagePath / the _guestImagePath field.
                    string ImagePath = ResolveGuestImagePath(Instance._binary);
                    if (string.IsNullOrWhiteSpace(ImagePath))
                        ImagePath = !string.IsNullOrWhiteSpace(MainModule.Path) ? MainModule.Path : (!string.IsNullOrWhiteSpace(MainModule.Name) ? MainModule.Name : "C:\\blob.bin");
                    string CurrentDir = GuestDirectoryOf(ImagePath);
                    string DesktopInfo = "Winsta0\\Default";
                    string WindowTitle = ImagePath;
                    string CommandLine = GeneralHelper.QuoteCommandLineArg(ImagePath);
                    if (!string.IsNullOrWhiteSpace(Instance.RawProgramArguments))
                        CommandLine += $" {Instance.RawProgramArguments}";

                    static byte[] Wz(string s) => Encoding.Unicode.GetBytes(s + "\0");

                    byte[] EnvBlock = BuildEnvironment(Instance, out ulong envSize);
                    ulong HeaderSize = 0x448;
                    ulong TotalSize = HeaderSize + (ulong)Wz(CurrentDir).Length + (ulong)Wz(ImagePath).Length + (ulong)Wz(CommandLine).Length + (ulong)Wz(WindowTitle).Length + (ulong)Wz(DesktopInfo).Length + envSize;
                    TotalSize = BinaryEmulator.AlignUp(TotalSize, 0x10);

                    ProcessParams = Instance.MapUniqueAddress(TotalSize, MemoryProtection.ReadWrite);
                    Instance._emulator.WriteMemory(ProcessParams, new byte[HeaderSize]);
                    Instance._emulator.WriteMemory(PEB + 0x20, ProcessParams, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x410, new byte[0x38]);
                    ulong Cursor = ProcessParams + HeaderSize;

                    void WriteInlineUnicodeString(ulong StructOffset, string Value, ushort ForcedMax = 0)
                    {
                        byte[] Data = Wz(Value);
                        Instance._emulator.WriteMemory(Cursor, Data);
                        ushort Len = (ushort)(Data.Length - 2);
                        ushort Max = ForcedMax != 0 ? ForcedMax : (ushort)Data.Length;
                        Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x0, Len, 2);
                        Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x2, Max, 2);
                        Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x8, Cursor, 8);
                        Cursor += (ulong)Data.Length;
                        Cursor = BinaryEmulator.AlignUp(Cursor, 2);
                    }

                    Instance._emulator.WriteMemory(ProcessParams + 0x8, 0x6001u, 4);
                    WriteInlineUnicodeString(0x38, CurrentDir, ForcedMax: 1024);
                    if (UsesDirectBlobStartup || (IsPeImage && Instance._binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui)))
                    {
                        ulong Handle = WinHelper.ConsoleHandle.Handle;
                        Instance._emulator.WriteMemory(ProcessParams + 0x10, Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x18, new byte[] { 0x00, 0x00, 0x00, 0x00 });
                        Instance._emulator.WriteMemory(ProcessParams + 0x20, WinHelper.STD_IN.Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x28, WinHelper.STD_OUT.Handle, 8);
                        Instance._emulator.WriteMemory(ProcessParams + 0x30, WinHelper.STD_OUT.Handle, 8);
                    }
                    WriteInlineUnicodeString(0x60, ImagePath);
                    WriteInlineUnicodeString(0x70, CommandLine);
                    ulong EnvPtr = Cursor;
                    Instance._emulator.WriteMemory(EnvPtr, EnvBlock);
                    Instance._emulator.WriteMemory(ProcessParams + 0x80, EnvPtr, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x3F0, envSize, 8);
                    Instance._emulator.WriteMemory(ProcessParams + 0x3F8, 0UL, 8);
                    Cursor += envSize;
                    Cursor = BinaryEmulator.AlignUp(Cursor, 2);
                    WriteInlineUnicodeString(0xB0, WindowTitle);
                    WriteInlineUnicodeString(0xC0, DesktopInfo);
                    Instance._emulator.WriteMemory(ProcessParams + 0x408, 0u, 4);
                    Instance._emulator.WriteMemory(ProcessParams + 0x40C, 4u, 4);
                    uint Used = (uint)(Cursor - ProcessParams);
                    uint Length = Used < (uint)HeaderSize ? (uint)HeaderSize : Used;
                    Instance._emulator.WriteMemory(ProcessParams + 0x0, (uint)TotalSize, 4);
                    Instance._emulator.WriteMemory(ProcessParams + 0x4, Length, 4);
                }
            }
            else
            {
                // 32-bit guest (WOW64 PE or raw blob): build the full 32-bit PEB + RTL_USER_PROCESS_PARAMETERS.
                // Previously only a minimal PEB was populated (and only for the raw-blob path), leaving a real
                // 32-bit PE without ProcessParameters — ntdll's loader then read a NULL command line / image
                // path and faulted. BuildProcessEnvironment32 mirrors the x64 block with x86 field offsets.
                BuildProcessEnvironment32(Instance, MainModule);
            }

            WinHelper.AddModule(MainModule, true);
            LoadNtdll(Instance);
            if (Instance._binary.Architecture == BinaryArchitecture.x86)
            {
                SetupWow64SyscallTransition(Instance);
                SetupWow64Info(Instance);
            }
            if (UsesDirectBlobStartup)
                InstallSyntheticLdrData(Instance);
            WinHelper.LdrTracker = new PebLdrTracker(Instance, WinHelper);
            WinHelper.LdrTracker.Install();
        }

        /// <summary>
        /// Builds the 32-bit PEB and RTL_USER_PROCESS_PARAMETERS for a WOW64 / native-x86 guest. Mirrors the
        /// x64 build in <see cref="PrepareWinEnvironment"/> using the documented x86 field offsets (32-bit
        /// pointers, UNICODE_STRING buffer at struct+4).
        /// </summary>
        private void BuildProcessEnvironment32(BinaryEmulator Instance, WinModule MainModule)
        {
            bool IsPeImage = Instance._binary.FileFormat == BinaryFormat.PE;

            // ---- PEB (32-bit) ----
            Instance._emulator.WriteMemory(PEB + 0x00, (byte)0, 1);                                  // InheritedAddressSpace
            Instance._emulator.WriteMemory(PEB + 0x01, (byte)0, 1);                                  // ReadImageFileExecOptions
            Instance._emulator.WriteMemory(PEB + 0x02, (byte)0, 1);                                  // BeingDebugged
            Instance._emulator.WriteMemory(PEB + 0x03, (byte)0, 1);                                  // BitField
            Instance._emulator.WriteMemory(PEB + 0x04, 0xFFFFFFFFu);                                 // Mutant
            Instance._emulator.WriteMemory(PEB + 0x08, (uint)MainModule.MappedBase);                 // ImageBaseAddress
            Instance._emulator.WriteMemory(PEB + 0x0C, 0u);                                          // Ldr (filled by the loader)
            Instance._emulator.WriteMemory(PEB + 0x38, (uint)ApiSetMap);                             // ApiSetMap
            Instance._emulator.WriteMemory(PEB + 0xA4, WindowsVersionInfo.MajorVersion, 4);          // OSMajorVersion
            Instance._emulator.WriteMemory(PEB + 0xA8, WindowsVersionInfo.MinorVersion, 4);          // OSMinorVersion
            Instance._emulator.WriteMemory(PEB + 0xAC, WindowsVersionInfo.BuildNumberShort, 2);      // OSBuildNumber
            Instance._emulator.WriteMemory(PEB + 0xAE, (ushort)0, 2);                                // OSCSDVersion
            Instance._emulator.WriteMemory(PEB + 0xB0, WindowsVersionInfo.PlatformIdWin32Nt, 4);     // OSPlatformId

            if (!IsPeImage && !UsesDirectBlobStartup)
            {
                Instance._emulator.WriteMemory(PEB + 0x10, 0u);                                      // ProcessParameters (none)
                return;
            }

            // ---- RTL_USER_PROCESS_PARAMETERS (32-bit) ----
            string ImagePath = ResolveGuestImagePath(Instance._binary);
            if (string.IsNullOrWhiteSpace(ImagePath))
                ImagePath = !string.IsNullOrWhiteSpace(MainModule.Path) ? MainModule.Path : (!string.IsNullOrWhiteSpace(MainModule.Name) ? MainModule.Name : "C:\\blob.bin");
            string CurrentDir = GuestDirectoryOf(ImagePath);
            string DesktopInfo = "Winsta0\\Default";
            string WindowTitle = ImagePath;
            string CommandLine = GeneralHelper.QuoteCommandLineArg(ImagePath);
            if (!string.IsNullOrWhiteSpace(Instance.RawProgramArguments))
                CommandLine += $" {Instance.RawProgramArguments}";

            static byte[] Wz(string s) => Encoding.Unicode.GetBytes(s + "\0");

            byte[] EnvBlock = BuildEnvironment(Instance, out ulong envSize);
            // Full fixed size of the 32-bit RTL_USER_PROCESS_PARAMETERS header. It must cover EVERY trailing
            // field — RedirectionDllName@0x2A4, HeapPartitionName@0x2AC, DefaultThreadpoolCpuSetMasks@0x2B4,
            // DefaultThreadpoolThreadMaximum@0x2BC, HeapMemoryTypeMask@0x2C0 (through ~0x2C4 on current builds) —
            // so the zero-fill below leaves them all NULL (their correct default) and the inline string buffers
            // that follow don't overwrite them. Previously 0x2A0, which stopped short of HeapPartitionName: the
            // CurrentDirectory buffer (written at HeaderSize) bled a path string into HeapPartitionName.Buffer
            // (0x2B0). ntdll's RtlpHpShouldEnableSegmentHeap reads a non-NULL HeapPartitionName.Buffer as "this
            // process was launched into a memory partition" and switches the process heap to the segment heap —
            // whose RtlpHpVs free-chunk RB-tree then FAST_FAIL_INVALID_BALANCED_TREE'd during heap init. A classic
            // 32-bit process has an empty HeapPartitionName and uses the NT heap; sizing the header correctly
            // restores that. 0x300 gives margin beyond the last known field and keeps the 16-byte alignment.
            ulong HeaderSize = 0x300;
            ulong TotalSize = HeaderSize + (ulong)Wz(CurrentDir).Length + (ulong)Wz(ImagePath).Length + (ulong)Wz(CommandLine).Length + (ulong)Wz(WindowTitle).Length + (ulong)Wz(DesktopInfo).Length + envSize;
            TotalSize = BinaryEmulator.AlignUp(TotalSize, 0x10);

            ProcessParams = Instance.MapUniqueAddress(TotalSize, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemory(ProcessParams, new byte[HeaderSize]);
            Instance._emulator.WriteMemory(PEB + 0x10, (uint)ProcessParams);
            ulong Cursor = ProcessParams + HeaderSize;

            void WriteInlineUnicodeString(ulong StructOffset, string Value, ushort ForcedMax = 0)
            {
                byte[] Data = Wz(Value);
                Instance._emulator.WriteMemory(Cursor, Data);
                ushort Len = (ushort)(Data.Length - 2);
                ushort Max = ForcedMax != 0 ? ForcedMax : (ushort)Data.Length;
                Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x0, Len, 2);
                Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x2, Max, 2);
                Instance._emulator.WriteMemory(ProcessParams + StructOffset + 0x4, (uint)Cursor, 4);
                Cursor += (ulong)Data.Length;
                Cursor = BinaryEmulator.AlignUp(Cursor, 2);
            }

            Instance._emulator.WriteMemory(ProcessParams + 0x08, 0x6001u, 4);                        // Flags (normalized)
            if (UsesDirectBlobStartup || (IsPeImage && Instance._binary.PE.Subsystem.HasFlag(Subsystem.WindowsCui)))
            {
                Instance._emulator.WriteMemory(ProcessParams + 0x10, (uint)WinHelper.ConsoleHandle.Handle, 4); // ConsoleHandle
                Instance._emulator.WriteMemory(ProcessParams + 0x14, 0u, 4);                          // ConsoleFlags
                Instance._emulator.WriteMemory(ProcessParams + 0x18, (uint)WinHelper.STD_IN.Handle, 4);  // StandardInput
                Instance._emulator.WriteMemory(ProcessParams + 0x1C, (uint)WinHelper.STD_OUT.Handle, 4); // StandardOutput
                Instance._emulator.WriteMemory(ProcessParams + 0x20, (uint)WinHelper.STD_OUT.Handle, 4); // StandardError
            }
            WriteInlineUnicodeString(0x24, CurrentDir, ForcedMax: 1024);                             // CurrentDirectory.DosPath
            WriteInlineUnicodeString(0x38, ImagePath);                                               // ImagePathName
            WriteInlineUnicodeString(0x40, CommandLine);                                             // CommandLine
            ulong EnvPtr = Cursor;
            Instance._emulator.WriteMemory(EnvPtr, EnvBlock);
            Instance._emulator.WriteMemory(ProcessParams + 0x48, (uint)EnvPtr, 4);                   // Environment
            Cursor += envSize;
            Cursor = BinaryEmulator.AlignUp(Cursor, 2);
            WriteInlineUnicodeString(0x70, WindowTitle);                                             // WindowTitle
            WriteInlineUnicodeString(0x78, DesktopInfo);                                             // DesktopInfo
            Instance._emulator.WriteMemory(ProcessParams + 0x290, (uint)envSize, 4);                 // EnvironmentSize

            uint Used = (uint)(Cursor - ProcessParams);
            uint Length = Used < (uint)HeaderSize ? (uint)HeaderSize : Used;
            Instance._emulator.WriteMemory(ProcessParams + 0x0, (uint)TotalSize, 4);                 // MaximumLength
            Instance._emulator.WriteMemory(ProcessParams + 0x4, Length, 4);                          // Length

            SetupCsrReadOnlySharedSection32(Instance);
        }

        /// <summary>
        /// Creates the CSR read-only shared section that the kernel maps into every process and wires the three
        /// 32-bit PEB fields kernelbase reads to locate <c>BASE_STATIC_SERVER_DATA</c>. During its own DllMain
        /// (BaseDllInitialize) the WOW64 kernelbase computes the client-side BSSD pointer with the classic CSR
        /// remap <c>BSSD = ReadOnlyStaticServerData[1] - ServerSharedBase + ReadOnlySharedMemoryBase</c>:
        /// <list type="bullet">
        ///   <item><c>PEB+0x4C ReadOnlySharedMemoryBase</c> = client view base of the section.</item>
        ///   <item><c>PEB+0x54 ReadOnlyStaticServerData</c> = the section's server-data pointer descriptor, whose
        ///         <c>+0x8</c> slot holds the (server-view) BSSD pointer — that descriptor is exactly the
        ///         <c>Base+0x10</c> block <see cref="NtMapViewOfSection.InitializeWindowsSharedSection"/> lays
        ///         down, whose <c>+0x8</c> already points at BSSD (<c>Base+0x1000</c>).</item>
        ///   <item><c>PEB+0x248</c> = server-view base of the section, subtracted in the remap.</item>
        /// </list>
        /// Because Brovan has no separate csrss address space, the server view and the client view are the same
        /// mapping, so the server base equals the client base and the remap is the identity — the descriptor's
        /// absolute BSSD pointer resolves to itself. Without this, all three fields are NULL, kernelbase reads
        /// <c>[NULL+8]</c> during init, faults, and BaseDllInitialize returns FALSE → STATUS_DLL_INIT_FAILED.
        /// x64 guests reach BSSD through the CSR port connect reply instead, so this is the WOW64 path only.
        /// </summary>
        private void SetupCsrReadOnlySharedSection32(BinaryEmulator Instance)
        {
            const ulong SharedSectionSize = 0x10000;
            ulong Base = Instance.MapUniqueAddress(SharedSectionSize, MemoryProtection.ReadWrite);
            if (Base == 0)
                return;

            NtMapViewOfSection.InitializeWindowsSharedSection(Instance, Base);

            Instance._emulator.WriteMemory(PEB + 0x4C, (uint)Base, 4);          // ReadOnlySharedMemoryBase (client base)
            Instance._emulator.WriteMemory(PEB + 0x54, (uint)(Base + 0x10), 4); // ReadOnlyStaticServerData (server-data descriptor)
            Instance._emulator.WriteMemory(PEB + 0x248, (uint)Base, 4);         // server-view base (identity → remap is a no-op)
        }

        /// <summary>
        /// Sets up the WOW64 system-call transition for a 32-bit guest. Maps a tiny trampoline that runs a
        /// <c>sysenter</c> (which Brovan intercepts and dispatches through <see cref="TryHandleSyscall"/>) and
        /// points ntdll's <c>Wow64Transition</c> global — and, per-thread, the TEB's <c>WOW32Reserved</c>
        /// (fs:[0xC0]) — at it. The 32-bit ntdll Nt* stubs reach the kernel through this pointer rather than a
        /// native <c>syscall</c> instruction, so this is the single interception point for every x86 syscall.
        /// The trampoline pops the stub return address so the syscall stack frame the C# handler sees matches
        /// the classic x86 convention (ESP → caller return address, args at ESP+4).
        /// </summary>
        private void SetupWow64SyscallTransition(BinaryEmulator Instance)
        {
            if (_wow64SyscallTrampoline != 0)
                return;

            // pop edx ; sysenter ; push edx ; ret  — pop discards the ntdll-stub return address that
            // `call fs:[0xC0]` / `jmp [Wow64Transition]` left on top, so at the sysenter the guest ESP points
            // at the ORIGINAL caller's return address with the syscall arguments immediately above it (ESP+4,
            // ESP+8, …) — exactly what GetArg32 / ReadWindowsSyscallArguments expect. push restores it so the
            // final ret returns into the stub's `ret N`, which cleans the stdcall arguments.
            byte[] Trampoline = { 0x5A, 0x0F, 0x34, 0x52, 0xC3 };
            ulong TrampolinePage = Instance.MapUniqueAddress(0x1000, MemoryProtection.ReadExecute);
            Instance._emulator.WriteMemory(TrampolinePage, Trampoline);
            _wow64SyscallTrampoline = TrampolinePage;

            // Point ntdll's Wow64Transition global at the trampoline. The Nt* stub variant
            // `mov edx, Wow64SystemServiceCall ; call edx` reaches `jmp [Wow64Transition]`; both the direct
            // fs:[0xC0] call and this indirect path must land on the trampoline.
            if (_ntdllModule != null && _ntdllModule.ExportsByName != null &&
                _ntdllModule.ExportsByName.TryGetValue("Wow64Transition", out ulong TransitionRva) && TransitionRva != 0)
            {
                ulong TransitionVa = Instance.TranslateVirtualAddress(TransitionRva, "ntdll.dll");
                if (TransitionVa != 0)
                    Instance._emulator.WriteMemory(TransitionVa, (uint)_wow64SyscallTrampoline);
            }
        }

        /// <summary>
        /// Allocates (once per process) the WOW64INFO structure and records its guest address in
        /// <see cref="_wow64InfoPtr"/>. <see cref="AllocateAndInitializeTEB"/> then writes that pointer into
        /// every 32-bit thread's TEB at TlsSlots[WOW64_TLS_WOW64INFO] (0xE38). On a real WOW64 process this is
        /// wow64.dll's job, done before the 32-bit ntdll executes; the pure-32-bit model has no wow64.dll, so
        /// without this the 32-bit ntdll's CPU-feature init dereferences a NULL TlsSlots[10] and raises an
        /// access violation that fails process init (STATUS_APP_INIT_FAILURE).
        ///
        /// ntdll reads (SysWOW64\ntdll RVA 0xAA872 and 0x9E5B4, cross-checked against the x64 sibling at
        /// RVA 0xC5792 which NULL-guards the same slot):
        ///   +0x00 NativeSystemPageSize — bit-scanned into the cached page shift (0x1000 → shift 12).
        ///   +0x04 CpuFlags — bit 0x2 gated: SET routes RtlQueryPerformanceCounter through the syscall
        ///                    transition (NtQueryPerformanceCounter, which Brovan services); CLEAR takes the
        ///                    legacy `int 0x81` WOW64 fast-syscall path Brovan does not implement.
        ///   +0x20 NativeMachine   (USHORT) — matched against machine types by the x64 sibling.
        ///   +0x22 EmulatedMachine (USHORT).
        /// </summary>
        private void SetupWow64Info(BinaryEmulator Instance)
        {
            if (_wow64InfoPtr != 0)
                return;

            const int Wow64InfoSize = 0x40;                 // >= 0x24 (last field EmulatedMachine@0x22); page-rounded by the allocator.
            const ushort ImageFileMachineAmd64 = 0x8664;    // native machine of the x64 host running WOW64.
            const ushort ImageFileMachineI386 = 0x014C;     // emulated machine of the 32-bit process.
            const uint CpuFlagsUseSyscallQpc = 0x2;         // bit 0x2 → syscall QPC path (not the `int 0x81` fast path).
            const uint NativeSystemPageSize = 0x1000;       // x64 host native page size = 4096 (ntdll bit-scans it → page shift 12).

            ulong Block = Instance.MapUniqueAddress(Wow64InfoSize, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemory(Block, new byte[Wow64InfoSize]);
            Instance._emulator.WriteMemory(Block + 0x00, NativeSystemPageSize);          // NativeSystemPageSize (0x1000 → page shift 12)
            Instance._emulator.WriteMemory(Block + 0x04, CpuFlagsUseSyscallQpc);         // CpuFlags
            Instance._emulator.WriteMemory(Block + 0x20, ImageFileMachineAmd64, 2);      // NativeMachine
            Instance._emulator.WriteMemory(Block + 0x22, ImageFileMachineI386, 2);       // EmulatedMachine
            _wow64InfoPtr = Block;
        }

        /// <summary>
        /// Installs (once) a 32-bit GDT and points the FS segment at the given TEB. In MODE_32 the FS_BASE
        /// pseudo-register is a no-op, so the FS base has to be programmed through a real GDT descriptor
        /// (selector 0x53, the WOW64 TEB selector) reached via GDTR. On every thread switch the FS descriptor's
        /// base is rewritten to that thread's TEB and FS is reloaded so the hidden base is refreshed.
        /// CS/DS/ES/SS are left at the flat MODE_32 defaults (base 0) — Unicorn faults on a mid-run CS reload,
        /// and a flat data/code model is already correct for a 32-bit process.
        /// </summary>
        private void SetupWow64Segments(BinaryEmulator Instance, ulong Teb)
        {
            static ulong MakeDescriptor(uint Base, uint Limit, byte Access, byte Flags)
            {
                ulong D = Limit & 0xFFFFUL;
                D |= (ulong)(Base & 0xFFFFFFU) << 16;
                D |= (ulong)Access << 40;
                D |= (ulong)((Limit >> 16) & 0xF) << 48;
                D |= (ulong)(Flags & 0xF) << 52;
                D |= (ulong)((Base >> 24) & 0xFF) << 56;
                return D;
            }

            const byte AccessDpl0Code = 0x9A;    // present, DPL0, code, readable
            const byte AccessDpl0Data = 0x92;    // present, DPL0, data, writable
            const byte Flags4KB32 = 0xC;         // 4KB granularity, 32-bit

            if (_gdt32Base == 0)
            {
                _gdt32Base = Instance.MapUniqueAddress(0x1000, MemoryProtection.ReadWrite);
                Instance._emulator.WriteMemory(_gdt32Base, new byte[0x1000]);
                // Flat code / data descriptors. Loading a custom GDTR turns the default SS=0 into a null
                // selector (stack pushes then #GP), so SS/DS/ES must be reloaded with valid flat selectors.
                Instance._emulator.WriteMemory(_gdt32Base + Wow64CodeGdtIndex * 8, MakeDescriptor(0, 0xFFFFF, AccessDpl0Code, Flags4KB32), 8);
                Instance._emulator.WriteMemory(_gdt32Base + Wow64DataGdtIndex * 8, MakeDescriptor(0, 0xFFFFF, AccessDpl0Data, Flags4KB32), 8);
                Instance._emulator.WriteGdtr(_gdt32Base, 0x1000 - 1);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_SS, Wow64DataSelector);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_DS, Wow64DataSelector);
                Instance._emulator.WriteRegister(Registers.UC_X86_REG_ES, Wow64DataSelector);
                // CS is left at the flat MODE_32 default (Unicorn faults on a mid-run CS reload); flat code
                // fetch is already correct.
            }

            // (Re)write the FS descriptor with this thread's TEB base, then reload FS so the cached base updates.
            Instance._emulator.WriteMemory(_gdt32Base + Wow64FsGdtIndex * 8, MakeDescriptor((uint)Teb, 0xFFFFF, AccessDpl0Data, Flags4KB32), 8);
            Instance._emulator.WriteRegister(Registers.UC_X86_REG_FS, Wow64FsSelector);
        }

        /// <summary>
        /// Builds a 32-bit CONTEXT record in guest memory for the initial user thread. On x86, ntdll's
        /// LdrInitializeThunk finishes process init and NtContinue's to this context, whose Eip is
        /// RtlUserThreadStart with Eax = thread entry and Ebx = parameter (the x86 RtlUserThreadStart ABI).
        /// </summary>
        private ulong BuildInitialContext32(BinaryEmulator Instance, ulong Eip, ulong Esp, ulong Eax, ulong Ebx)
        {
            const uint CONTEXT_i386 = 0x00010000;
            const uint CONTEXT_CONTROL = 0x1;
            const uint CONTEXT_INTEGER = 0x2;
            const uint CONTEXT_SEGMENTS = 0x4;

            ulong ContextSize = 0x2CC;                                   // sizeof(CONTEXT) on x86
            ulong ContextAddress = Instance.MapUniqueAddress(ContextSize, MemoryProtection.ReadWrite);
            Instance._emulator.WriteMemory(ContextAddress, new byte[ContextSize]);
            Instance._emulator.WriteMemory(ContextAddress + 0x00, CONTEXT_i386 | CONTEXT_CONTROL | CONTEXT_INTEGER | CONTEXT_SEGMENTS, 4); // ContextFlags
            Instance._emulator.WriteMemory(ContextAddress + 0x8C, 0x0000u, 4);   // SegGs
            Instance._emulator.WriteMemory(ContextAddress + 0x90, 0x0053u, 4);   // SegFs
            Instance._emulator.WriteMemory(ContextAddress + 0x94, 0x002Bu, 4);   // SegEs
            Instance._emulator.WriteMemory(ContextAddress + 0x98, 0x002Bu, 4);   // SegDs
            Instance._emulator.WriteMemory(ContextAddress + 0xA4, (uint)Ebx, 4); // Ebx
            Instance._emulator.WriteMemory(ContextAddress + 0xB0, (uint)Eax, 4); // Eax
            Instance._emulator.WriteMemory(ContextAddress + 0xB8, (uint)Eip, 4); // Eip
            Instance._emulator.WriteMemory(ContextAddress + 0xBC, 0x0023u, 4);   // SegCs
            Instance._emulator.WriteMemory(ContextAddress + 0xC0, 0x0202u, 4);   // EFlags
            Instance._emulator.WriteMemory(ContextAddress + 0xC4, (uint)Esp, 4); // Esp
            Instance._emulator.WriteMemory(ContextAddress + 0xC8, 0x002Bu, 4);   // SegSs
            return ContextAddress;
        }

        /// <summary>
        /// Installs a minimal PEB loader list for direct raw-blob starts where ntdll's loader entry path is intentionally skipped.
        /// </summary>
        /// <param name="Instance">The emulator instance.</param>
        private void InstallSyntheticLdrData(BinaryEmulator Instance)
        {
            if (WinHelper == null || WinHelper.WinModules.Count == 0)
                return;

            if (Instance._binary.Architecture == BinaryArchitecture.x64)
                InstallSyntheticLdrData64(Instance);
            else
                InstallSyntheticLdrData32(Instance);
        }

        private void InstallSyntheticLdrData64(BinaryEmulator Instance)
        {
            const uint LdrSize = 0x58;
            const uint EntrySize = 0x120;
            ulong LdrData = Instance.MapUniqueAddress(LdrSize, MemoryProtection.ReadWrite);
            if (LdrData == 0)
                return;

            Instance._emulator.WriteMemoryByte(LdrData, 0, LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x0, (uint)LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x4, (byte)1, 1);

            List<ulong> Entries = new List<ulong>();
            foreach (WinModule Module in WinHelper.WinModules)
            {
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong Entry = Instance.MapUniqueAddress(EntrySize, MemoryProtection.ReadWrite);
                if (Entry == 0)
                    continue;

                Instance._emulator.WriteMemoryByte(Entry, 0, EntrySize);
                Instance._emulator.WriteMemory(Entry + 0x30, Module.MappedBase, 8);
                Instance._emulator.WriteMemory(Entry + 0x38, Module.EntryPoint, 8);
                Instance._emulator.WriteMemory(Entry + 0x40, (uint)Math.Min(Module.SizeOfImage, uint.MaxValue), 4);
                WriteUnicodeString64(Instance, Entry + 0x48, !string.IsNullOrWhiteSpace(Module.Path) ? Module.Path : GetModuleName(Module));
                WriteUnicodeString64(Instance, Entry + 0x58, GetModuleName(Module));
                Instance._emulator.WriteMemory(Entry + 0x68, 0x000022CCu, 4);
                Entries.Add(Entry);
            }

            LinkLdrList64(Instance, LdrData + 0x10, Entries, 0x00);
            LinkLdrList64(Instance, LdrData + 0x20, Entries, 0x10);
            LinkLdrList64(Instance, LdrData + 0x30, Entries, 0x20);
            Instance._emulator.WriteMemory(PEB + 0x18, LdrData, 8);
        }

        private void InstallSyntheticLdrData32(BinaryEmulator Instance)
        {
            const uint LdrSize = 0x30;
            const uint EntrySize = 0x80;
            ulong LdrData = Instance.MapUniqueAddress(LdrSize, MemoryProtection.ReadWrite);
            if (LdrData == 0)
                return;

            Instance._emulator.WriteMemoryByte(LdrData, 0, LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x0, (uint)LdrSize);
            Instance._emulator.WriteMemory(LdrData + 0x4, (byte)1, 1);

            List<ulong> Entries = new List<ulong>();
            foreach (WinModule Module in WinHelper.WinModules)
            {
                if (Module == null || Module.MappedBase == 0 || Module.SizeOfImage == 0)
                    continue;

                ulong Entry = Instance.MapUniqueAddress(EntrySize, MemoryProtection.ReadWrite);
                if (Entry == 0)
                    continue;

                Instance._emulator.WriteMemoryByte(Entry, 0, EntrySize);
                Instance._emulator.WriteMemory(Entry + 0x18, (uint)Module.MappedBase);
                Instance._emulator.WriteMemory(Entry + 0x1C, (uint)Module.EntryPoint);
                Instance._emulator.WriteMemory(Entry + 0x20, (uint)Math.Min(Module.SizeOfImage, uint.MaxValue));
                WriteUnicodeString32(Instance, Entry + 0x24, !string.IsNullOrWhiteSpace(Module.Path) ? Module.Path : GetModuleName(Module));
                WriteUnicodeString32(Instance, Entry + 0x2C, GetModuleName(Module));
                Instance._emulator.WriteMemory(Entry + 0x34, 0x000022CCu);
                Entries.Add(Entry);
            }

            LinkLdrList32(Instance, LdrData + 0x0C, Entries, 0x00);
            LinkLdrList32(Instance, LdrData + 0x14, Entries, 0x08);
            LinkLdrList32(Instance, LdrData + 0x1C, Entries, 0x10);
            Instance._emulator.WriteMemory(PEB + 0x0C, (uint)LdrData);
        }

        private static string GetModuleName(WinModule Module)
        {
            if (!string.IsNullOrWhiteSpace(Module.Name))
                return Module.Name;

            if (!string.IsNullOrWhiteSpace(Module.Path))
                return Path.GetFileName(Module.Path);

            return "module.bin";
        }

        private void LinkLdrList64(BinaryEmulator Instance, ulong Head, List<ulong> Entries, ulong LinkOffset)
        {
            if (Entries.Count == 0)
            {
                Instance._emulator.WriteMemory(Head + 0x0, Head, 8);
                Instance._emulator.WriteMemory(Head + 0x8, Head, 8);
                return;
            }

            for (int i = 0; i < Entries.Count; i++)
            {
                ulong Current = Entries[i] + LinkOffset;
                ulong Next = i + 1 < Entries.Count ? Entries[i + 1] + LinkOffset : Head;
                ulong Previous = i == 0 ? Head : Entries[i - 1] + LinkOffset;
                Instance._emulator.WriteMemory(Current + 0x0, Next, 8);
                Instance._emulator.WriteMemory(Current + 0x8, Previous, 8);
            }

            Instance._emulator.WriteMemory(Head + 0x0, Entries[0] + LinkOffset, 8);
            Instance._emulator.WriteMemory(Head + 0x8, Entries[^1] + LinkOffset, 8);
        }

        private void LinkLdrList32(BinaryEmulator Instance, ulong Head, List<ulong> Entries, ulong LinkOffset)
        {
            if (Entries.Count == 0)
            {
                Instance._emulator.WriteMemory(Head + 0x0, (uint)Head);
                Instance._emulator.WriteMemory(Head + 0x4, (uint)Head);
                return;
            }

            for (int i = 0; i < Entries.Count; i++)
            {
                ulong Current = Entries[i] + LinkOffset;
                ulong Next = i + 1 < Entries.Count ? Entries[i + 1] + LinkOffset : Head;
                ulong Previous = i == 0 ? Head : Entries[i - 1] + LinkOffset;
                Instance._emulator.WriteMemory(Current + 0x0, (uint)Next);
                Instance._emulator.WriteMemory(Current + 0x4, (uint)Previous);
            }

            Instance._emulator.WriteMemory(Head + 0x0, (uint)(Entries[0] + LinkOffset));
            Instance._emulator.WriteMemory(Head + 0x4, (uint)(Entries[^1] + LinkOffset));
        }

        private void WriteUnicodeString64(BinaryEmulator Instance, ulong Address, string Value)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            ulong Buffer = Instance.MapUniqueAddress(Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 2)), MemoryProtection.ReadWrite);
            if (Buffer == 0)
                return;

            Instance._emulator.WriteMemory(Buffer, Data);
            Instance._emulator.WriteMemory(Address + 0x0, (ushort)Math.Max(0, Data.Length - 2), 2);
            Instance._emulator.WriteMemory(Address + 0x2, (ushort)Data.Length, 2);
            Instance._emulator.WriteMemory(Address + 0x8, Buffer, 8);
        }

        private void WriteUnicodeString32(BinaryEmulator Instance, ulong Address, string Value)
        {
            byte[] Data = Encoding.Unicode.GetBytes((Value ?? string.Empty) + "\0");
            ulong Buffer = Instance.MapUniqueAddress(Instance.AlignToPageSize((ulong)Math.Max(Data.Length, 2)), MemoryProtection.ReadWrite);
            if (Buffer == 0)
                return;

            Instance._emulator.WriteMemory(Buffer, Data);
            Instance._emulator.WriteMemory(Address + 0x0, (ushort)Math.Max(0, Data.Length - 2), 2);
            Instance._emulator.WriteMemory(Address + 0x2, (ushort)Data.Length, 2);
            Instance._emulator.WriteMemory(Address + 0x4, (uint)Buffer);
        }

        private void LoadNtdll(BinaryEmulator Instance)
        {
            try
            {
                if (Instance._binary.Location == null && !UsesDirectBlobStartup)
                    return;

                string NtdllPath = Instance._binary.Architecture == BinaryArchitecture.x64
                    ? GeneralHelper.GetWindowsLibPath("ntdll.dll")
                    : GeneralHelper.GetWindowsLibPath("ntdll.dll", true, BinaryArchitecture.x86);

                if (!File.Exists(NtdllPath))
                {
                    string CurrentPathNtdll = Path.Combine(AppContext.BaseDirectory, "ntdll.dll");
                    if (File.Exists(CurrentPathNtdll))
                        NtdllPath = CurrentPathNtdll;
                }

                if (!File.Exists(NtdllPath))
                {
                    Instance.TriggerEventMessage("[-] ntdll.dll was not found for emulation.", LogFlags.Issues);
                    Utils.LogError("Couldn't find ntdll.dll for the windows guest environment.");
                    return;
                }

                using (BinaryFile Library = new BinaryFile(NtdllPath, true))
                {
                    _ntdllModule = Instance.LoadWinLibrary(Library, true, MapBySections: false);
                }
            }
            catch (Exception ex)
            {
                Utils.LogError($"Error while handling ntdll.dll loading for emulation: {ex.Message}");
            }
        }
    }
}
