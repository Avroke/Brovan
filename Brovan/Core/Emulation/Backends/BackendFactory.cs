namespace Brovan.Core.Emulation
{
    public static class BackendFactory
    {
        public static IEmulationBackend Create(EmulationBackendKind kind, Arch arch, Mode mode, bool noHooks)
        {
            IEmulationBackend backend = kind switch
            {
                EmulationBackendKind.Unicorn => new UnicornBackend(arch, mode),
                EmulationBackendKind.Kvm => new KvmBackend(arch, mode),
                EmulationBackendKind.Whp => new WhpBackend(arch, mode),
                _ => throw new System.ArgumentOutOfRangeException(nameof(kind), kind, "Unknown emulation backend."),
            };

            backend.NoHooks = noHooks;
            return backend;
        }
    }
}
