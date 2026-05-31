namespace Brovan.Core.Emulation.OS.Windows.Win32k
{
    internal class NtGdiInit2 : IWinSyscall
    {
        private static readonly NtGdiInit Handler = new NtGdiInit();

        public NTSTATUS Handle(BinaryEmulator Instance)
        {
            return Handler.Handle(Instance);
        }
    }
}