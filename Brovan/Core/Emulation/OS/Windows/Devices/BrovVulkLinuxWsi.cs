using System;
using System.Runtime.InteropServices;

namespace Brovan.Core.Emulation.OS.Windows
{
    internal static class BrovVulkLinuxWsi
    {
        internal const int VkStructureTypeXcbSurfaceCreateInfoKHR = 1000005000;

        [DllImport("vulkan-1.dll", EntryPoint = "vkCreateXcbSurfaceKHR", CallingConvention = CallingConvention.Winapi)]
        internal static extern int vkCreateXcbSurfaceKHR(IntPtr instance, IntPtr pCreateInfo, IntPtr pAllocator, IntPtr pSurface);

        [DllImport("libX11-xcb.so.1", EntryPoint = "XGetXCBConnection")]
        internal static extern IntPtr XGetXCBConnection(IntPtr display);
    }
}
