using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    internal sealed class WindowsWinManager : IDisplayConnection, ITextRenderSupport, ITextMetricsSupport
    {
        private static readonly object WindowSync = new();
        private static readonly Dictionary<IntPtr, WindowsWindow> Windows = new();

        private static readonly WindowProcDelegate WindowProcHandler = WindowProc;
        private static readonly IntPtr WindowProcPointer = Marshal.GetFunctionPointerForDelegate(WindowProcHandler);

        private static readonly object MetricsLock = new();
        private static IntPtr _metricsDc = IntPtr.Zero;
        private static IntPtr _metricsFont = IntPtr.Zero;
        private static IntPtr _metricsPreviousFont = IntPtr.Zero;

        private static int _pendingHostRepaint;

        public static bool ConsumePendingHostRepaint()
        {
            return Interlocked.Exchange(ref _pendingHostRepaint, 0) != 0;
        }

        private readonly IntPtr _instanceHandle;
        private readonly string _className;
        private bool _disposed;

        private const int GWL_STYLE = -16;
        private const int GWL_EXSTYLE = -20;

        private const uint WM_DESTROY = 0x0002;
        private const uint WM_CLOSE = 0x0010;
        private const uint WM_ERASEBKGND = 0x0014;
        private const uint WM_SIZE = 0x0005;
        private const uint WM_PAINT = 0x000F;
        private const uint WM_SHOWWINDOW = 0x0018;
        private const uint WM_SETTEXT = 0x000C;
        private const uint WM_GETTEXT = 0x000D;
        private const uint WM_GETTEXTLENGTH = 0x000E;

        private const uint WS_OVERLAPPEDWINDOW = 0x00CF0000;
        private const uint WS_POPUP = 0x80000000;
        private const uint WS_VISIBLE = 0x10000000;
        private const uint WS_CAPTION = 0x00C00000;
        private const uint WS_THICKFRAME = 0x00040000;
        private const uint WS_MINIMIZEBOX = 0x00020000;
        private const uint WS_MAXIMIZEBOX = 0x00010000;
        private const uint WS_SYSMENU = 0x00080000;

        private const int SW_HIDE = 0;
        private const int SW_SHOWNORMAL = 1;
        private const int SW_SHOW = 5;
        private const int SW_MINIMIZE = 6;
        private const int SW_MAXIMIZE = 3;
        private const int SW_RESTORE = 9;

        private const uint PM_REMOVE = 0x0001;

        private const uint SWP_NOSIZE = 0x0001;
        private const uint SWP_NOMOVE = 0x0002;
        private const uint SWP_NOZORDER = 0x0004;
        private const uint SWP_NOACTIVATE = 0x0010;
        private const uint SWP_FRAMECHANGED = 0x0020;

        public WindowsWinManager()
        {
            if (!GeneralHelper.IsWindows)
                throw new PlatformNotSupportedException("Windows window manager needs to be used on a Windows system.");

            _instanceHandle = GetModuleHandleW(null);
            _className = $"BrovanWindow_{Guid.NewGuid():N}";
            RegisterWindowClass();
        }

        public bool IsConnected => !_disposed;

        public IntPtr NativeHandle => IntPtr.Zero;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(WindowsWinManager));

            options = Normalize(options ?? new WindowOptions());

            uint style = options.Decorated ? WS_OVERLAPPEDWINDOW : WS_POPUP;
            if (options.Visible)
                style |= WS_VISIBLE;

            if (!options.Resizable)
                style &= ~(WS_THICKFRAME | WS_MAXIMIZEBOX | WS_MINIMIZEBOX);

            int requestedClientWidth = Math.Max(options.Width, 1);
            int requestedClientHeight = Math.Max(options.Height, 1);
            ResolveOuterFromClient(style, 0, requestedClientWidth, requestedClientHeight, out int outerWidth, out int outerHeight);

            IntPtr hwnd = CreateWindowExW(
                0,
                _className,
                string.IsNullOrWhiteSpace(options.Title) ? string.Empty : options.Title,
                style,
                options.X,
                options.Y,
                outerWidth,
                outerHeight,
                IntPtr.Zero,
                IntPtr.Zero,
                _instanceHandle,
                IntPtr.Zero);

            if (hwnd == IntPtr.Zero)
                throw new InvalidOperationException("CreateWindowExW failed.");

            WindowsWindow window = new(this, hwnd, options);
            lock (WindowSync)
                Windows[hwnd] = window;

            ApplyInitialState(window, options);
            return window;
        }

        public void PumpEvents()
        {
            if (_disposed)
                return;

            while (PeekMessageW(out MSG msg, IntPtr.Zero, 0, 0, PM_REMOVE))
            {
                if (msg.message == 0x0012)
                {
                    _disposed = true;
                    break;
                }

                TranslateMessage(ref msg);
                DispatchMessageW(ref msg);
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            WindowsWindow[] windows;
            lock (WindowSync)
            {
                windows = new WindowsWindow[Windows.Values.Count];
                Windows.Values.CopyTo(windows, 0);
                Windows.Clear();
            }

            foreach (WindowsWindow window in windows)
                window.Dispose();
        }

        private void RegisterWindowClass()
        {
            WNDCLASSEXW wndClass = new()
            {
                cbSize = (uint)Marshal.SizeOf<WNDCLASSEXW>(),
                style = 0,
                lpfnWndProc = WindowProcPointer,
                cbClsExtra = 0,
                cbWndExtra = 0,
                hInstance = _instanceHandle,
                hIcon = IntPtr.Zero,
                hCursor = IntPtr.Zero,
                hbrBackground = (IntPtr)6,
                lpszMenuName = null,
                lpszClassName = _className,
                hIconSm = IntPtr.Zero,
            };

            if (RegisterClassExW(ref wndClass) == 0)
                throw new InvalidOperationException("RegisterClassExW failed.");
        }

        private static WindowOptions Normalize(WindowOptions options)
        {
            options ??= new WindowOptions();
            if (options.Width <= 0)
                options = options with { Width = 800 };

            if (options.Height <= 0)
                options = options with { Height = 600 };

            return options;
        }

        private static void ApplyInitialState(WindowsWindow window, WindowOptions options)
        {
            if (options.Center)
            {
                CenterWindow(window);
            }

            window.State = options.State;

            if (!options.Visible)
                window.Hide();
        }

        private static void CenterWindow(WindowsWindow window)
        {
            RECT rect;
            if (!GetWindowRect(window.NativeHandle, out rect))
                return;

            int width = rect.Right - rect.Left;
            int height = rect.Bottom - rect.Top;
            int screenWidth = GetSystemMetrics(0);
            int screenHeight = GetSystemMetrics(1);

            int x = Math.Max((screenWidth - width) / 2, 0);
            int y = Math.Max((screenHeight - height) / 2, 0);

            SetWindowPos(window.NativeHandle, IntPtr.Zero, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE);
        }

        private static IntPtr WindowProc(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam)
        {
            lock (WindowSync)
            {
                if (Windows.TryGetValue(hwnd, out WindowsWindow? window))
                    return window.HandleMessage(msg, wParam, lParam);
            }

            return DefWindowProcW(hwnd, msg, wParam, lParam);
        }

        internal static bool CloseWindowHandle(IntPtr hwnd)
        {
            if (hwnd == IntPtr.Zero)
                return false;

            bool removed;
            lock (WindowSync)
            {
                removed = Windows.Remove(hwnd);
            }

            if (!removed)
                return false;

            return DestroyWindowNative(hwnd);
        }

        internal void RemoveWindow(IntPtr hwnd)
        {
            lock (WindowSync)
                Windows.Remove(hwnd);
        }

        internal void UpdateWindowText(IntPtr hwnd, string text)
        {
            SetWindowTextW(hwnd, text ?? string.Empty);
        }

        internal void UpdateWindowSize(IntPtr hwnd, int width, int height)
        {
            RECT rect;
            if (!GetWindowRect(hwnd, out rect))
                return;

            uint style = (uint)GetWindowLongPtrW(hwnd, GWL_STYLE).ToInt64();
            uint exStyle = (uint)GetWindowLongPtrW(hwnd, GWL_EXSTYLE).ToInt64();
            ResolveOuterFromClient(style, exStyle, Math.Max(width, 1), Math.Max(height, 1), out int outerWidth, out int outerHeight);

            SetWindowPos(hwnd, IntPtr.Zero, rect.Left, rect.Top, outerWidth, outerHeight, SWP_NOZORDER | SWP_NOACTIVATE);
        }

        private static void ResolveOuterFromClient(uint style, uint exStyle, int clientWidth, int clientHeight, out int outerWidth, out int outerHeight)
        {
            RECT rect = new RECT { Left = 0, Top = 0, Right = clientWidth, Bottom = clientHeight };
            if (AdjustWindowRectEx(ref rect, style, false, exStyle))
            {
                outerWidth = Math.Max(rect.Right - rect.Left, 1);
                outerHeight = Math.Max(rect.Bottom - rect.Top, 1);
                return;
            }

            outerWidth = Math.Max(clientWidth, 1);
            outerHeight = Math.Max(clientHeight, 1);
        }

        internal void UpdateWindowVisibility(IntPtr hwnd, bool visible)
        {
            ShowWindow(hwnd, visible ? SW_SHOW : SW_HIDE);
        }

        internal void UpdateWindowState(IntPtr hwnd, WindowState state)
        {
            switch (state)
            {
                case WindowState.Minimized:
                    ShowWindow(hwnd, SW_MINIMIZE);
                    break;
                case WindowState.Maximized:
                    ShowWindow(hwnd, SW_MAXIMIZE);
                    break;
                case WindowState.Fullscreen:
                    ShowWindow(hwnd, SW_MAXIMIZE);
                    break;
                default:
                    ShowWindow(hwnd, SW_RESTORE);
                    break;
            }
        }

        internal void ApplyDecorations(IntPtr hwnd, bool decorated, bool resizable)
        {
            long style = GetWindowLongPtrW(hwnd, GWL_STYLE).ToInt64();

            if (decorated)
                style |= (long)WS_OVERLAPPEDWINDOW;
            else
                style &= ~((long)WS_CAPTION | (long)WS_THICKFRAME | (long)WS_MINIMIZEBOX | (long)WS_MAXIMIZEBOX | (long)WS_SYSMENU);

            if (resizable)
                style |= (long)(WS_THICKFRAME | WS_MINIMIZEBOX | WS_MAXIMIZEBOX);
            else
                style &= ~((long)WS_THICKFRAME | (long)WS_MINIMIZEBOX | (long)WS_MAXIMIZEBOX);

            SetWindowLongPtrW(hwnd, GWL_STYLE, new IntPtr(style));
            SetWindowPos(hwnd, IntPtr.Zero, 0, 0, 0, 0, SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_FRAMECHANGED);
        }

        public void RenderText(IntPtr windowHandle, string text, int x, int y, int rectLeft, int rectTop, int rectRight, int rectBottom, uint options)
        {
            if (windowHandle == IntPtr.Zero || string.IsNullOrEmpty(text))
                return;

            IntPtr hdc = GetDC(windowHandle);
            if (hdc == IntPtr.Zero)
                return;

            IntPtr stockFont = GetStockObject(STOCK_OBJECT_DEFAULT_GUI_FONT);
            IntPtr previousFont = stockFont != IntPtr.Zero ? SelectObject(hdc, stockFont) : IntPtr.Zero;

            SetTextColor(hdc, 0x00000000);
            SetBkMode(hdc, 1);

            RECT rect = new RECT { Left = rectLeft, Top = rectTop, Right = rectRight, Bottom = rectBottom };
            ExtTextOutW(hdc, x, y, options, ref rect, text, (uint)text.Length, IntPtr.Zero);

            if (previousFont != IntPtr.Zero)
                SelectObject(hdc, previousFont);

            ReleaseDC(windowHandle, hdc);
        }

        public bool MeasureText(string text, out int width, out int height)
        {
            width = 0;
            height = 0;

            if (text == null)
                text = string.Empty;

            lock (MetricsLock)
            {
                IntPtr hdc = EnsureMetricsDc();
                if (hdc == IntPtr.Zero)
                    return false;

                if (!GetTextExtentPoint32W(hdc, text, text.Length, out SIZE size))
                    return false;

                width = size.cx;
                height = size.cy;
            }

            if (text.Length == 0)
            {
                if (GetTextMetrics(out TextMetricsData metrics))
                    height = metrics.Height;
            }

            return true;
        }

        public bool GetTextMetrics(out TextMetricsData metrics)
        {
            metrics = default;

            lock (MetricsLock)
            {
                IntPtr hdc = EnsureMetricsDc();
                if (hdc == IntPtr.Zero)
                    return false;

                if (!GetTextMetricsW(hdc, out TEXTMETRICW native))
                    return false;

                metrics.Height = native.tmHeight;
                metrics.Ascent = native.tmAscent;
                metrics.Descent = native.tmDescent;
                metrics.InternalLeading = native.tmInternalLeading;
                metrics.ExternalLeading = native.tmExternalLeading;
                metrics.AveCharWidth = native.tmAveCharWidth;
                metrics.MaxCharWidth = native.tmMaxCharWidth;
                metrics.Weight = native.tmWeight;
                metrics.Overhang = native.tmOverhang;
                metrics.DigitizedAspectX = native.tmDigitizedAspectX;
                metrics.DigitizedAspectY = native.tmDigitizedAspectY;
                metrics.FirstChar = native.tmFirstChar;
                metrics.LastChar = native.tmLastChar;
                metrics.DefaultChar = native.tmDefaultChar;
                metrics.BreakChar = native.tmBreakChar;
                metrics.Italic = native.tmItalic;
                metrics.Underlined = native.tmUnderlined;
                metrics.StruckOut = native.tmStruckOut;
                metrics.PitchAndFamily = native.tmPitchAndFamily;
                metrics.CharSet = native.tmCharSet;
            }

            return true;
        }

        private static IntPtr EnsureMetricsDc()
        {
            if (_metricsDc != IntPtr.Zero)
                return _metricsDc;

            IntPtr screenDc = GetDC(IntPtr.Zero);
            if (screenDc == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr memoryDc = CreateCompatibleDC(screenDc);
            ReleaseDC(IntPtr.Zero, screenDc);
            if (memoryDc == IntPtr.Zero)
                return IntPtr.Zero;

            IntPtr font = GetStockObject(STOCK_OBJECT_DEFAULT_GUI_FONT);
            if (font != IntPtr.Zero)
                _metricsPreviousFont = SelectObject(memoryDc, font);

            _metricsFont = font;
            _metricsDc = memoryDc;
            return _metricsDc;
        }

        private sealed class WindowsWindow : IWindow
        {
            private readonly WindowsWinManager _manager;
            private readonly IntPtr _hwnd;
            private bool _disposed;
            private string _title;
            private int _width;
            private int _height;
            private bool _visible;
            private WindowState _state;
            private bool _decorated;
            private readonly bool _resizable;

            internal WindowsWindow(WindowsWinManager manager, IntPtr hwnd, WindowOptions options)
            {
                _manager = manager;
                _hwnd = hwnd;
                _title = options.Title ?? string.Empty;
                _width = Math.Max(options.Width, 1);
                _height = Math.Max(options.Height, 1);
                _visible = options.Visible;
                _state = options.State;
                _decorated = options.Decorated;
                _resizable = options.Resizable;

                _manager.ApplyDecorations(_hwnd, _decorated, _resizable);
            }

            public string Title
            {
                get => _title;
                set
                {
                    EnsureAlive();
                    _title = value ?? string.Empty;
                    Present();
                }
            }

            public int Width
            {
                get => _width;
                set
                {
                    EnsureAlive();
                    _width = Math.Max(value, 1);
                    Present();
                }
            }

            public int Height
            {
                get => _height;
                set
                {
                    EnsureAlive();
                    _height = Math.Max(value, 1);
                    Present();
                }
            }

            public bool Visible
            {
                get => _visible;
                set
                {
                    EnsureAlive();
                    _visible = value;
                    Present();
                }
            }

            public WindowState State
            {
                get => _state;
                set
                {
                    EnsureAlive();
                    _state = value;
                    Present();
                }
            }

            public bool Resizable => _resizable;

            public bool Decorated
            {
                get => _decorated;
                set
                {
                    EnsureAlive();
                    _decorated = value;
                    Present();
                }
            }

            public void Present()
            {
                EnsureAlive();

                _manager.ApplyDecorations(_hwnd, _decorated, _resizable);
                _manager.UpdateWindowText(_hwnd, _title);
                _manager.UpdateWindowSize(_hwnd, _width, _height);

                if (_visible)
                {
                    _manager.UpdateWindowVisibility(_hwnd, true);
                    _manager.UpdateWindowState(_hwnd, _state);
                }
                else
                {
                    _manager.UpdateWindowVisibility(_hwnd, false);
                }
            }

            public IntPtr NativeHandle => _hwnd;

            public void Show() => Visible = true;

            public void Hide() => Visible = false;

            public void Close() => Dispose();

            public void Dispose()
            {
                if (_disposed)
                    return;

                _disposed = true;
                _manager.RemoveWindow(_hwnd);
                CloseWindowHandle(_hwnd);
            }

            internal IntPtr HandleMessage(uint msg, IntPtr wParam, IntPtr lParam)
            {
                if (msg == WM_CLOSE)
                {
                    Close();
                    return IntPtr.Zero;
                }

                if (msg == WM_DESTROY)
                {
                    _manager.RemoveWindow(_hwnd);

                    lock (WindowSync)
                    {
                        if (Windows.Count == 0)
                            PostQuitMessage(0);
                    }

                    return IntPtr.Zero;
                }

                if (msg == WM_PAINT || msg == WM_SIZE || msg == WM_SHOWWINDOW)
                    Interlocked.Exchange(ref _pendingHostRepaint, 1);

                return DefWindowProcW(_hwnd, msg, wParam, lParam);
            }

            private void EnsureAlive()
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(WindowsWindow));
            }
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct WNDCLASSEXW
        {
            public uint cbSize;
            public uint style;
            public IntPtr lpfnWndProc;
            public int cbClsExtra;
            public int cbWndExtra;
            public IntPtr hInstance;
            public IntPtr hIcon;
            public IntPtr hCursor;
            public IntPtr hbrBackground;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpszMenuName;
            [MarshalAs(UnmanagedType.LPWStr)] public string? lpszClassName;
            public IntPtr hIconSm;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public POINT pt;
            public uint lPrivate;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct POINT
        {
            public int X;
            public int Y;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RECT
        {
            public int Left;
            public int Top;
            public int Right;
            public int Bottom;
        }

        [UnmanagedFunctionPointer(CallingConvention.Winapi)]
        private delegate IntPtr WindowProcDelegate(IntPtr hwnd, uint msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern ushort RegisterClassExW(ref WNDCLASSEXW lpwcx);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr CreateWindowExW(
            int dwExStyle,
            string lpClassName,
            string lpWindowName,
            uint dwStyle,
            int X,
            int Y,
            int nWidth,
            int nHeight,
            IntPtr hWndParent,
            IntPtr hMenu,
            IntPtr hInstance,
            IntPtr lpParam);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetWindowTextW(IntPtr hWnd, string lpString);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool DestroyWindowNative(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool SetWindowPos(IntPtr hWnd, IntPtr hWndInsertAfter, int X, int Y, int cx, int cy, uint uFlags);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool AdjustWindowRectEx(ref RECT lpRect, uint dwStyle, [MarshalAs(UnmanagedType.Bool)] bool bMenu, uint dwExStyle);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr DefWindowProcW(IntPtr hWnd, uint Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool PeekMessageW(out MSG lpMsg, IntPtr hWnd, uint wMsgFilterMin, uint wMsgFilterMax, uint wRemoveMsg);

        [DllImport("user32.dll", SetLastError = true)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool TranslateMessage(ref MSG lpMsg);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr DispatchMessageW(ref MSG lpmsg);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr GetWindowLongPtrW(IntPtr hWnd, int nIndex);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern IntPtr SetWindowLongPtrW(IntPtr hWnd, int nIndex, IntPtr dwNewLong);

        [DllImport("user32.dll")]
        private static extern int GetSystemMetrics(int nIndex);

        [DllImport("user32.dll")]
        private static extern bool GetWindowRect(IntPtr hWnd, out RECT lpRect);

        [DllImport("user32.dll")]
        private static extern void PostQuitMessage(int nExitCode);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandleW(string lpModuleName);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern int GetDeviceCaps(IntPtr hdc, int nIndex);

        [DllImport("user32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        private static extern IntPtr GetDC(IntPtr hWnd);

        [DllImport("user32.dll", SetLastError = true)]
        private static extern int ReleaseDC(IntPtr hWnd, IntPtr hDC);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool ExtTextOutW(IntPtr hdc, int x, int y, uint fuOptions, ref RECT lprc, string lpString, uint cbCount, IntPtr lpDx);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern int SetTextColor(IntPtr hdc, int crColor);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern int SetBkColor(IntPtr hdc, int crColor);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern int SetBkMode(IntPtr hdc, int iBkMode);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTextExtentPoint32W(IntPtr hdc, string lpString, int cchString, out SIZE psizl);

        [DllImport("gdi32.dll", SetLastError = true, CharSet = CharSet.Unicode)]
        [return: MarshalAs(UnmanagedType.Bool)]
        private static extern bool GetTextMetricsW(IntPtr hdc, out TEXTMETRICW lptm);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr CreateCompatibleDC(IntPtr hdc);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr SelectObject(IntPtr hdc, IntPtr hObject);

        [DllImport("gdi32.dll", SetLastError = true)]
        private static extern IntPtr GetStockObject(int fnObject);

        private const int STOCK_OBJECT_DEFAULT_GUI_FONT = 17;

        [StructLayout(LayoutKind.Sequential)]
        private struct SIZE
        {
            public int cx;
            public int cy;
        }

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
        private struct TEXTMETRICW
        {
            public int tmHeight;
            public int tmAscent;
            public int tmDescent;
            public int tmInternalLeading;
            public int tmExternalLeading;
            public int tmAveCharWidth;
            public int tmMaxCharWidth;
            public int tmWeight;
            public int tmOverhang;
            public int tmDigitizedAspectX;
            public int tmDigitizedAspectY;
            public ushort tmFirstChar;
            public ushort tmLastChar;
            public ushort tmDefaultChar;
            public ushort tmBreakChar;
            public byte tmItalic;
            public byte tmUnderlined;
            public byte tmStruckOut;
            public byte tmPitchAndFamily;
            public byte tmCharSet;
        }
    }
}
