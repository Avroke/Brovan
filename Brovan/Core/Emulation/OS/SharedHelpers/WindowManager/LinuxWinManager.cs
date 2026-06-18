using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace Brovan.Core.Emulation.OS.SharedHelpers
{
    public static partial class X11
    {
        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XOpenDisplay(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial int XDefaultScreen(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XRootWindow(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial int XDisplayWidth(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial int XDisplayHeight(IntPtr display, int screen);

        [LibraryImport("libX11.so.6")]
        public static partial IntPtr XCreateSimpleWindow(
            IntPtr display,
            IntPtr parent,
            int x,
            int y,
            uint width,
            uint height,
            uint borderWidth,
            ulong border,
            ulong background);

        [LibraryImport("libX11.so.6")]
        public static partial int XMapWindow(IntPtr display, IntPtr window);

        [LibraryImport("libX11.so.6")]
        public static partial int XUnmapWindow(IntPtr display, IntPtr window);

        [LibraryImport("libX11.so.6")]
        public static partial int XDestroyWindow(IntPtr display, IntPtr window);

        [LibraryImport("libX11.so.6", StringMarshalling = StringMarshalling.Utf8)]
        public static partial int XStoreName(IntPtr display, IntPtr window, string windowName);

        [LibraryImport("libX11.so.6")]
        public static partial int XResizeWindow(IntPtr display, IntPtr window, uint width, uint height);

        [LibraryImport("libX11.so.6")]
        public static partial int XMoveWindow(IntPtr display, IntPtr window, int x, int y);

        [LibraryImport("libX11.so.6")]
        public static partial int XSelectInput(IntPtr display, IntPtr window, long eventMask);

        [LibraryImport("libX11.so.6")]
        public static partial int XPending(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial int XNextEvent(IntPtr display, out XEvent @event);

        [LibraryImport("libX11.so.6")]
        public static partial int XFlush(IntPtr display);

        [LibraryImport("libX11.so.6")]
        public static partial int XCloseDisplay(IntPtr display);

        [StructLayout(LayoutKind.Sequential)]
        public unsafe struct XEvent
        {
            private fixed ulong _data[24];
        }
    }

    public static partial class Wayland
    {
        [LibraryImport("libwayland-client.so.0")]
        public static partial IntPtr wl_display_connect(IntPtr name);

        [LibraryImport("libwayland-client.so.0")]
        public static partial void wl_display_disconnect(IntPtr display);

        [LibraryImport("libwayland-client.so.0")]
        public static partial int wl_display_dispatch_pending(IntPtr display);

        [LibraryImport("libwayland-client.so.0")]
        public static partial int wl_display_flush(IntPtr display);
    }

    internal sealed class LinuxWinManager : IDisplayConnection
    {
        private readonly object _sync = new();
        public readonly Dictionary<IntPtr, LinuxWindow> _windows = new();
        private LinuxDisplayBackend _backend;
        private IntPtr _xDisplay;
        private IntPtr _wlDisplay;
        private bool _disposed;

        public LinuxWinManager()
        {
            if (!GeneralHelper.IsLinux)
                throw new PlatformNotSupportedException("Linux window manager needs to be used on a Linux system.");

            _wlDisplay = Wayland.wl_display_connect(IntPtr.Zero);
            if (_wlDisplay != IntPtr.Zero)
                _backend = LinuxDisplayBackend.Wayland;

            _xDisplay = X11.XOpenDisplay(IntPtr.Zero);
            if (_xDisplay != IntPtr.Zero && _backend == LinuxDisplayBackend.None)
                _backend = LinuxDisplayBackend.X11;

            if (_backend == LinuxDisplayBackend.None)
            {
                string Supported = string.Join(", ", Enum.GetValues<LinuxDisplayBackend>().Where(x => x != LinuxDisplayBackend.None));
                throw new PlatformNotSupportedException($"No supported Linux display backend was found. Supported desktop environments: {Supported}");
            }
        }

        public bool IsConnected => !_disposed && (_xDisplay != IntPtr.Zero || _wlDisplay != IntPtr.Zero);

        public IntPtr NativeHandle => _xDisplay != IntPtr.Zero ? _xDisplay : _wlDisplay;

        public IWindow CreateWindow(WindowOptions options)
        {
            if (_disposed)
                throw new ObjectDisposedException(nameof(LinuxWinManager));

            options ??= new WindowOptions();

            if (_xDisplay == IntPtr.Zero)
                throw new PlatformNotSupportedException("A live X11 display connection is required for host window creation in the current Linux backend.");

            IntPtr windowHandle = CreateX11Window(options);
            LinuxWindow window = new(this, _xDisplay, windowHandle, options);
            lock (_sync)
                _windows[windowHandle] = window;

            return window;
        }

        public void PumpEvents()
        {
            if (_disposed)
                return;

            if (_xDisplay != IntPtr.Zero)
            {
                while (X11.XPending(_xDisplay) > 0)
                {
                    X11.XNextEvent(_xDisplay, out _);
                }

                X11.XFlush(_xDisplay);
            }

            if (_wlDisplay != IntPtr.Zero)
            {
                Wayland.wl_display_dispatch_pending(_wlDisplay);
                Wayland.wl_display_flush(_wlDisplay);
            }
        }

        public void Dispose()
        {
            if (_disposed)
                return;

            _disposed = true;

            LinuxWindow[] windows;
            lock (_sync)
            {
                windows = _windows.Values.ToArray();
                _windows.Clear();
            }

            foreach (LinuxWindow window in windows)
                window.Dispose();

            if (_xDisplay != IntPtr.Zero)
            {
                X11.XCloseDisplay(_xDisplay);
                _xDisplay = IntPtr.Zero;
            }

            if (_wlDisplay != IntPtr.Zero)
            {
                Wayland.wl_display_disconnect(_wlDisplay);
                _wlDisplay = IntPtr.Zero;
            }
        }

        private IntPtr CreateX11Window(WindowOptions options)
        {
            options ??= new WindowOptions();
            int screen = X11.XDefaultScreen(_xDisplay);
            IntPtr rootWindow = X11.XRootWindow(_xDisplay, screen);

            int width = Math.Max(options.Width, 1);
            int height = Math.Max(options.Height, 1);

            if (options.Center)
            {
                int screenWidth = X11.XDisplayWidth(_xDisplay, screen);
                int screenHeight = X11.XDisplayHeight(_xDisplay, screen);
                options = options with
                {
                    X = Math.Max((screenWidth - width) / 2, 0),
                    Y = Math.Max((screenHeight - height) / 2, 0),
                };
            }

            IntPtr window = X11.XCreateSimpleWindow(
                _xDisplay,
                rootWindow,
                options.X,
                options.Y,
                (uint)width,
                (uint)height,
                0,
                0,
                0);

            const long EventMask = (1L << 0) | (1L << 1) | (1L << 2) | (1L << 3) | (1L << 15) | (1L << 17);
            X11.XSelectInput(_xDisplay, window, EventMask);

            if (!string.IsNullOrWhiteSpace(options.Title))
                X11.XStoreName(_xDisplay, window, options.Title);

            if (options.Visible)
                X11.XMapWindow(_xDisplay, window);

            X11.XFlush(_xDisplay);
            return window;
        }

        private void RemoveWindow(IntPtr handle)
        {
            lock (_sync)
                _windows.Remove(handle);
        }

        internal bool DestroyWindow(IntPtr handle)
        {
            if (_xDisplay == IntPtr.Zero || handle == IntPtr.Zero)
                return false;

            bool removed;
            lock (_sync)
            {
                removed = _windows.Remove(handle);
            }

            if (!removed)
                return false;

            X11.XDestroyWindow(_xDisplay, handle);
            X11.XFlush(_xDisplay);
            return true;
        }

        public bool TryGetWindow(IntPtr handle, out LinuxWindow window)
        {
            lock (_sync)
                return _windows.TryGetValue(handle, out window);
        }

        public sealed class LinuxWindow : IWindow
        {
            private readonly LinuxWinManager _manager;
            private readonly IntPtr _display;
            private readonly IntPtr _window;
            private bool _disposed;
            private string _title;
            private int _width;
            private int _height;
            private bool _visible;
            private bool _decorated;
            private WindowState _state;
            private readonly bool _resizable;

            internal LinuxWindow(LinuxWinManager manager, IntPtr display, IntPtr window, WindowOptions options)
            {
                _manager = manager;
                _display = display;
                _window = window;
                _title = options.Title ?? string.Empty;
                _width = Math.Max(options.Width, 1);
                _height = Math.Max(options.Height, 1);
                _visible = options.Visible;
                _decorated = options.Decorated;
                _resizable = options.Resizable;
                _state = options.State;
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

                X11.XStoreName(_display, _window, _title ?? string.Empty);
                X11.XResizeWindow(_display, _window, (uint)_width, (uint)_height);

                if (_visible)
                    X11.XMapWindow(_display, _window);
                else
                    X11.XUnmapWindow(_display, _window);

                X11.XFlush(_display);
            }

            public IntPtr NativeHandle => _window;

            public void Show() => Visible = true;

            public void Hide() => Visible = false;

            public void Close() => Dispose();

            public void Dispose()
            {
                if (_disposed)
                    return;

                _disposed = true;
                _manager.DestroyWindow(_window);
            }

            private void EnsureAlive()
            {
                if (_disposed)
                    throw new ObjectDisposedException(nameof(LinuxWindow));
            }
        }
    }
}
