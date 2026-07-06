@echo off
setlocal
set "HERE=%~dp0"

if not exist "%HERE%obj\generated\brovvulk_gen.c" (
    echo error: generated sources missing. Build the Brovan project first ^(it runs the code generator^). 1>&2
    exit /b 1
)

if not exist "%HERE%bin" mkdir "%HERE%bin"
if not exist "%HERE%obj\build" mkdir "%HERE%obj\build"

where cl >nul 2>&1 && goto :msvc

set "VSWHERE=%ProgramFiles(x86)%\Microsoft Visual Studio\Installer\vswhere.exe"
if not exist "%VSWHERE%" goto :try_mingw
for /f "usebackq tokens=*" %%i in (`"%VSWHERE%" -latest -products * -requires Microsoft.VisualStudio.Component.VC.Tools.x86.x64 -property installationPath 2^>nul`) do set "VSPATH=%%i"
if not defined VSPATH goto :try_mingw
if not exist "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" goto :try_mingw
call "%VSPATH%\VC\Auxiliary\Build\vcvars64.bat" >nul 2>&1
where cl >nul 2>&1 && goto :msvc

:try_mingw
if "%CC%"=="" set "CC=x86_64-w64-mingw32-gcc"
where %CC% >nul 2>&1
if errorlevel 1 (
    echo error: no MSVC C++ toolset and no MinGW-w64 compiler found. Install the VS C++ workload or mingw-w64, or set CC. 1>&2
    exit /b 1
)
pushd "%HERE%"
echo Building BrovVulk guest vulkan-1.dll with %CC%
"%CC%" -O2 -shared -o bin\vulkan-1.dll vulkan_shim.c obj\generated\exports.def -I. -I..\vulkan-headers -static -static-libgcc -static-libstdc++ -Wl,--out-implib,bin\libvulkan-1.a -lkernel32
if errorlevel 1 (echo BrovVulk build FAILED & popd & exit /b 1)
popd
goto :deploy_all

:msvc
pushd "%HERE%"
echo Building BrovVulk guest vulkan-1.dll with MSVC cl
cl /nologo /O2 /MT /LD vulkan_shim.c /I. /I..\vulkan-headers /Foobj\build\ /Febin\vulkan-1.dll /link /DEF:obj\generated\exports.def /IMPLIB:bin\vulkan-1.lib kernel32.lib
if errorlevel 1 (echo BrovVulk build FAILED & popd & exit /b 1)
popd

:deploy_all
echo Deploying vulkan-1.dll:
call :deploy "%HERE%..\..\VirtualFS"
for /f "delims=" %%E in ('dir /b /s "%HERE%..\..\Brovan\bin\Brovan.exe" "%HERE%..\..\Brovan.Graphics\Brovan.exe" 2^>nul') do call :deploy "%%~dpE\VirtualFS"
exit /b 0

:deploy
set "VFS=%~1\C\Windows\System32"
if not exist "%VFS%" mkdir "%VFS%"
copy /Y "%HERE%bin\vulkan-1.dll" "%VFS%\vulkan-1.dll" >nul
echo   deployed -^> %VFS%\vulkan-1.dll
exit /b 0
