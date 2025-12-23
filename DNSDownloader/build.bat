@echo off
REM Build script for DnsDownloader.cs
REM Requires .NET Framework SDK or Visual Studio Build Tools

echo Building DnsDownloader.exe...

csc /t:exe ^
    /out:DnsDownloader.exe ^
    /r:System.IO.Compression.dll ^
    /r:System.IO.Compression.FileSystem.dll ^
    DnsDownloader.cs

if %ERRORLEVEL% EQU 0 (
    echo.
    echo [+] Build successful: DnsDownloader.exe
    echo.
    echo Usage:
    echo   DnsDownloader.exe -d test.local -p secret123 -s 127.0.0.1 -P 5353
) else (
    echo.
    echo [!] Build failed with error code %ERRORLEVEL%
)

pause

