@echo off
rem ============================================
rem  NetAudit build script (uses local .NET Framework csc, no Visual Studio needed)
rem  Dependencies: lib\Microsoft.Diagnostics.Tracing.TraceEvent.dll
rem               lib\Microsoft.Diagnostics.FastSerialization.dll
rem  Output: bin\NetAudit.exe (run as administrator; keep the two DLLs next to it)
rem ============================================
setlocal
set CORE=C:\Windows\Microsoft.NET\Framework64\v4.0.30319
set SRC=%~dp0
if not exist "%SRC%bin" mkdir "%SRC%bin"

"%CORE%\csc.exe" /nologo /target:winexe /out:"%SRC%bin\NetAudit.exe" ^
  /win32manifest:"%SRC%app.manifest" /optimize+ ^
  /reference:System.dll ^
  /reference:System.Core.dll ^
  /reference:System.Drawing.dll ^
  /reference:System.Windows.Forms.dll ^
  /reference:Microsoft.CSharp.dll ^
  /reference:"%CORE%\netstandard.dll" ^
  /reference:"%SRC%lib\Microsoft.Diagnostics.Tracing.TraceEvent.dll" ^
  /reference:"%SRC%lib\Microsoft.Diagnostics.FastSerialization.dll" ^
  "%SRC%Program.cs" ^
  "%SRC%MainForm.cs" ^
  "%SRC%Models\Models.cs" ^
  "%SRC%Core\NativeMethods.cs" ^
  "%SRC%Core\ProcessResolver.cs" ^
  "%SRC%Core\TrafficMonitor.cs" ^
  "%SRC%Core\ConnectionSampler.cs" ^
  "%SRC%Core\RuleEngine.cs" ^
  "%SRC%Core\HostsExporter.cs" ^
  "%SRC%Core\AuditLogger.cs" ^
  "%SRC%Properties\AssemblyInfo.cs"

if errorlevel 1 (
  echo.
  echo Build FAILED - check the compiler errors above.
  exit /b 1
)

copy /Y "%SRC%lib\Microsoft.Diagnostics.Tracing.TraceEvent.dll" "%SRC%bin\" > nul
copy /Y "%SRC%lib\Microsoft.Diagnostics.FastSerialization.dll" "%SRC%bin\" > nul

echo.
echo Build OK: %SRC%bin\NetAudit.exe
endlocal
