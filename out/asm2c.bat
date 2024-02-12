@echo off
setlocal ENABLEDELAYEDEXPANSION

set "dp=%~dp0"
cd !dp!

set "path=%1"
for %%a in ("!path!") do set "name=%~n1"
set "origin1=!dp!!name!.asm"
set "origin2=!dp!!name!.obj"
set "origin3=!dp!!name!.exe"
set "origin4=!dp!!name!.c"

(
	.\assembler\nasm.exe -f win64 "!origin1!" 2>nul && .\linker\link.exe /entry:main /subsystem:windows /LARGEADDRESSAWARE:NO /fixed "!origin2!"
) || (
	del "!origin2!" 2>nul
	.\assembler\nasm.exe -f win32 "!origin1!" 2>nul && .\linker\link.exe /entry:main /subsystem:windows /LARGEADDRESSAWARE:NO /fixed "!origin2!"
) || (
	del "!origin2!" 2>nul
	.\assembler\nasm.exe -o "!origin2!" -f coff "!origin1!" 2>nul && .\linker\link.exe /entry:main /subsystem:windows /LARGEADDRESSAWARE:NO /fixed "!origin2!"
) || (
	echo Error
	pause
	exit /b 1
)
.\decompiler\bin\retdec-decompiler.exe -o "!origin4!" "!origin3!"

del "!dp!!name!.config.json" 2>nul
del "!dp!!name!.bc" 2>nul
del "!dp!!name!.dsm" 2>nul
del "!dp!!name!.ll" 2>nul
del "!dp!!name!-unpacked" 2>nul
del "!origin2!" 2>nul
del "!origin3!" 2>nul

pause