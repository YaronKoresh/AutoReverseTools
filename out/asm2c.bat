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

.\assembler\nasm.exe -f win64 -O1 --reproducible "!origin1!"
.\linker\link.exe /entry:main /subsystem:windows /LARGEADDRESSAWARE:NO /fixed "!origin2!"
.\decompiler\bin\retdec-decompiler.exe -o "!origin4!" "!origin3!"

del "!dp!!name!.config.json"
del "!dp!!name!.bc"
del "!dp!!name!.dsm"
del "!dp!!name!.ll"
del "!dp!!name!-unpacked"
del "!origin2!"
del "!origin3!"

pause