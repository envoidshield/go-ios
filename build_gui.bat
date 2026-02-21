@echo off
set PATH=C:\mingw64\bin;%PATH%
set CGO_ENABLED=1
set CC=gcc
echo Generating Windows resources...
%USERPROFILE%\go\bin\rsrc.exe -manifest manifest.xml -ico favicon.ico -o rsrc.syso
echo Building executable...
"C:\Program Files\Go\bin\go.exe" build -tags gui -ldflags="-H windowsgui" -o Pairing-Assistant.exe
echo Done!
