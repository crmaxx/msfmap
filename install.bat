::  MSFMap Convenience Install Script
::  Copies all of the necessary files to the proper directories
@ECHO off

IF "%1"=="" GOTO USAGE
IF NOT EXIST "%1" GOTO INVALIDDIR
IF NOT EXIST "%1\lib\rex" GOTO INVALIDDIR

ECHO Installing...

ECHO copy /y "client\command_dispatcher\*" "%1\lib\rex\post\meterpreter\ui\console\command_dispatcher\"
copy /y "client\command_dispatcher\*" "%1\lib\rex\post\meterpreter\ui\console\command_dispatcher\" >nul

ECHO copy /y "client\msfmap" "%1\lib\rex\post\meterpreter\extensions\"
copy /y "client\msfmap" "%1\lib\rex\post\meterpreter\extensions\" >nul

:: ECHO copy /y "client\plugin\msfmap.rb" "%1\plugins\msfmap.rb"
:: copy /y "client\plugin\msfmap.rb" "%1\plugins\msfmap.rb" >nul

ECHO copy /y "server\ext_server_msfmap.dll" "%1\data\meterpreter\"
copy /y "server\ext_server_msfmap.dll" "%1\data\meterpreter\" >nul

ECHO copy /y "server\ext_server_msfmap.x64.dll" "%1\data\meterpreter\"
copy /y "server\ext_server_msfmap.x64.dll" "%1\data\meterpreter\" >nul

ECHO copy /y "server\source" "%1\external\source\meterpreter\source\extensions\msfmap"
copy /y "server\source" "%1\external\source\meterpreter\source\extensions\msfmap" >nul

ECHO Done.
GOTO END

:INVALIDDIR
ECHO Invalid Directory
ECHO.

:USAGE
ECHO MSFMap Convenience Installer
ECHO Usage:
ECHO.
ECHO         install.bat [ path to framework base ]

:END