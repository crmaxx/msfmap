::  MSFMap Convenience Install Script
::  Copies all of the necessary files to the proper directories
@ECHO off

IF "%1"=="" GOTO USAGE
IF NOT EXIST %1 GOTO INVALIDDIR
IF NOT EXIST %1\lib\rex GOTO INVALIDDIR

ECHO Installing...

@ECHO on
copy /y client\command_dispatcher\* %1\lib\rex\post\meterpreter\ui\console\command_dispatcher\ >nul

md %1\lib\rex\post\meterpreter\extensions\msfmap >nul
copy /y client\msfmap %1\lib\rex\post\meterpreter\extensions\msfmap >nul

:: copy /y client\plugin\msfmap.rb %1\plugins\msfmap.rb >nul

copy /y server\ext_server_msfmap.x86.dll %1\data\meterpreter\ >nul

copy /y server\ext_server_msfmap.x64.dll %1\data\meterpreter\ >nul

@ECHO off

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
