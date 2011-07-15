#! /bin/sh
# MSFMap Convenience Install Script
# Copies all of the necessary files to the proper directories

USAGE="MSFMap Convenience Installer
Usage:

	install.sh [ path to framework base ]"

if [ "$(id -u)" != "0" ]; then
	echo "This Must Be Run As Root"
	echo ""
	echo "$USAGE"
	exit 1
fi

if [ $# != 1 ]; then
	echo "Missing Option"
	echo ""
	echo "$USAGE"
	exit 1
fi

if [ ! -d "$1" ]; then
	echo "Invalid Directory"
	echo ""
	echo "$USAGE"
	exit 1
elif [ ! -d "$1/msf3" ]; then
	echo "Invalid Directory"
	echo ""
	echo "$USAGE"
	exit 1
fi

echo "Installing..."

echo "cp client/command_dispatcher/msfmap.rb $1/msf3/lib/rex/post/meterpreter/ui/console/command_dispatcher/msfmap.rb"
cp client/command_dispatcher/* $1/msf3/lib/rex/post/meterpreter/ui/console/command_dispatcher/

echo "cp -r client/msfmap $1/msf3/lib/rex/post/meterpreter/extensions/"
cp -r client/msfmap $1/msf3/lib/rex/post/meterpreter/extensions/

echo "cp server/ext_server_msfmap.dll $1/msf3/data/meterpreter/"
cp server/ext_server_msfmap.dll $1/msf3/data/meterpreter/

echo "cp -r server/source $1/msf3/external/source/meterpreter/source/extensions/msfmap"
cp -r server/source $1/msf3/external/source/meterpreter/source/extensions/msfmap

echo "Done."
