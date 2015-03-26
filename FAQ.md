## Frequently Asked Questions ##
### Will this conflict with Metasploit as installed from the main trunk? ###
No, MSFMap does not overwrite or modify any of the files used by a traditional Metasploit installation. The command msfupdate will continue to keep a MSFMap user up to the most current revision and will not have any conflicts. The only reason this would change is if MSFMap is added to the trunk at a later point in time.

### Does this modify the compromised host? ###
No, like a proper Meterpreter extension, MSFMap does not write anything to disk, install services or modify the registry.

### Is this affiliated with Nmap? ###
No, MSFMap is not related to the Nmap project. A lot of MSFMap functionality is designed to imitate Nmap. This is so the user feels comfortable switching between the two.

### Why does it say "The Desired Scan Type Is Not Supported"? ###
Support for SYN scans are currently in an experimental status.

There are two common problems that cause this error to occur:
  1. The user may not be running with Administrative privileges.
  1. The user may have selected to use a SYN Scan on an operating system that does not support the raw socket features necessary.  Since XP SP2, the client versions of Windows have restricted the use of raw sockets and thus made the features that are necessary to perform this type of scan unusable.

For more information please read the "Limitations on Raw Sockets" section of the following article: http://msdn.microsoft.com/en-us/library/windows/desktop/ms740548%28v=vs.85%29.aspx