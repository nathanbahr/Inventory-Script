Using the script
----------------
To use the script, run "inventoryStart.bat". This allows the PowerShell part of the script to run even if the execution policy does not strictly allow it. A command line window will appear and display any errors it encountered. It will also display the hostname of the computer if had to create a directoty, or in other words; has not run on that particular machine before. If the script has been used on the computer before, an error message will say there is already a folder with that name. This can be ignored.


Where does the information go?
------------------------------
When the script is run, it will output several files. All files are saved into the "Inventory" folder. Two files are used for the actual database; "Inentory.txt" and "Version.txt". These can be imported into a program such as Microsoft Access or Microsoft Excel to manipulate the data including exporting to CSV. A folder called "details" contains more information about a particular computer after it has been scanned and presents it in an easier to read format.


What is in the files?
---------------------
Inventory.txt contains relevant system information such as the IP address, hostname, serial number, and amount of memory.

Version.txt contains the software version for several programs that regularly need updating. This includes Firefox, Chrome, Internet Explorer, Java, and Flash as well as the operating system, BIOS, and PowerShell version.

All files have timestamps of when the computer was scanned. Both the "Inventory.txt" and "Version.txt" include an "ID" coulomb that uses the last two octets of the computers IP address. For example a computer with the IP address: 192.168.51.46 would have an ID if 5146. This allows a database such as Microsoft Access to use the ID as the primary key and avoid using the same static IP address as another device. 
