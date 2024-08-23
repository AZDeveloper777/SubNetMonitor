Intended for use with a tool like Suricata  
Tested on Windows 10.  
Use case:  Suricata tells you a machine is making calls to a given IP address and you don't know what program is doing that.  
           Put the subnet for that IP address in a file called subnets.txt in your executable directory.  
           Run the console app and wait for it to output the process / service that calls that subnet.  

Targets DotNet 6
