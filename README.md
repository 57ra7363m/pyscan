````
-----------------------------------------------------------------

         _     _        _          _             _             _                   _          
        /\ \  /\ \     /\_\       / /\         /\ \           / /\                /\ \     _  
       /  \ \ \ \ \   / / /      / /  \       /  \ \         / /  \              /  \ \   /\_\ 
      / /\ \ \ \ \ \_/ / /      / / /\ \__   / /\ \ \       / / /\ \            / /\ \ \_/ / /
     / / /\ \_\ \ \___/ /      / / /\ \___\ / / /\ \ \     / / /\ \ \          / / /\ \___/ / 
    / / /_/ / /  \ \ \_/       \ \ \ \/___// / /  \ \_\   / / /  \ \ \        / / /  \/____/  
   / / /__\/ /    \ \ \         \ \ \     / / /    \/_/  / / /___/ /\ \      / / /    / / /   
  / / /_____/      \ \ \    _    \ \ \   / / /          / / /_____/ /\ \    / / /    / / /    
 / / /              \ \ \  /_/\__/ / /  / / /________  / /_________/\ \ \  / / /    / / /     
/ / /                \ \_\ \ \/___/ /  / / /_________\/ / /_       __\ \_\/ / /    / / /      
\/_/                  \/_/  \_____\/   \/____________/\_\___\     /____/_/\/_/     \/_/       



Port Scanning Is Not A Crime!


Pyscan is a simple script written in an attempt to learn how to parse arguments in python scripts.  
Currently the script will run nmap, dirb, wpscan, dnsenum, dnsmap, dnsrecon, theHarvester, dmitry and nikto scanning.  Other molules will be added soon.


Dependencies
python-nmap
nikto
dirb
theHarvester
dmitry
wpscan
dnsenum
dnsmap
dnsrecon

usage: pyscan.py [-h] [-t TARGETS] [-o OPTIONS] [-d] [--dnsmap] [--dnsrecon]
                 [--dnsenum] [--harvester] [--dmitry] [--wpscan] [-n]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        Input IPs of Hosts to Scan
  -o OPTIONS, --options OPTIONS
                        NMAP options. Input options inside single quotes (ex.
                        '-sT -sV'). For information on options go to
                        https://nmap.org/book/man-briefoptions.html or type
                        man nmap.
  -d, --dirb            Directory Buster, requires a scan on a single IP or
                        domain name; cannot scan range
  --dnsmap              dnsmap, requires a scan on a single IP or domain name;
                        cannot scan range
  --dnsrecon            dnsrecon, requires a scan on a single IP or domain
                        name; cannot scan range
  --dnsenum             dnsenum, requires a scan on a single IP or domain
                        name; cannot scan range
  --harvester           TheHarvester, requires a scan on a single IP or domain
                        name; cannot scan range
  --dmitry              dmitry, requires a scan on a single IP or domain name;
                        cannot scan range
  --wpscan              WPscan, requires a single domain name for domain
                        running WordPress
  -n, --nikto           Nikto Scan, requires scan on single IP or domain name;
                        cannot scan range
````
