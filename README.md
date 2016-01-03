

PyScan



Port Scanning Is Not A Crime!


Pyscan is a simple script written in an attempt to learn how to parse arguments in python scripts.  
Currently the script will run nmap, dirb, theHarvester, dmitry and nikto scanning.  Other molules will be added soon.


Dependencies
python-nmap
nikto
dirb
theHarvester
dmitry

usage: pyscan.py [-h] [-t TARGETS] [-o OPTIONS] [-n] [-d] [--harvester]
                 [--dmitry]

optional arguments:
  -h, --help            show this help message and exit
  -t TARGETS, --targets TARGETS
                        Input IPs of Hosts to Scan
  -o OPTIONS, --options OPTIONS
                        Input options inside single quotes (ex. '-sT -sV').
                        For information on options go to https://nmap.org/book
                        /man-briefoptions.html or type man nmap.
  -n, --nikto           Nikto Scan, requires scan on single IP or domain name;
                        cannot scan range
  -d, --dirb            Directory Buster, requires a scan on a single IP or
                        domain name; cannot scan range
  --harvester           TheHarvester, requires a scan on a single IP or domain
                        name; cannot scan range
  --dmitry              dmitry, requires a scan on a single IP or domain name;
                        cannot scan range
