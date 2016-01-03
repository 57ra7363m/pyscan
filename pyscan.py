import nmap
import argparse
import os

print """


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
                                                                                            


"""
print ""
print "Port Scanning Is Not A Crime!"
print ""
print ""
print ""

parser = argparse.ArgumentParser()


parser.add_argument( "-t" ,"--targets", help = "Input IPs of Hosts to Scan")

parser.add_argument( "-o", "--options", help = "Input options inside single quotes (ex. '-sT -sV'). For information on options go to https://nmap.org/book/man-briefoptions.html or type man nmap.")

parser.add_argument("-n", "--nikto", help = "Nikto Scan, requires scan on single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("-d", "--dirb", help = "Directory Buster, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--harvester", help = "TheHarvester, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

args = parser.parse_args()

hosts = args.targets

options = args.options

nikto = args.nikto

dirb = args.dirb

harvester = args.harvester

nm = nmap.PortScanner()

nm.scan(hosts= hosts, arguments= options)

for host in nm.all_hosts():
  print('----------------------------------------------------')
  print('Host : %s (%s)' % (host, nm[host].hostname()))
  print('State : %s' % nm[host].state())

for proto in nm[host].all_protocols():
  print('----------')
  print('Protocol : %s' % proto)

  lport = nm[host][proto].keys()
  lport.sort()
  for port in lport:
    print('port : %s\tstate : %s' % (port, nm[host][proto][port]['state']))

print('----------------------------------------------------')

if args.nikto:
  os.system('nikto -host %s' % hosts)

if args.dirb:
  os.system('dirb http://%s' % hosts)

if args.harvester:
  os.system('theharvester %s -b all' % hosts)
print ""
print ""
print "Scan Complete!"