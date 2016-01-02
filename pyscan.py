import nmap
import argparse

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

args = parser.parse_args()

hosts = args.targets

options = args.options


nm = nmap.PortScanner()

nm.scan(hosts= hosts, arguments= options)
#insert NK ranges into hosts

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
