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

parser.add_argument("--nmap", help = "NMAP", action = "store_true")

parser.add_argument( "-o", "--options", help = "NMAP options. For information on options go to https://nmap.org/book/man-briefoptions.html or type man nmap.")

parser.add_argument("--dirb", help = "Directory Buster, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--dnsmap", help = "dnsmap, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--dnsrecon", help = "dnsrecon, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--dnsenum", help = "dnsenum, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--harvester", help = "TheHarvester, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--dmitry", help = "dmitry, requires a scan on a single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--wpscan", help = "WPscan, requires a single domain name for domain running WordPress", action = "store_true")

parser.add_argument("--joomscan", help = "Joomscan, requires a single domain name for domain running Joomla", action = "store_true")

parser.add_argument("--nikto", help = "Nikto Scan, requires scan on single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--arachni", help = "Arachni vulnerability scan, requires scan on single IP or domain name; cannot scan range", action = "store_true")

parser.add_argument("--uniscan", help = "Uniscan vulnerability scan, requires scan on single domain; cannot scan range", action = "store_true")

parser.add_argument("--allthethings", help = "Run All The Scans", action = "store_true")

parser.add_argument("--sublist3r", help = "Sublist3r (https://github.com/aboul3la/Sublist3r), directory must be stored in same directory as pyscan.py; requires scan on single domain, cannot scan range", action = "store_true")




args = parser.parse_args()

hosts = args.targets

nmap = args.nmap

options = args.options

dirb = args.dirb

harvester = args.harvester

dmitry = args.dmitry

dnsmap = args.dnsmap

dnsrecon = args.dnsrecon

dnsenum = args.dnsenum

wpscan = args.wpscan

joomscan = args.joomscan

nikto = args.nikto

uniscan = args.uniscan

arachni = args.arachni

allthethings = args.allthethings 

sublist3r = args.sublist3r





if args.nmap:
  os.system('nmap %s %s' % (options, hosts))

if args.nikto:
  os.system('nikto -host %s' % hosts)

if args.dirb:
  os.system('dirb http://%s' % hosts)

if args.harvester:
  os.system('theharvester %s -b all' % hosts)

if args.dmitry:
  os.system('dmitry %s' % hosts)

if args.dnsmap:
  os.system('dnsmap %s' % hosts)

if args.dnsrecon:
  os.system('dnsrecon -d %s' % hosts)

if args.dnsenum:
  os.system('dnsenum %s' % hosts)

if args.wpscan:
  os.system('wpscan -url %s' % hosts)

if args.arachni:
  os.system('arachni http://%s' % hosts)

if args.joomscan:
  os.system('joomscan -u %s' % hosts)

if args.uniscan:
  os.system('uniscan -u http://%s' % hosts)

if args.sublist3r:
  os.system('cd Sublist3r && python sublist3r.py -d %s' % hosts)

if args.allthethings:
  print """


      ___           ___           ___           ___                    ___           ___       ___                                   
     /\  \         /\  \         /\  \         /\__\                  /\  \         /\__\     /\__\                                  
    /::\  \       /::\  \       /::\  \       /::|  |                /::\  \       /:/  /    /:/  /                                  
   /:/\ \  \     /:/\:\  \     /:/\:\  \     /:|:|  |               /:/\:\  \     /:/  /    /:/  /                                   
  _\:\~\ \  \   /:/  \:\  \   /::\~\:\  \   /:/|:|  |__            /::\~\:\  \   /:/  /    /:/  /                                    
 /\ \:\ \ \__\ /:/__/ \:\__\ /:/\:\ \:\__\ /:/ |:| /\__\          /:/\:\ \:\__\ /:/__/    /:/__/                                     
 \:\ \:\ \/__/ \:\  \  \/__/ \/__\:\/:/  / \/__|:|/:/  /          \/__\:\/:/  / \:\  \    \:\  \                                     
  \:\ \:\__\    \:\  \            \::/  /      |:/:/  /                \::/  /   \:\  \    \:\  \                                    
   \:\/:/  /     \:\  \           /:/  /       |::/  /                 /:/  /     \:\  \    \:\  \                                   
    \::/  /       \:\__\         /:/  /        /:/  /                 /:/  /       \:\__\    \:\__\                                  
     \/__/         \/__/         \/__/         \/__/                  \/__/         \/__/     \/__/                                  
      ___           ___           ___                    ___           ___                       ___           ___           ___     
     /\  \         /\__\         /\  \                  /\  \         /\__\          ___        /\__\         /\  \         /\  \    
     \:\  \       /:/  /        /::\  \                 \:\  \       /:/  /         /\  \      /::|  |       /::\  \        \:\  \   
      \:\  \     /:/__/        /:/\:\  \                 \:\  \     /:/__/          \:\  \    /:|:|  |      /:/\:\  \        \:\  \  
      /::\  \   /::\  \ ___   /::\~\:\  \                /::\  \   /::\  \ ___      /::\__\  /:/|:|  |__   /:/  \:\  \        \:\  \ 
     /:/\:\__\ /:/\:\  /\__\ /:/\:\ \:\__\              /:/\:\__\ /:/\:\  /\__\  __/:/\/__/ /:/ |:| /\__\ /:/__/_\:\__\ _______\:\__
    /:/  \/__/ \/__\:\/:/  / \:\~\:\ \/__/             /:/  \/__/ \/__\:\/:/  / /\/:/  /    \/__|:|/:/  / \:\  /\ \/__/ \::::::::/__/
   /:/  /           \::/  /   \:\ \:\__\              /:/  /           \::/  /  \::/__/         |:/:/  /   \:\ \:\__\    \:\~~\~~    
   \/__/            /:/  /     \:\ \/__/              \/__/            /:/  /    \:\__\         |::/  /     \:\/:/  /     \:\  \     
                   /:/  /       \:\__\                                /:/  /      \/__/         /:/  /       \::/  /       \:\__\    
                   \/__/         \/__/                                \/__/                     \/__/         \/__/         \/__/    

""" 
  print ""
  print ""
  os.system('nmap %s %s' % (options, hosts))
  os.system('dirb http://%s' % hosts)
  os.system('dnsmap %s' % hosts)
  os.system('dnsrecon -d %s' % hosts)
  os.system('dnsenum %s' % hosts)
  os.system('theharvester %s -b all' % hosts)
  os.system('dmitry %s' % hosts)
  os.system('nikto -host %s' % hosts)
  os.system('wpscan -url %s' % hosts)
  os.system('joomscan -u %s' % hosts)
  os.system('arachni http://%s' % hosts)
  os.system('uniscan -u http://%s' % hosts)

  
print ""
print ""
print "Scan Complete!"