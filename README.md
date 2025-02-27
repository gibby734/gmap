# gmap - overview
  CLI script in python to use NMAP with maximum scanning ability
# DESCRIPTION
  gmap is a simple python script used in the CLI to reduce the time and memorization it takes to type the flags
  nmap is the old-reliable for port scanning but was made in 1997 when the computer resources were a fraction of what
  they are today. Instead of using nmap to check if hosts are online, and scan 100 or 1000 common ports, gmap uses
  modern CPU threads and RAM capability to scan every port online or not, posting all information needed while still 
  using good old NMAP. Instead of remembering and typing all 6 flags, just use gmap. 

   -A : for OS detection, version detection, script scanning, and traceroute
   -p- : Scan all 65,535 TCP ports
   -T4 : Set the timing template to 4 (Aggressive) for faster scanning
   -Pn : Skip host discovery and treat all hosts as online, redundant with -A and if you intend to scan every port. 
   -sC : default scripts for additional service information
   -sV : Detect service versions running on open ports
   --min-rate=2000 : Set the minimum rate of packets sent per second to 2000

# COMPATIBILITY
  tested for nmap version 7.95, python-nmap version (0.7.1-0.2) and (2.6.1+dfsg-1)

# USAGE
  download gmap.py or paste the script into a .py file named gmap.py in a directory of your choice and run 
  
  sudo python3 gmap.py [IP_ADDRESS]
  
  recommended for high end linux systems or virtual machines with lots of computing power allocated
  
