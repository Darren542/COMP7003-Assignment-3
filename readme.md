# Installation on WSL
sudo apt install python3-netaddr

# 1 Host 1 Port
sudo python3 main.py -show open -p 22 -t 192.168.0.40

# 1 Host, Many Ports
sudo python3 main.py -show open -p 20-53 -t 192.168.0.1

# Many Hosts, 1 Port
sudo python3 main.py -show open -p 23 -t 192.168.0.1-192.168.0.10

# Many Hosts, Many Ports
sudo python3 main.py -show open -p 20-29 -t 192.168.0.40-192.168.0.44