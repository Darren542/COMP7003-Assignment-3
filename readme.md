# Installation on WSL
sudo apt install python3-netaddr

# 1 Host 1 Port
sudo python3 main.py --show open -p 22 -t 192.168.0.40
Other Laptop: 192.168.1.70
Router: 192.168.1.154
Loopback: 127.0.0.1
# 1 Host, Many Ports
sudo python3 main.py --show open -p 20-53 -t 192.168.0.1

# Many Hosts, 1 Port
sudo python3 main.py --show open -p 23 -t 192.168.0.1-192.168.0.10

# Many Hosts, Many Ports
sudo python3 main.py --show open -p 20-29 -t 192.168.0.40-192.168.0.44