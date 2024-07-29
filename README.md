# PyPackets
PyPackets is a simple, fast packets sender.  
Currently it can send ethernet, ipv4 and tcp packets.  
PyPackets focuses on spoofing sent packets.   

- Warning: this project in alpha version 
- Warning: this project is only for linux 

## Installation
The current recommended way to install pypackets is from source.  
### From source
```
git clone https://github.com/sharik-game/pypackets.git
cd pypackets
python3 -m pip install -e .
```
### Direct (main)
```
python3 -m pip install git+https://github.com/sharik-game/pypackets.git
```

## TODO:
- [ ] move creating socket functions into sockets.py
- [ ] add lru cache for Checksum and to_buffer funtions. May be it increase packets creation speed
- [ ] add in benchmark only send time mode
- [ ] try MSG_ZEROCOPY for sending packets
- [ ] for inet_raw socket add epoll(selectors), maybe also nonblocking sockets
- [ ] add packet_mmap socket creation with general tx ring
- [ ] add sending packets using xdp socket
- [ ] add multithreading(currently used only one core)
- [ ] support ipv6, udp

## Bugs
- [ ] if we spoof ip address but don't spoof tcp, in tcp we will have uncorrect checksum, because caching done bad
