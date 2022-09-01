# Remote Interface Controller Protocol
A protocol to transport the raw 0s and 1s of any interface via UDP.

RICP serves the user a model where the client can receive from one device, while
the server may send and interact with many clients along with multiple
interfaces acting as inputs to the various clients.

The traffic sent back and forth between the server and client are represented
to the client and server as a native interface such as eth0 or wlan0mon where
the user is able to launch common programs such as Airodump-ng or Kismet via the
same methods they are accustomed; the only difference is that UDP transports the
input or output of the device and ultimately the control of the device to a
user who may or may not be within the same broadcast domain or even close to the
same physical user as the other participant within the protocol.

## Security
For now, this protocol transports the output exactly as received.  Do not
transmit sensitive data using this protocol at this time unless you are sure the
data you are transmitting is secured as this protocol will send the data over
the Internet in the same format as received by your monitoring interface.

## Trust
Users of this protocol should take measures to ensure they are receiving traffic
only from trusted sources.  They should also take the time to ensure if and when
running in server mode that a good filtering of the expected input from users is
appropriately vetted for the syntax.

Running as root is explicitly discouraged unless you trust both the inputs and
outputs created by this protocol.  A review of the applicable firewall rules in
place is highly encouraged prior to deployment of RICP.

## Where to
The proof of concept is written in Python using the scapy library.  For quick
development purposes this will stay par for the course until a suitable C port
has been written.

### Create the environment
The files in RESOURCEs/ are simple copies from my other git repos, at some
point I will take the time and leverage submodules.  For now this works...
```
python3 -m venv env
source env/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install RESOURCEs/*
```

### Getting started with wired
As a client
```
python3 ./ricp.py --dstport 55000 --srcport 65000 --srcip 192.168.50.51 --dstip 192.168.200.106 -c --monnic wlan0 --injnic wlan1 --snfnic tap0 -t --wired
```

As a server
```
python3 ./ricp.py --monnic eth0 --dstport 55000 --srcport 65000 --srcip 192.168.50.51 --dstip 192.168.200.106 -s
```

With the above done, now interact with tap0
```
tcpdump -i tap0
```

### Getting started with wireless
As a client
```
python3 ./ricp.py --dstport 55000 --srcport 65000 --srcip 192.168.50.51 --dstip 192.168.200.106 -c --monnic wlan0 --injnic lo --snfnic wlan2mon
```

As a server
```
python3 ./ricp.py --dstip 192.168.200.254 --dstport 20001 --srcport 20001 --srcip 192.168.200.150 --monnic wlan1mon -s
```

With the above done, now interact with wlan2mon
```
tcpdump -i wlan2mon
```

### Debugging example
```
from IPython import embed
embed()

%run ./ricp.py --dstport 55000 --srcport 65000 --srcip 192.168.50.51 --dstip 192.168.200.106 -c --monnic wlan0 --injnic lo --snfnic wlan1mon --debug
```
