# Remote Interface Controller Protocol
A protocol to transport the raw 0s and 1s of any interface via UDP.

RICP serves the user a model where the client can receive from one device, while the server may send and interact with many clients along with multiple interfaces acting as inputs to the various clients.

The traffic sent back and forth between the server and client are represented to the client and server as a native interface such as eth0 or wlan0mon where the user is able to launch common programs such as Airodump-ng or Kismet via the same methods they are accustomed; the only difference is that UDP transports the input or output of the device and ultimately the control of the device to a user who may or may not be within the same broadcast domain or even close to the same physical user as the other participant within the protocol.

## Security
RICP utilizes the [PyNaCl library](https://pynacl.readthedocs.io/en/latest/) for security.  At a minimum --password must be invoked by default with --salt and --key being optional.  To disable security for RICP invoke the --weak flag.

## Trust
Users of this protocol should take measures to ensure they are receiving traffic only from trusted sources.  They should also take the time to ensure if and when running in server mode that a good filtering of the expected input from users is appropriately vetted for the syntax.

Running as root is explicitly discouraged unless you trust both the inputs and outputs created by this protocol.  A review of the applicable firewall rules in place is highly encouraged prior to deployment of RICP.

### Create the environment
```
python3 -m venv env
source env/bin/activate
python3 -m pip install -r requirements.txt
python3 -m pip install RESOURCEs/*
```
The files in RESOURCEs/ are simple copies from my other git repos.

### Getting started with wired
As a server
```
python3 ./ricp.py --monnic eth0 --dstport 55000 --dstip 192.168.200.106 -s --weak
```

As a client
```
python3 ./ricp.py --dstport 55000 --dstip 192.168.200.106 -c --monnic wlan0 --snfnic tap0 -t --wired --weak
```

With the above done, now interact with tap0
```
tcpdump -i tap0
```

### Getting started with wireless
As a server
```
python3 ./ricp.py --dstip 192.168.200.106 --dstport 20001 --monnic wlan1mon -s --weak
```

As a client
```
python3 ./ricp.py --dstport 20001 --dstip 192.168.200.106 -c --monnic wlan0 --snfnic wlan1mon --weak
```

With the above done, now interact with wlan1mon
```
tcpdump -i wlan1mon
```

### Debugging example
```
from IPython import embed
embed()

%run ./ricp.py --dstport 55000 --dstip 192.168.200.106 -c --monnic wlan0 --snfnic wlan1mon --debug
```
