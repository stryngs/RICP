# Remote Interface Controller Protocol
A protocol model for transporting the raw 0s and 1s of any interface on a given node via UDP to another node in such a way that the other node sees the traffic as local.

The traffic sent back and forth between the server and client are represented to the client and server as a native interface such as eth0, wlan0mon, tap and so on.  The user is able to launch common programs such as Airodump-ng or Kismet via the same methods they are accustomed when physically present.

## Security
RICP utilizes the [PyNaCl library](https://pynacl.readthedocs.io/en/latest/) for security.  At a minimum --password must be invoked by default with --salt and --key being optional.  To disable security for RICP invoke the --weak flag.

## Trust
Users of this protocol should take measures to ensure they are receiving traffic only from trusted sources.  They should also take the time to ensure if and when running in server mode that a good filtering of the expected input from users is appropriately vetted for the syntax.

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

%run ./ricp.py --dstport 55000 --dstip 192.168.200.106 -c --monnic wlan0 --snfnic wlan1mon --debug --weak
```
