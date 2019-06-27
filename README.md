IP Sniffer
==================

Sniffer is the service that collects information about network traffic.
The service collects all incoming IPs and counts them in daemon mode(on the background of OS).

The IPs retrieve via libpcap API.
Searching the IP is provided with O(1) time complexity. It is connected with used gHashTable in it. Еherefore key -> IP address and count -> value.
Daemon management provides via signals.
All output data transmits to dump file on SIGUSR2 signal and saved respectively.

For rebooting the daemon need to rerun the main executable file. After this, the process will be stopped, cleaned and run new.
In additional is possible to stop daemon via "--stop" key

That implementation gives the ability to communicate with daemon and control it in a wide enough range of variants. In result, the user will get a dump with data array (like shown below).
As addition, the daemon is able to be controlled via peripheral programs in another process (f.e. in cli). Have got plans to design a program to communicate with daemon via IPC in the future.

All abilities showed below

Synopsis
--------

```
# make clean all
# ./main -h
./sniffer options [...]
	--start  Run sniffer daemon with default interface (eth0)
	--stop   Stop sniffer daemon
	--select [iface] Run sniffer daemon with [iface] interface
 	-i --ip [ip] Put into a dump info only about single IP address
 	-f --file    Select file for retrieving dump data(eth0)
 	-w --show    Display collected statistics
 	-h --help    Display usage information
 	General:  ./main --iface wlpxsx --file="path_to_dump/dump.log" 
 	Execute with sudo
```


Flow example on 'wlan0':
```
# ./sniffer -i wlan0
IP:62.x.236.171 Package count: 5 
IP:192.x.1.18 Package count: 2 
IP:138.x.81.199 Package count: 5 
IP:194.x.85.5 Package count: 3 
IP:192.x.253.125 Package count: 2 
IP:192.x.1.1 Package count: 1 
IP:192.x.1.16 Package count: 22 
IP:140.x.114.25 Package count: 4 
IP:54.x.66.195 Package count: 2 
```

System logs of sniffer is displayed in '/var/log/ip_sniffer.log'

PID of daemon and dump file path is displayed in '/var/run/ip_sniffer.pid'


