IP Sniffer
==================

Sniffer is the service that collects information about network traffic.
The service collects all incomming IPs and counts them in daemon mode.

The IPs retrievs via libpcap API.
Searching the IP provides with O(1) time complexity.It is connected with used gHashTable in it.
Daemon managment provides via signals.
All output data transmitts to dump file on SIGUSR2 signal and saved respectively.


For rebooting the daemon need to rerun main executable file.After this the process will be stopped, cleaned and runned new.
In additional is possible to stop daemon via "--stop" key

Like an addition is usefull to control daemon via addition programs in another process (f.e. in cli).
But seems to me this implementation is a good basis for designing any variant of data analysis.
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


