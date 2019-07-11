IP Sniffer
==================

Sniffer is the service that collects information about network traffic.
This IP sniffer service collects all incoming IPs and counts their packages in daemon mode(on the background of OS).

The IPs are scanned using **libpcap** library. By dint of this library each, all incoming IPs trigger the daemon and raise callback function inside. In the following, hashtable operates data insertion routine inside the call.

Inserting the IP is provided with O(1) time complexity. 
The package consists: "key = IP address" and "number of packages = value". (more about hash table: https://en.wikipedia.org/wiki/Hash_table) 
These routines are located in **gHashTable** (glib-2.0.h).

Daemon management (which is based on 'named pipes') is provided via a command-line interface.
Named pipes work in this implementation by type a client-server architecture. The start transaction request is provided via signal (SIGUSR1 from ipsniffer program which locates in '/usr/sbin' ) for making a request to read pipe.
At this transaction is transmitted IP address (which --ip [address]) or "putall" (if no options) string to the daemon. 
After getting the signal, daemon starts to read the pipe. 
Next the daemon searches the read data and gives away the answer: number of packages if 'address' received correctly or all statistics if vice versa "putall" string is received.
For curiosity, searching  IP calculated with O(1) time complexity (the same as insertion). 
The Daemon is able to be stopped with using SIGTERM signal.
Moreover is possible to find in **/bin/dipsniffer@.service** the line with the signal from above for stopping. 
The command-line process mentioned before provides data exchange between the daemon and produces output on stdout.

Also is used the **sytemd** subsystem for comfortable and reliable daemon management.

I don`t guarantee to receive an absolutely all packages.
Was designed and tested on Manjaro XFCE.

Synopsis
--------

```
# make clean all
# make install/uninstall - embbed/withdraw daemon in/from systemd and cli binaries routines in/from /usr/sbin/
# make booton/bootoff - set daemon in autostarting mode (not tested on a wide ranges of devices)
# systemctl start dipsniffer@xxx where 'xxx' - name of iterface (the default is eth0)
# systemctl stop dipsniffer - stop dipsniffer daemon execution
# systemctl -l status dipsniffer - spectate the status
for more see - man systemd

IPC managment, should use an another command line:
# ipsniffer --ip [ip] - Put in command line number of IP packages (f.e. 192.168.1.17 1)
# ipsniffer --stat - Put in command line all statistics about number of IP packages 
```

Flow example on 'wlp3s0':
![clisample](/media/sample.png)

System logs of daemon is displayed in '/var/log/ip_sniffer.log'

PID of daemon is displayed in '/var/run/ip_sniffer.pid'
