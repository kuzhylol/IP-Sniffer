IP Sniffer
==================

Sniffer is the service that collects information about network traffic.
The service collects all incoming IPs and counts them in daemon mode(on the background of OS).

The IPs retrieve via libpcap API.
Searching the IP is provided with O(1) time complexity. It is connected with used gHashTable (Glib) in it. 
Therefore "key = IP address" and "number of packages -> value".
Daemon management provides via cli(command-line interface) and signal for "start transaction".
Cli process provides data exchange between the daemon and produces output on stdout. 

I don`t guarantee to receive an absolutely all packages.
Was tested on Aarch, Manjaro XFCE.

Synopsis
--------

```
# make clean all
# make install | (embbed daemon in systemd and cli binaries routines in /usr/sbin/
# make booton/bootoff | set daemon in autostarting mode (not tested on a wide ranges of devices)
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
