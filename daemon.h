#pragma once

#include <stdbool.h>
#include <pcap.h>

/* files to set server-client interface */
/* between cli and daemon via named pipe */

/* the client pipe for request */
#define IPCOUNT_FIFO_F "/tmp/ipfifo"
/* the server pipe for answer */
#define IPCOUNT_FIFO_S "/tmp/ipfifo1"

/* the limit for opened descriptors */
#define FD_LIMIT 1024*10

#define DLOGDIR "/var/log"
#define LOG_PATH DLOGDIR"/ipsniffer.log"

int daemon_sniff(const char*);
void put_log(const char* , int , ...);
