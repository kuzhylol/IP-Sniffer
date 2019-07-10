#pragma once

#include <stdbool.h>
#include <pcap.h>

/* files to set server-client interface */
/* between cli and daemon via named pipe */

/* here request */
#define IPCOUNT_FIFO_F "/tmp/ipfifo"
/*here answer */
#define IPCOUNT_FIFO_S "/tmp/ipfifo1"

/* the limit for opened descriptors */
#define FD_LIMIT 1024*10

int daemon_sniff(const char*);
void put_log(const char* , int , ...);
