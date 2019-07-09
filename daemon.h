#pragma once

#include <stdbool.h>
#include <pcap.h>

#include "sniff.h"

/* the limit for opened descriptors */
#define FD_LIMIT	1024*10
#define IPCOUNT_FIFO_F "/tmp/ipfifo"
#define  IPCOUNT_FIFO_S "/tmp/ipfifo1"

#if !defined(_GNU_SOURCE)
	#define _GNU_SOURCE
#endif

int daemon_sniff(char*);
void put_log(char* , int , ...);
