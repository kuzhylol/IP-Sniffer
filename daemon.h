#pragma once

#include <stdbool.h>
#include <pcap.h>

#include "sniff.h"

/* the limit for opened descriptors */
#define FD_LIMIT			1024*10

#define CHILD_HAVETO_TERMINATE	2

#define SNIFF_PID_FILE "/var/run/ip_sniffer.pid"
#define LOG_FILE "/var/log/ip_sniffer.log"

#if !defined(_GNU_SOURCE)
	#define _GNU_SOURCE
#endif

int daemon_sniff(char*);
int sniffer_fork(char*);
