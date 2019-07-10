#pragma once

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

int run_sniffing();
void get_req();

void receive_dataflow_callback(u_char *, const struct pcap_pkthdr* , const u_char *);
