#include <pcap.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib-2.0/gmodule.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/socket.h>

#include "daemon.h"
#include "sniff.h"


static inline void insertTo_ip_table(GHashTable *anIP_table, char *key_ip);


/* SIGTERM handler */
void sniff_term(){
	pcap_breakloop(phadle);
}


static inline char *make_ipstring(const char *ip, const char *key, size_t size){
	char *buffer2write = calloc(size, sizeof(buffer2write));
	char *Result = NULL;

	/* 192.168.1.1 453\n <- how to saves*/
	if(NULL != ip && NULL != key && NULL != buffer2write){
		char *space = " ", *newline = "\n"; /* don't forget about '\0' */
		/* copy ip to buffer */
		memcpy(buffer2write, ip, strlen(ip)+1);
		strcat(buffer2write, space);
		strcat(buffer2write, key);
		strcat(buffer2write, newline);

	}else{
		return Result;
	}

	return buffer2write;
}

/* glib handler */
static void fout_iptable(gpointer key, gpointer value, gpointer file){
	int *ip_file = file;
	char *ip2write = make_ipstring((char*)key, (char*)value, 64);
		if(NULL != ip2write){
		write(*ip_file, ip2write, 64);
		free(ip2write);
	}else {
		put_log("[SNIFFING]Nothing to show", 0);
	}
}


static char *get_ip(){
	char *r_ip = calloc(32, sizeof(r_ip));
	if(NULL == r_ip)
		return NULL;

	int readfd;
	if((readfd = open(IPCOUNT_FIFO_F, O_RDONLY)) < 0){
		put_log("[SNIFFING]Opening fifo channel error on read", 1, strerror(errno));
		return NULL;
	}
	read(readfd, r_ip, 32);
	close(readfd);
	return r_ip;
}

static void match_specific_ip(const char* anip, const int fdes){

	gpointer ipcnt = g_hash_table_lookup(ip_table, (gpointer*) anip );
	char *ip2write = make_ipstring(anip, (char*)ipcnt, 64);
	write(fdes, ip2write, 64);
	free(ip2write);
}


/* USR1 handler */
void get_req(){

	char *sr_ip;
	sr_ip = get_ip();
	if(sr_ip == NULL)
		return;

	/* answer */
	int writefd;
	if((writefd = open(IPCOUNT_FIFO_S, O_WRONLY)) < 0){
		put_log("[SNIFFING]Opening fifo channel error", 1, strerror(errno));
		return;
	}

	switch(strcmp(sr_ip, "putall")){
		case(0):
			/* give all ip statistics to cli*/
			g_hash_table_foreach(ip_table, fout_iptable, &writefd);
		break;
		default:
			/* give specific ip statistics to cli */
			match_specific_ip(sr_ip, writefd);
		break;

	}
	close(writefd);
	free(sr_ip);
	put_log("[SNIFFING]IP putted into dump", 0);
}


void receive_dataflow_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char *packet)
{
	const struct sniff_ip *ip; /* The IP header */
	u_int size_ip;

	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		return;
	}

	insertTo_ip_table(ip_table, inet_ntoa(ip->ip_src) );
}


static inline void insertTo_ip_table(GHashTable *anIP_table, char *key_ip){

	char* subIP_key = NULL;
        char* subcnt_IP = NULL;
        char** ip_key = &subIP_key;
        char** cnt_ip = &subcnt_IP;

	char *char_cnt_val = NULL;
	int real_cntIPval = 0;

	gboolean Sresult = false;

        /* Try looking up this key. */
	Sresult = g_hash_table_lookup_extended (anIP_table, key_ip, (gpointer*)ip_key, (gpointer*)cnt_ip);

	/* insertion routine */
	switch(Sresult)
    	{
		case(true):
			char_cnt_val = strdup(subcnt_IP);
			real_cntIPval = atoi( subcnt_IP );
			++real_cntIPval;
			sprintf(char_cnt_val, "%d", real_cntIPval);
	            	/* Rewrite old value of cnt */
		    	g_hash_table_replace (anIP_table, g_strdup (key_ip), g_strdup (char_cnt_val));
		break;
		default:
			/* Insert into our hash table it is not a duplicate. */
	 	       	g_hash_table_insert (anIP_table, g_strdup (key_ip), (gpointer*)"1");
	       	break;
    	}
	free(char_cnt_val);
}


int run_sniffing(const char *dev_interface){
	int timeout = -1;

	bool promiscuous_mode = false;

	char _errbuff[PCAP_ERRBUF_SIZE];/* Errors data here */

	/* declaration in sniff.h */
	phadle = NULL;
	ip_table = NULL;

	bpf_u_int32 netp;  /* IPv4 netp of the network on which packets are being captured */
	bpf_u_int32 maskp; /* Mask associated with*/
	/* Determine the IPv4 network number and mask */
	if(pcap_lookupnet(dev_interface, &netp, &maskp, _errbuff) == -1){
		netp = 0;
		maskp = 0;
		put_log("[SNIFFING]Couldn't get netmask for device:", 1, _errbuff);
		exit(EXIT_FAILURE);

	}

	put_log("[SNIFFING]Device specified: ", 1, dev_interface);

	/* Opening device in promiscuous-mode */
	phadle = pcap_open_live(dev_interface, BUFSIZ, promiscuous_mode, timeout, _errbuff);
	if(NULL == phadle) {
		put_log("[SNIFFING]Couldn't open device:", 1, _errbuff);
		exit(EXIT_FAILURE);
	}

	put_log("[SNIFFING]Sniffing started", 0);

	/* memory allocation for first set IP|COUNT of Hash table*/
	ip_table = g_hash_table_new(g_str_hash, g_str_equal);

	put_log("[SNIFFING]Hash table created", 0);

 	pcap_loop(phadle, timeout, receive_dataflow_callback, NULL);
	pcap_close(phadle);

	put_log("[SNIFFING]Sniffer terminated", 0);

	return SIGTERM;
}
