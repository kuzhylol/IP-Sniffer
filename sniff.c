#include <pcap.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <glib-2.0/gmodule.h>
#include <pcap.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>

#include "daemon.h"
#include "sniff.h"

/* The Pointers below are global.
It is related to their application 
in signal handlers */
/* An associative array for contaning a hashtable
with output data (ip+package num)*/
GHashTable *global_ip_list;
/* The main pointer to iFace data collection */
pcap_t* phadle;

struct ip_header{
        u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
        u_char  ip_tos;                 /* type of service */
        u_short ip_len;                 /* total length */
        u_short ip_id;                  /* identification */
        u_short ip_off;                 /* fragment offset field */
        #define IP_RF 0x8000            /* reserved fragment flag */
        #define IP_DF 0x4000            /* dont fragment flag */
        #define IP_MF 0x2000            /* more fragments flag */
        #define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
        u_char  ip_ttl;                 /* time to live */
        u_char  ip_p;                   /* protocol */
        u_short ip_sum;                 /* checksum */
        struct  in_addr ip_src;  /* source and dest address */
};
/* IP header lenght */
/* Is used for software reducing broken packages */
#define IP_HL(ip) (((ip)->ip_vhl) & 0x0f)


static inline void insert_ip2table(GHashTable *ip_list, char *key_ip);


/* SIGTERM handler signal */
void sniff_term(){
	pcap_breakloop(phadle);
}


static inline char *make_ipstring(const char *ip, const char *key, size_t size){
	char *buffer2write = calloc(size, sizeof(buffer2write));
	char *Result = NULL;

	/* 192.168.1.1 453\n <- how is saves */
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


static void print2f_iplist(gpointer key, gpointer value, gpointer file){
	int *ip_file = file;
	char *ip2write = make_ipstring((char*)key, (char*)value, 64);
	if(NULL != ip2write){
		write(*ip_file, ip2write, 64);
		free(ip2write);
	}else {
		put_log("[SNIFFING]Nothing to show", 0);
	}
}


static char *get_ip(int buffsize){
	char *ip_literal;
	if(NULL == (ip_literal = calloc(buffsize, sizeof(ip_literal))))
		return NULL;

	int readfd;
	if((readfd = open(IPCOUNT_FIFO_F, O_RDONLY)) < 0){
		put_log("[SNIFFING]Opening fifo channel error on read", 1, strerror(errno));
		return NULL;
	}
	read(readfd, ip_literal, buffsize);
	close(readfd);
	/* dont forget free ip_literal*/
	return ip_literal;
}

static void match_specific_ip(const char* anip, const int fdes){
	unsigned ip_plus_cnt_size = 64;
	gpointer ipcnt = g_hash_table_lookup(global_ip_list, (gpointer*) anip );
	char *ip2write = make_ipstring(anip, (char*)ipcnt, ip_plus_cnt_size);
	write(fdes, ip2write, ip_plus_cnt_size);
	free(ip2write);
}


/* SIGUSR1 signal handler */
void get_req(){

	char *sip_literal;
	int ip_cnt = 64;
	sip_literal = get_ip(ip_cnt);
	if(NULL == sip_literal)
		return;

	/* answer */
	int writefd;
	if((writefd = open(IPCOUNT_FIFO_S, O_WRONLY)) < 0){
		put_log("[SNIFFING]Opening fifo channel error", 1, strerror(errno));
		return;
	}

	const char *const get_fullstatistic = "putall";
	switch(strcmp(sip_literal, get_fullstatistic)){
		case(0):
			/* give all ip statistics to cli*/
			g_hash_table_foreach(global_ip_list, print2f_iplist, &writefd);
		break;
		default:
			/* give specific ip statistics to cli */
			match_specific_ip(sip_literal, writefd);
		break;

	}
	close(writefd);
	free(sip_literal);
}


void receive_dataflow_callback(u_char *args, const struct pcap_pkthdr* pkthdr,
		const u_char *packet)
{
	const struct ip_header *ip; /* The IP header */
	u_int ipheader_lenght;
	u_int edgelen = 20;

	ip = (struct ip_header*)(packet + SIZE_ETHERNET);
	ipheader_lenght = IP_HL(ip)*4;
	if (ipheader_lenght < edgelen) {
		return;
	}

	char *connected_ip = inet_ntoa(ip->ip_src);
	insert_ip2table(global_ip_list,  connected_ip);
}


static inline void insert_ip2table(GHashTable *ip_list, char *key_ip){

	char* literal_hashipkey = NULL;
        char* literal_hashnum_packages = NULL;
        char** ip_key = &literal_hashipkey;
        char** cnt_ip = &literal_hashnum_packages;

	char *char_cnt_val = NULL;
	int number_of_ippackages = 0;

	gboolean Sresult = false;

        /* Try looking up this key. */
	Sresult = g_hash_table_lookup_extended (ip_list, key_ip, (gpointer*)ip_key, (gpointer*)cnt_ip);

	/* insertion routine */
	switch(Sresult)
    	{
		case(true):
			char_cnt_val = strdup(literal_hashnum_packages);
			number_of_ippackages = atoi( literal_hashnum_packages );
			++number_of_ippackages;
			sprintf(char_cnt_val, "%d", number_of_ippackages);
	            	/* Rewrite old value of cnt */
		    	g_hash_table_replace (ip_list, g_strdup (key_ip), g_strdup (char_cnt_val));
		break;
		default:
			/* Insert into our hash table it is not a duplicate. */
	 	       	g_hash_table_insert (ip_list, g_strdup (key_ip), (gpointer*)"1");
	       	break;
    	}
	free(char_cnt_val);
}


int run_sniffing(const char *dev_interface){
	int timeout = -1;

	bool promiscuous_mode = false;

	char errbuff[PCAP_ERRBUF_SIZE];/* Errors data here */

	/* declaration in sniff.h */
	phadle = NULL;
	global_ip_list = NULL;

	bpf_u_int32 netp;  /* IPv4 netp of the network on which packets are being captured */
	bpf_u_int32 maskp; /* Mask associated with*/
	/* Determine the IPv4 network number and mask */
	if(-1 == pcap_lookupnet(dev_interface, &netp, &maskp, errbuff)){
		netp = 0;
		maskp = 0;
		put_log("[SNIFFING]Couldn't get netmask for device:", 1, errbuff);
		exit(EXIT_FAILURE);

	}

	put_log("[SNIFFING]Device specified: ", 1, dev_interface);

	/* Opening device in promiscuous-mode */
	phadle = pcap_open_live(dev_interface, BUFSIZ, promiscuous_mode, timeout, errbuff);
	if(NULL == phadle) {
		put_log("[SNIFFING]Couldn't open device:", 1, errbuff);
		exit(EXIT_FAILURE);
	}

	put_log("[SNIFFING]Sniffing started", 0);

	/* memory allocation for first set ip-count pair of Hash table*/
	global_ip_list = g_hash_table_new(g_str_hash, g_str_equal);

	put_log("[SNIFFING]Hash table created", 0);

 	pcap_loop(phadle, timeout, receive_dataflow_callback, NULL);
	pcap_close(phadle);

	put_log("[SNIFFING]Sniffer terminated", 0);

	return SIGTERM;
}
