#include <pcap.h>
#include <stdbool.h>

#include <glib-2.0/gmodule.h>

#include "daemon.h"
#include "sniff.h"
#include "ipsniffer.h"


int run_sniffing(char *dev_interface){
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
	ip_table = g_hash_table_new (g_str_hash, g_str_equal);

	put_log("[SNIFFING]Hash table created", 0);

 	pcap_loop(phadle, timeout, receive_dataflow_callback, NULL);
	pcap_close(phadle);

	put_log("[SNIFFING]Sniffer terminated", 0);

	return CHILD_HAVETO_TERMINATE;
}

void insertTo_ip_table(GHashTable *anIP_table, char *key_ip){

	char* subIP_key = NULL;
        char* subcnt_IP = NULL;
        char** ip_key = &subIP_key;
        char** cnt_ip = &subcnt_IP;

	char *char_cnt_val = NULL;
	int real_cntIPval = 0;

	gboolean Sresult = false;

        /* Try looking up this key. */
	Sresult = g_hash_table_lookup_extended (anIP_table, key_ip, (gpointer*)ip_key, (gpointer*)cnt_ip);

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


static void fout_iptable(gpointer key, gpointer value, gpointer file)
{
	FILE *ip_file = file;
	fprintf(ip_file, "IP:%s Package count: %s \n", (char *)key, (char *)value );
}

/* USR2 handler */
void sniff_get_IPtable(){
	FILE *dumpIP_file;
	gpointer ipcnt;
        dumpIP_file = fopen(dump_file, "w+b");
        if(NULL == dumpIP_file){
                put_log("[SNIFFING]Cannot create a dump file due to file open error", 0);
                return;
        }

	if(IPto_find != NULL){
		ipcnt = g_hash_table_lookup(ip_table, (gpointer*) IPto_find );
		fprintf(dumpIP_file, "IP:%s Package count: %s \n", (char *)IPto_find, (char *)ipcnt);
		fclose(dumpIP_file);
		put_log("[SNIFFING]IP putted in the dump", 0);
		return;
	}

        g_hash_table_foreach(ip_table, fout_iptable, dumpIP_file);
        fclose(dumpIP_file);
        put_log("[SNIFFING]Dump putted", 0);
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

		if(lookup_break){
			lookup_break = false;
			pcap_breakloop(phadle);
		}
}
