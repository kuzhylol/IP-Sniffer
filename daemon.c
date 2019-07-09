#include <sys/resource.h>
#include <sys/stat.h>

#include <signal.h>
#include <errno.h>
#include <unistd.h>

#include <stdbool.h>
#include <pcap.h>

#include <glib-2.0/gmodule.h>

#include "sniff.h"
#include "daemon.h"


void put_log(char* msg, int msgcnt, ...)
{
        va_list ams;
        char *nextmsg;
        char *log_path = "/var/log/ip_sniffer.log";
	FILE *fd = fopen(log_path, "a+");
	if (NULL == fd) {
		fprintf(stderr, "Cannot open the log file: %s\n", log_path);
		exit(EXIT_FAILURE);
	}

        fprintf(fd, "|IP_SNIFFER|: %s", msg);

        va_start(ams, msgcnt);
        for(int i=0;i<msgcnt;i++){
                nextmsg = va_arg(ams, char*);
                fprintf(fd, "%s ", nextmsg);
        }
        fprintf(fd, "\n");
        va_end(ams);
	fclose(fd);
}

static void destroy_thread(void)
{
	g_hash_table_destroy(ip_table);
}


static int fd_limit(int MaxFd)
{
	struct rlimit lim;
	int status = -1;

	lim.rlim_cur = MaxFd;
	lim.rlim_max = MaxFd;

	status = setrlimit(RLIMIT_NOFILE, &lim);

	return status;
}


int daemon_sniff(char* devname)
{
	int sniff_retval = 0;
	// sigset_t sigset;

	int signal_list[2] = {SIGTERM, SIGUSR1};
	size_t signum = sizeof(signal_list)/sizeof(signal_list[0]);

	struct sigaction actchunk[signum];
        for(size_t i=0;i<signum;i++){
	       memset (&actchunk[i], '\0', sizeof(actchunk[i]));
       }
	/* handlers located in sniff.c */
	void sniff_term(), get_req();

        /* SIGTERM = sniff_term
           SIGUSR1 = get_req */
	void (*fsigs[])() = {sniff_term, get_req};

	/* fill handlers field */
	for(size_t i=0;i<signum;i++){
		actchunk[i].sa_sigaction = fsigs[i];
                actchunk[i].sa_flags=SA_SIGINFO; /* use sa_sigaction instead sa_handler (legacy) */
	}

	for(size_t i=0;i<signum;i++){
		if(sigaction(signal_list[i], &actchunk[i], NULL) < 0){
                        put_log("[DAEMON] Signal action error\n", 0);
                        exit(EXIT_FAILURE);
                }
	}

	put_log("[DAEMON] Signal handlers granted \n", 0);

	fd_limit(FD_LIMIT);
	/* the main procedure of getting IP info */
	/* search run_sniffing() in sniff.c */
	sniff_retval = run_sniffing(devname);
	put_log("[DAEMON] Sniffer completed\n", 0);


	destroy_thread();

	put_log("[DAEMON] Sniffer terminated\n", 0);

	return sniff_retval;
}
