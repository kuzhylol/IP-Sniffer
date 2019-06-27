#include <sys/resource.h>
#include <sys/stat.h>

#include <signal.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>

#include <stdbool.h>
#include <pcap.h>

#include <glib-2.0/gmodule.h>

#include "sniff.h"
#include "daemon.h"
#include "main.h"


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

int sniffer_fork(char *devname){
        pid_t pid;
        int rv_stat = 0;
        int theResult = -1;

	sigset_t sigset;
	sigemptyset(&sigset);

	int signal_list[5] = {SIGQUIT, SIGINT, SIGCHLD, SIGUSR1, SIGUSR2};

	for(int i=0; i < (sizeof(signal_list)/sizeof(signal_list[0]));i++){
		sigaddset(&sigset, signal_list[i]);
	}

	sigemptyset(&sigset);

	sigprocmask(SIG_BLOCK, &sigset, NULL);

        pid = fork();

        switch(pid){
                case(0):/* child  daemon execute*/
                        put_log("Double fork: ", 1, strerror(errno));
                        pid_file_create(SNIFF_PID_FILE, dump_file);
                        umask(0);
                        rv_stat = daemon_sniff(devname);
                        /* close process */
                        exit(rv_stat);
                break;
                case(1):/* parent_child */
                        wait(&rv_stat);
                        rv_stat = WEXITSTATUS(rv_stat);

                        if(CHILD_HAVETO_TERMINATE == rv_stat){
                                theResult = 0;
			}
			remove(SNIFF_PID_FILE);
                        put_log("Second child stopped", 0);
                break;
                default:
                        put_log("Fork failed ", 0);
                break;
        }

        	return theResult;
}

void sniff_term(){
	lookup_break = true;
}

int daemon_sniff(char* devname)
{
	int sniff_retval = 0;
        lookup_break = false;
	sigset_t sigset;
	sigemptyset(&sigset);
	int signal_list[3] = {SIGQUIT, SIGINT, SIGTERM};

	for(int i=0; i<sizeof(signal_list)/sizeof(signal_list[0]);i++){
		sigaddset(&sigset, signal_list[i]);
	}

	sigprocmask(SIG_BLOCK, &sigset, 0);

	signal(SIGUSR1, sniff_term);
	signal(SIGUSR2, sniff_get_IPtable);

        fd_limit(FD_LIMIT);

	put_log("[DAEMON] Started\n", 0);

	sniff_retval = run_sniffing(devname);

	destroy_thread();

	put_log("[DAEMON] Sniffer completed and terminated\n", 0);

	return sniff_retval;
}
