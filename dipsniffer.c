#include <sys/stat.h>
#include <wait.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include "daemon.h"
#include "sniff.h"

static bool pid_file_create(const char* filename)
{
	pid_t aPID = -1;
        int success = false;

	FILE* fd = fopen(filename, "w+");
	if(NULL == fd){
		perror("PID file wasn't created");
		exit(EXIT_FAILURE);
	}

        aPID = getpid();
	if( fprintf(fd,"%d\n" , aPID) > 0) {
                success = true;
	}
	fclose(fd);

        return success;
}


void print_usage(FILE* stream, int exit_code,
		char* program_name, const char *err[], int optnum) {

	fprintf(stream, "Usage: %s options [...] \n", program_name);
        for(int i=0;i<optnum;i++){
                fprintf(stream, "%s",err[i]);
        }
	 exit(exit_code);
}


int main(int argc,char *argv[])
{

	char* program_name;
	unsigned optsize = 2;
	static const char *optarray[2] = {
		" --select [iface] Run sniffer daemon with [iface] interface\n",
		" -h --help    Display usage information.n \n"
	};

	const char* const short_options = "l:h";
	static char *device_interface = "eth0";

	const struct option long_options[] = {
		{ "iface", 1, NULL, 'l' },
		{ "help",    0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int next_option;
	program_name = argv[0];
	do {
		next_option = getopt_long(argc, argv, short_options,
					long_options, NULL);
		switch(next_option) {
			case 'l':
				device_interface = strdup(optarg);
			break;
			case 'h':
				print_usage(stdout, EXIT_SUCCESS, program_name, optarray, optsize);
                        break;
			case '?':
				print_usage(stderr, EXIT_FAILURE, program_name, optarray, optsize);
                        break;
			case -1:
			break;
			default:
				abort();
			break;
		}
	}while (next_option != -1);

	fprintf(stdout, "%s\n",device_interface);
	/* Our process ID and Session ID */
	pid_t pid, sid;

	/* Fork off the parent process */
	pid = fork();

	if (pid < 0) {
		perror("Start Daemon Error");
		exit(EXIT_FAILURE);
	}

	fprintf(stdout, "PID: %d \n", pid);

	/* If we got a good PID, then
	   we can exit the parent process. */
	if (pid > 0) {
		exit(EXIT_SUCCESS);
	}

	/* Change the file mode mask */
	umask(0);

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
                perror("The process can not create a session");
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if ((chdir("/")) < 0) {
                perror("The process can not change working directory");
		exit(EXIT_FAILURE);
	}

        /* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

        int rv_stat;
        int aResult = -1;
        pid_t ret_status;
        /* We run daemon here */
        const char *sniff_pid_file =  "/var/run/ip_sniffer.pid";

        /* make second fork for run sniffer */
        switch(ret_status = fork()){
                case(0):/* child  daemon execute*/
                        put_log("Double fork: ", 1, strerror(errno));

                        if(pid_file_create(sniff_pid_file)){
                                put_log("PID file was saved correctly", 0);
                        }

			/* file locates in daemon.h */
			/* 0666 | wr-wr-wr- */
			if(mkfifo(IPCOUNT_FIFO_F, 0666) == -1){
				if(EEXIST != errno)
					put_log("Can not open fifo channel to receive", 0);
			}

                        rv_stat = daemon_sniff(device_interface);

                        /* close process */
                        exit(rv_stat);
                break;
                case(1):/* parent_child */

                        wait(&rv_stat);
                        rv_stat = WEXITSTATUS(rv_stat);

                        if(SIGTERM == rv_stat){
                                aResult = 0;
			}
			unlink(sniff_pid_file);
                break;
                default:
                        aResult = -1;
                        perror("Sniffer fork unsuccessful");
                        exit(EXIT_FAILURE);
                break;
        }

	put_log("[SNIFFING]Sniffer terminated", 0);

	free(device_interface);

	/* remove pipe from system */
	unlink(IPCOUNT_FIFO_F);
	unlink(IPCOUNT_FIFO_S);

	return aResult;
}
