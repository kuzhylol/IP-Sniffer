#include <sys/stat.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>

#include <glib.h>
#include <string.h>

#include "daemon.h"
#include "sniff.h"
#include "ipsniffer.h"

void put_log(char* msg, int msgcnt, ...)
{
        va_list ams;
        char *nextmsg;
	FILE *fd = fopen(LOG_FILE , "a");
	if (NULL == fd) {
		fprintf(stderr, "Cannot open the log file: %s\n", LOG_FILE);
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

void pid_file_create(char* filename,char *dump_f)
{
	pid_t aPID = -1;
	FILE* fd;

	fd = fopen(filename, "w+");
	if(NULL == fd){
		put_log("PID file wasn't created" , 0);
		exit(EXIT_FAILURE);
	}

        aPID = getpid();
	if( fprintf(fd,"%d\n%s" , aPID, dump_f) > 0) {
		put_log("PID file was created correctly", 0);
	}
	fclose(fd);
}


int getPID(char *dfile)
{
	FILE *pid_file;
	pid_file = fopen (SNIFF_PID_FILE, "r+b");

        int len = 100;
	char cpid[len];
	int pid_read = -1;

	if (NULL == pid_file){
                fprintf(stderr, "Sniffer didn't run before: ");
		fprintf(stderr, "PID file doesn't exist\n");
		return (-1);
	}
        fgets(cpid, len, pid_file);

        pid_read = atoi((char*)cpid);

        if(dfile != NULL){
                fgets(dfile, len, pid_file);
        }

	fflush(pid_file);
	fclose(pid_file);

        return pid_read;
}


static const char *array[7] = {
        " --start  Run sniffer daemon with default interface (eth0)\n",
        " --stop   Stop sniffer daemon\n",
        " --select [iface] Run sniffer daemon with [iface] interface\n",
        " -i --ip [ip] Put into a dump info only about single IP address\n",
        " -f --file    Select file for retrieving dump data(eth0)\n",
        " -w --show    Display collected statistics\n",
        " -h --help    Display usage information.n \n"
};

const char* program_name;

void print_usage(FILE* stream, int exit_code) {
	fprintf(stream, "Usage: %s options [...] \n", program_name);
        for(int i=0;i<7;i++){
                fprintf(stream, "%s",array[i]);
        }
	 exit(exit_code);
}

int main(int argc,char *argv[])
{
	const char* const short_options = "rsl:i:f:wh";
	static char *device_interface = "eth0";

	dump_file = strdup("/tmp/dump_file.log");
	IPto_find = NULL;
        int prev_pid = -1;
        char collected_IPfile[100];

	const struct option long_options[] = {
		{ "start",  0, NULL, 'r' },
		{ "stop",  0, NULL, 's' },
		{ "iface", 1, NULL, 'l' },
		{ "ip", 1, NULL, 'i' },
                { "file", 1, NULL, 'f' },
                { "show",  0, NULL, 'w' },
		{ "help",    0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int next_option;
	program_name = argv[0];
	do {
		next_option = getopt_long(argc, argv, short_options,
					long_options, NULL);
		switch(next_option) {
			case 'r':
			break;
			case 's':
				prev_pid = getPID(NULL);
                                if(prev_pid < 0){
                                        fprintf(stderr, "IP sniffer daemon wasn't created\n");
                                        return -1;
                                }
                                printf("%d\n", prev_pid);
				kill(prev_pid, SIGUSR1);
                                fprintf(stdout, "Process %d was requested to be stopped\n", prev_pid);
                                exit(EXIT_SUCCESS);
			break;
			case 'l':
				device_interface = strdup(optarg);
			break;
			case 'i':
				IPto_find = strdup(optarg);
			break;
                        case 'f':
				dump_file = strdup(optarg);
			break;
                        case 'w':
                                prev_pid = getPID(collected_IPfile);
                                if(prev_pid < 0){
                                        fprintf(stderr, "Doesn't exist any working ip sniffers\n");
                                        return 0;
                                }
                                kill(prev_pid, SIGUSR2);
                                fprintf(stdout, "Statistics will be saved in \" %s\" \n", collected_IPfile);
                                exit(EXIT_SUCCESS);
			break;
			case 'h':
				print_usage(stdout, 0);
                        break;
			case '?':
				print_usage(stderr, 1);
                        break;
			case -1:
			break;
			default:
				abort();
			break;
		}
	}while (next_option != -1);

        prev_pid = getPID(NULL);
        if(prev_pid > 0 ){
                kill(prev_pid, SIGUSR1);
                fprintf(stdout, "IPSniffer has already been runned and was stopped %d \n", prev_pid );
                fprintf(stdout, "Previous PID: %d\n", prev_pid );
        }


	printf("%s %s\n",device_interface, dump_file);
	/* Our process ID and Session ID */
	pid_t pid, sid;
        int ret_status = -1;

	/* Fork off the parent process */
	pid = fork();

	if (pid < 0) {
		printf("Start Daemon Error: %s", strerror(errno));
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

	/* Open any logs here */

	/* Create a new SID for the child process */
	sid = setsid();
	if (sid < 0) {
		/* Log the failure */
		exit(EXIT_FAILURE);
	}

	/* Change the current working directory */
	if ((chdir("/")) < 0) {
		/* Log the failure */
		exit(EXIT_FAILURE);
	}

	/* Close out the standard file descriptors */
	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	ret_status = sniffer_fork(device_interface);
        if(ret_status < 0){
                exit(EXIT_FAILURE);
        }

	free(dump_file);
	free(device_interface);
        free(IPto_find);

	return 0;
}
