#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <errno.h>


int getPID_fromdir()
{
	char *sniff_pid_file = "/var/run/ip_sniffer.pid";


	FILE *pid_file = fopen(sniff_pid_file, "r+b");

	/* max available size of pid len */
        int len = 32;
	char cpid[len];
	int pid_read;

	if (NULL == pid_file){
                perror("Sniffer didn't run before: ");
		perror("PID file doesn't exist");
		return (-1);
	}
        fgets(cpid, len, pid_file);

        pid_read = atoi((char*)cpid);

	fflush(pid_file);
	fclose(pid_file);

        return pid_read;
}

void fatal(char *err){
	perror(err);
	exit(1);
}

static const char *array[3] = {
        " -i --ip [ip] Put into a dump info only about single IP address\n",
        " -s --stat    Display collected statistics\n",
        " -h --help    Display usage information.n \n"
};

const char* program_name;

void print_usage(FILE* stream, int exit_code) {
	fprintf(stream, "Usage: %s options [...] \n", program_name);
        for(int i=0;i<3;i++){
                fprintf(stream, "%s",array[i]);
        }
	 exit(exit_code);
}

int main(int argc,char *argv[])
{
	char *ip2search = "putall";

	const char* const short_options = "i:sh";
	const struct option long_options[] = {
                { "ip",  1, NULL, 'i' },
		{ "stat", 0, NULL, 's' },
		{ "help", 0, NULL, 'h' },
		{ NULL, 0, NULL, 0 }
	};

	int next_option;
	program_name = argv[0];
	do {
		next_option = getopt_long(argc, argv, short_options,
					long_options, NULL);
		switch(next_option) {
			case 'i':
				ip2search = strdup(optarg);
			break;
                        case 's':
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

	int main_pid = getPID_fromdir();
	if(main_pid < 0){
		fatal("Please, run daemon, use: systemctl start dipsniffer");
	}

	static char *ipcount_fifo_f = "/tmp/ipfifo";
	static char *ipcount_fifo_s = "/tmp/ipfifo1";

	if(mkfifo(ipcount_fifo_s, 0666) == -1){
		if(errno != EEXIST)
			fatal("Opening mkfifo channel error on read");
	}

	/* start transaction */
	kill(main_pid, SIGUSR1);

	int writefd;
	if((writefd = open(ipcount_fifo_f, O_WRONLY)) < 0){
		fatal("Opening fifo channel error on write");
		return (EXIT_FAILURE);
	}
	write(writefd, ip2search, strlen(ip2search)+1);
	close(writefd);

	char answer[64];
	int readfd;
	if((readfd = open(ipcount_fifo_s, O_RDWR)) < 0){
		fatal("Opening fifo channel error on read");
		return (EXIT_FAILURE);
	}

	do{
		read(readfd, answer, 64);
		fprintf(stdout, "%s",answer);
	}
	while(1);//fgetc(stdin)!= '\n');

	return 0;
}
