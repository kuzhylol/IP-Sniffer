#include <stdio.h>
#include <sys/time.h>
#include <sys/resource.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <sys/file.h>
#include <execinfo.h>
#include <signal.h>
#include <errno.h>
#include <wait.h>
#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <pcap.h>

#include <ctype.h>

int main(int argc, char *argv[]){
	kill(atoi(argv[1]), SIGUSR2);
}
