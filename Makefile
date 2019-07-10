TARGET=dipsniffer 
DEPS=daemon sniff
IPC=ipsniffer
LIBS=glib-2.0 libpcap

CC=gcc
CFLAGS=-O2 -std=gnu11 -Wall -Wextra -Wpedantic

DEPS:=$(addsuffix .o, $(DEPS))
LIBFLAGS:=$(shell pkg-config --cflags --libs $(LIBS))	
SYSTEMD=/etc/systemd/system
SYSPATH=/usr/sbin
IPATH=./bin

#sudo systemctl start ipsniffer
#sudo systemctl stop ipsniffer
#systemctl enable ipsniffer
#systemctl -l status ipsniffer

.PHONY: all clean install booton bootoff help

help:				## display this message
	@echo Available options:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

all: clean | $(TARGET) $(IPC) ## to assembly binaries

%.o: %.c
	$(CC) $(CFLAGS) $(LIBFLAGS) -c $<

$(TARGET): $(DEPS)		
	$(CC) $(CFLAGS) $(DEPS) $(addsuffix .c, $(TARGET)) $(LIBFLAGS) -o $@

$(IPC):	$(TARGET)
	$(CC) $(IPATH)/$(addsuffix .c, $(IPC)) -o $(IPATH)/$(IPC)

install:  	## to embbed daemon in systemd
	cp $(TARGET) $(IPATH)/$(IPC) -f $(SYSPATH)/
	cp $(IPATH)/$(addsuffix @.service , $(TARGET)) -f $(SYSTEMD)/
	systemctl daemon-reload

uninstall: 	## to remove executable files from OS
	rm -f $(SYSPATH)/$(IPC)  
	rm -f $(SYSTEMD)/$(addsuffix @.service , $(TARGET))


booton: $(TARGET) 	## to configure a service to start automatically on boot
	systemctl enable $(TARGET)

bootoff: $(TARGET) 	## to disable automatically daemon booting
	systemctl disable $(TARGET)

clean:	## to remove intermediate files
	@echo Tidying things up...
	-rm -f *.o $(TARGET) $(IPATH)/$(IPC)
	-rm -f *.log
