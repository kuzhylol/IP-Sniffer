TARGET=ipsniffer 
DEPS=daemon sniff
LIBS=glib-2.0 libpcap

CC=gcc
CFLAGS=-O2 -std=gnu11 -Wall -Wextra -Wpedantic

DEPS:=$(addsuffix .o, $(DEPS))
LIBFLAGS:=$(shell pkg-config --cflags --libs $(LIBS))	# be sure to see what it does

.PHONY: all clean

help:				## display this message
	@echo Available options:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

all: clean | $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) $(LIBFLAGS) -c $<

$(TARGET): $(DEPS)		
	$(CC) $(CFLAGS) $(DEPS) $(addsuffix .c, $(TARGET)) $(LIBFLAGS) -o $@


clean:
	@echo Tidying things up...
	-rm -f *.o $(TARGET)
	-rm -f *.log
