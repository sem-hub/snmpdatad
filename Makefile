CC=gcc

OBJS=main.o agentsubagent.o
TARGETS=snmpdatad

CFLAGS=-I. `net-snmp-config --cflags` -g -Wall
BUILDLIBS=`net-snmp-config --libs`
BUILDAGENTLIBS=`net-snmp-config --agent-libs`

# shared library flags (assumes gcc)
DLFLAGS=-fPIC -shared

all: $(TARGETS)

snmpdatad: $(OBJS)
	$(CC) -o $@ $(OBJS)  $(BUILDAGENTLIBS)

clean:
	rm -f $(OBJS) $(TARGETS) *.core

install: all
	install -o root -g wheel snmpdatad /usr/local/sbin
	
