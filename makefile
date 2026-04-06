LDLIBS += -lpcap

all: send-arp

send-arp: main.c
	gcc -Wall -o send-arp main.c $(LDLIBS)

clean:
	rm -f send-arp *.o
