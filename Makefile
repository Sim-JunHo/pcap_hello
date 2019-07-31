reall: clean all

all : pcap_hello

pcap_hello: packet.o main.o packetsend.o
	g++ -g -o pcap_hello packet.o main.o packetsend.o -lpcap

main.o:
	g++ -g -c -o main.o main.cpp

packet.o:
	g++ -g -c -o packet.o packet.cpp

packetsend.o:
	g++ -g -c -o packetsend.o packetsend.cpp

clean:
	rm -f pcap_hello
	rm -f *.o

