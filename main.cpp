#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include <time.h>
#include <stdlib.h>
#include <arpa/inet.h>
//#include <ip.h>

#define ETH_ALEN 6

#define ETHERTYPE_IP 0x0800
#define ETHERTYPE_ARP 0x0806
#define ETHERTYPE_LOOPBACK 0x9000
#define ETHERTYPE_IPv6 0x86dd

typedef uint32_t tcp_seq;

struct tcp_header {
	__extension__ union {
		struct {
			uint16_t th_sport;
			uint16_t th_dport;
			tcp_seq th_seq;
			tcp_seq th_ack;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
				uint8_t th_x2:4;
				uint8_t th_off:4;
			#endif
			#if __BYTE_ORDER == __BIG_ENDIAN
				uint8_t th_off:4;
				uint8_t th_x2:4;
			#endif
				uint8_t th_flags;
			#define TH_FIN 0x01
			#define TH_SYN 0x02
			#define TH_RST 0x04
			#define TH_PUSH 0x08
			#define TH_ACK 0x10
			#define TH_URG 0x20
			uint16_t th_win;
			uint16_t th_sum;
			uint16_t th_urp;
		};

		struct {
			uint16_t source;
			uint16_t dest;
			uint16_t seq;
			uint16_t ack_seq;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
				uint16_t res1:4;
				uint16_t doff:4;
				uint16_t fin:1;
				uint16_t syn:1;
				uint16_t rst:1;
				uint16_t psh:1;
				uint16_t ack:1;
				uint16_t urg:1;
				uint16_t res2:2;
			#elif __BYTE_ORDER == __BIG_ENDIAN
				uint16_t doff:4;
				uint16_t res1:4;
				uint16_t res2:2;
				uint16_t urg:1;
				uint16_t ack:1;
				uint16_t psh:1;
				uint16_t rst:1;
				uint16_t syn:1;
				uint16_t fin:1;
			#else
			#error "Adjust your bits/endian.h> defines"
			#endif
				uint16_t window;
				uint16_t check;
				uint16_t urg_ptr;
		};
	};
};

struct ip_addr {
	uint8_t a;
	uint8_t b;
	uint8_t c;
	uint8_t d;
};

struct ip_header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
	uint32_t ip_hl : 4;
	uint32_t ip_v : 4;
#endif

#if __BYTE_ORDER == __BIG_ENDIAN
	uint32_t ip_v : 4;
	uint32_t ip_hl : 4;
#endif
	uint8_t ip_tos;
	uint16_t ip_len;
	uint16_t ip_id;
	uint16_t ip_off;

#define IP_RF 0x8000
#define IP_DF 0x4000
#define IP_MF 0x2000
#define IP_OFFMASK 0x1fff

	uint8_t ip_ttl;
	uint8_t ip_p;
	uint16_t ip_sum;
	ip_addr ip_src;
	ip_addr ip_dst;
};

struct ether_header {
	uint8_t dst[ETH_ALEN];
	uint8_t src[ETH_ALEN];
	uint16_t ether_type;
} __attribute__ ((__packed__));

void usage() {
	printf("syntax: pcap_test <interface>\n");
	printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
	clock_t start, now;
	
	srand((unsigned int) time(NULL));

	if(argc != 2) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if(handle == NULL) {
		fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
		return -1;
	}

	start = clock();
	while(true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(handle, &header, &packet);

		now = clock();

		if(res == 0) continue;
		if(res == -1 || res == -2) break;
		printf("%u bytes captured\n", header->caplen);
		
		const ether_header *eth = (ether_header *)packet;
			//MAC 주소 받아오는 코드.
		const ip_header *ip = (ip_header *)(packet + sizeof(ether_header));
			//IP 주소 받아오는 코드.
		const tcp_header *tcp = (tcp_header *)(packet + sizeof(ether_header) + sizeof(ip_header));
			//tcp 포트 번호 받아오는 코드.
		
		//SRC MAC
		printf("MAC SRC : ");
		for(int i = 0; i < 6; i++) {
			printf("%02X", eth->src[i]);
			if(i!=5) printf(":");
		}
		
		/*
		//SRC IP
		printf("\tIP SRC : ");
		printf("%u", ip->ip_src.a);
		printf(".%u", ip->ip_src.b);
		printf(".%u", ip->ip_src.c);
		printf(".%u", ip->ip_src.d);
		*/

		//DEST MAC
		printf("\nMAC DEST : ");
		for(int i = 0; i < 6; i++) {
			printf("%02X", eth->dst[i]);
			if(i!=5) printf(":");
		}

		/*
		//DEST IP
		printf("\tIP DEST : ");
		printf("%u", ip->ip_dst.a);
		printf(".%u", ip->ip_dst.b);
		printf(".%u", ip->ip_dst.c);
		printf(".%u", ip->ip_dst.d);
		*/

		puts("");
		if(ntohs(eth->ether_type)==ETHERTYPE_IP) {
			printf("TYPE : IPv4");

			//SRC IP
			printf("\nIP SRC : ");
			printf("%u", ip->ip_src.a);
			printf(".%u", ip->ip_src.b);
			printf(".%u", ip->ip_src.c);
			printf(".%u", ip->ip_src.d);

			//DEST IP
			printf("\nIP DEST : ");
			printf("%u", ip->ip_dst.a);
			printf(".%u", ip->ip_dst.b);
			printf(".%u", ip->ip_dst.c);
			printf(".%u", ip->ip_dst.d);
		}


		else if(ntohs(eth->ether_type)==ETHERTYPE_ARP) {
			printf("TYPE : ARP");
		}
		//TCP port
		printf("\nTCP SRC : %d", tcp->th_sport);
		printf("\nTCP DEST :%d", tcp->th_dport);
		
		//time start~/ms
		printf("\nTIME : %08.3f\n\n", (double)now-start);
	}


	pcap_close(handle);
	return 0;
}
