#pragma once
#include <stdint.h>
#include <stdio.h>

typedef uint32_t udp_seq;

struct udp_header {
	__extension__ union {
		struct {
			uint16_t uh_sport;
			uint16_t uh_dport;
			udp_seq uh_seq;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
				uint8_t uh_x2:4;
				uint8_t uh_off:4;
			#endif
			#if __BYTE_ORDER == __BIG_ENDIAN
				uint8_t uh_off:4;
				uint8_t uh_x2:4;
			#endif
			#define UH_FIN 0x01
			#define UH_SYN 0x02
			#define UH_RST 0x04
			#define UH_PUSH 0x08
			uint16_t uh_sum;
		};

		struct {
			uint16_t source;
			uint16_t dest;
			#if __BYTE_ORDER == __LITTLE_ENDIAN
				uint16_t res1:4;
				uint16_t fin:1;
				uint16_t syn:1;
				uint16_t rst:1;
				uint16_t psh:1;
				uint16_t res2:2;
			#elif __BYTE_ORDER == __BIG_ENDIAN
				uint16_t res1:4;
				uint16_t res2:2;
				uint16_t psh:1;
				uint16_t rst:1;
				uint16_t syn:1;
				uint16_t fin:1;
			#else
			#error "Adjust your bits/endian.h> defines"
			#endif
				uint16_t check;
		};
	};
};
