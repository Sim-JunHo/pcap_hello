#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "all.h"

struct __attribute__((aligned(1), packed)) icmp_header {
	uint8_t type;
    uint8_t code;

	uint16_t chksum;
};