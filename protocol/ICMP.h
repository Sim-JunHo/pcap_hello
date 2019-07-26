#pragma once
#include <stdio.h>
#include <stdint.h>
#include <pcap.h>
#include "all.h"

struct __attribute__((aligned(1), packed)) icmp_header {
	uint8_t icmp_type;
    uint8_t icmp_code;

	uint16_t icmp_chksum;
};