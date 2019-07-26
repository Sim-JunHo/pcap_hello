#include <stdint.h>
#include <stdio.h>
#include <pcap.h>
#include "protocol/all.h"

void printpack(const unsigned char *p, uint32_t size)
{
	int n = 0, len = 0;
	while (len < size)
	{
		if (!(len % 16))
		{
			printf("%04X ", len);
		}
		printf("%02X ", *(p + len));
		if (!((len + 1) % 8))
		{
			printf("\t");
		}
		len++;
		if (!((len) % 16) || (size - len) == 0)
		{
			int length = (size - len) == 0 ? size % 16 : 16;
			if (length < 16)
			{
				for (int i = 0; i < 16 - length; i++)
				{
					printf("   ");
				
					if (!((i + 1) % 8))
					{
						printf("\t");
					}
				}
				printf("\t");
			}

			for (int i = 0; i < length; i++)
			{
				uint8_t nowChar = *(p + (len - (length - i)));
				if (nowChar >= 33 && nowChar <= 126)
				{
					printf("%c ", nowChar);
				}
				else
				{
					printf(". ");
				}
				if (!((i + 1) % 8))
				{
					printf("\t ");
				}
			}
			puts("");
		}
	}
}