#ifndef _NET_CKSUM_H
#define _NET_CKSUM_H 1
#include <sys/types.h>

u_short ip_cksum(u_short *addr, int len)
{
	register int nleft = len;
	register u_short *w = addr;
	register u_short answer;
	register int sum = 0;

	/*
	 *  Our algorithm is simple, using a 32 bit accumulator (sum),
	 *  we add sequential 16 bit words to it, and at the end, fold
	 *  back all the carry bits from the top 16 bits into the lower
	 *  16 bits.
	 */
	while (nleft > 1)
	{
		sum += *w++;
		nleft -= 2;
	}

	/* mop up an odd byte, if necessary */
	if (nleft == 1)
	{
		u_short u = 0;

		*(u_char *)(&u) = *(u_char *)w;
		sum += u;
	}

	/*
	 * add back carry outs from top 16 bits to low 16 bits
	 */
	sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
	sum += (sum >> 16);					/* add carry */
	answer = (u_short)(~sum);			/* truncate to 16 bits */
	return (answer);
}

//伪首部校验, 与ip一致
u_short udp_ph_cksum(u_short *addr, int len)
{
	return ip_cksum(addr, len);
}
#endif