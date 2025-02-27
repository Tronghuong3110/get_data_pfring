/*
 *
 * (C) 2005-23 - ntop
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Lesses General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 */


#ifndef _PFRING_UTILS__
#define _PFRING_UTILS__


int pfring_parse_pkt_ppp(u_char *data, struct pfring_pkthdr *hdr, u_int8_t level /* L2..L4, 5 (tunnel) */,
		     u_int8_t add_timestamp /* 0,1 */, u_int8_t add_hash /* 0,1 */);

#endif /* _PFRING_UTILS__ */