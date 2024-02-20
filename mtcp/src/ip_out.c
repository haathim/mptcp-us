#include "ip_out.h"
#include "ip_in.h"
#include "eth_out.h"
#include "arp.h"
#include "debug.h"

/*----------------------------------------------------------------------------*/
// Modified to include the source address as well (needed for multipath situations)
inline int
GetOutputInterface(uint32_t daddr, uint32_t saddr, uint8_t *is_external)
{
	int nif = -1;
	int i;
	int prefix = 0;
	int j;

	*is_external = 0;
	/* Longest prefix matching */
	for (i = 0; i < CONFIG.routes; i++) {
		if ((daddr & CONFIG.rtable[i].mask) == CONFIG.rtable[i].masked) {
			if (CONFIG.rtable[i].prefix > prefix) {
				nif = CONFIG.rtable[i].nif;
				prefix = CONFIG.rtable[i].prefix;
			} else {
				if (saddr == 0)
				{
					*is_external = 1;
					nif = (CONFIG.gateway[0])->nif;
				}
				else{
				
					for ( j = 0; j < CONFIG.gatewayCount; j++)
					{
						if (CONFIG.gateway[j] && CONFIG.gateway[j]->saddr == saddr){
							*is_external = 1;
							nif = (CONFIG.gateway[j])->nif;
						}
					}
				}
			}
			break;
		}
	}

	if (nif < 0) {
		uint8_t *da = (uint8_t *)&daddr;
		TRACE_ERROR("[WARNING] No route to %u.%u.%u.%u\n", 
				da[0], da[1], da[2], da[3]);
		assert(0);
	}
	
	return nif;
}
/*----------------------------------------------------------------------------*/
uint8_t *
IPOutputStandalone(struct mtcp_manager *mtcp, uint8_t protocol, 
		uint16_t ip_id, uint32_t saddr, uint32_t daddr, uint16_t payloadlen)
{
	struct iphdr *iph;
	int nif;
	unsigned char * haddr, is_external;
	int rc = -1;
	int j;

	nif = GetOutputInterface(daddr, saddr, &is_external);
	if (nif < 0)
		return NULL;

	haddr = GetDestinationHWaddr(daddr, saddr, is_external);
	if (!haddr) {
#if 0
		uint8_t *da = (uint8_t *)&daddr;
		TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
				"is not in ARP table!\n",
				da[0], da[1], da[2], da[3]);
#endif
		for(j = 0; j < CONFIG.gatewayCount; j++)
		{
			if (CONFIG.gateway[j]->saddr == saddr){
				RequestARP(mtcp, (is_external) ? ((CONFIG.gateway[j])->daddr) : daddr,
			   nif, mtcp->cur_ts);
			}
		}
		return NULL;
	}

	iph = (struct iphdr *)EthernetOutput(mtcp, 
			ETH_P_IP, nif, haddr, payloadlen + IP_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(IP_HEADER_LEN + payloadlen);
	iph->id = htons(ip_id);
	iph->frag_off = htons(IP_DF);	// no fragmentation
	iph->ttl = 64;
	iph->protocol = protocol;
	iph->saddr = saddr;
	iph->daddr = daddr;
	iph->check = 0;

#ifndef DISABLE_HWCSUM	
        if (mtcp->iom->dev_ioctl != NULL) {
		switch(iph->protocol) {
		case IPPROTO_TCP:
			rc = mtcp->iom->dev_ioctl(mtcp->ctx, nif, PKT_TX_TCPIP_CSUM_PEEK, iph);
			break;
		case IPPROTO_ICMP:
			rc = mtcp->iom->dev_ioctl(mtcp->ctx, nif, PKT_TX_IP_CSUM, iph);
			break;
		}
	}
	/* otherwise calculate IP checksum in S/W */
	if (rc == -1)
		iph->check = ip_fast_csum(iph, iph->ihl);
#else
	UNUSED(rc);
	iph->check = ip_fast_csum(iph, iph->ihl);
#endif

	return (uint8_t *)(iph + 1);
}
/*----------------------------------------------------------------------------*/
uint8_t *
IPOutput(struct mtcp_manager *mtcp, tcp_stream *stream, uint16_t tcplen)
{
	struct iphdr *iph;
	int nif;
	unsigned char *haddr, is_external = 0;
	int rc = -1;
	int j;

	if (stream->sndvar->nif_out >= 0) {
		nif = stream->sndvar->nif_out;
	} else {
		nif = GetOutputInterface(stream->daddr, stream->saddr, &is_external);
		stream->sndvar->nif_out = nif;
		stream->is_external = is_external;
	}

	haddr = GetDestinationHWaddr(stream->daddr, stream->saddr, stream->is_external);
	if (!haddr) {
#if 0
		uint8_t *da = (uint8_t *)&stream->daddr;
		TRACE_INFO("[WARNING] The destination IP %u.%u.%u.%u "
				"is not in ARP table!\n",
				da[0], da[1], da[2], da[3]);
#endif
		/* if not found in the arp table, send arp request and return NULL */
		/* tcp will retry sending the packet later */
		for(j = 0; j < CONFIG.gatewayCount; j++)
		{
			if (CONFIG.gateway[j]->saddr == stream->saddr){
				RequestARP(mtcp, (stream->is_external) ? (CONFIG.gateway[j])->daddr : stream->daddr,
			   stream->sndvar->nif_out, mtcp->cur_ts);
			}
		}
		
		return NULL;
	}
	
	iph = (struct iphdr *)EthernetOutput(mtcp, ETH_P_IP, 
			stream->sndvar->nif_out, haddr, tcplen + IP_HEADER_LEN);
	if (!iph) {
		return NULL;
	}

	iph->ihl = IP_HEADER_LEN >> 2;
	iph->version = 4;
	iph->tos = 0;
	iph->tot_len = htons(IP_HEADER_LEN + tcplen);
	iph->id = htons(stream->sndvar->ip_id++);
	iph->frag_off = htons(0x4000);	// no fragmentation
	iph->ttl = 64;
	iph->protocol = IPPROTO_TCP;
	iph->saddr = stream->saddr;
	iph->daddr = stream->daddr;
	iph->check = 0;

#ifndef DISABLE_HWCSUM
	/* offload IP checkum if possible */
        if (mtcp->iom->dev_ioctl != NULL) {
		switch (iph->protocol) {
		case IPPROTO_TCP:
			rc = mtcp->iom->dev_ioctl(mtcp->ctx, nif, PKT_TX_TCPIP_CSUM_PEEK, iph);
			break;
		case IPPROTO_ICMP:
			rc = mtcp->iom->dev_ioctl(mtcp->ctx, nif, PKT_TX_IP_CSUM, iph);
			break;
		}
	}
	/* otherwise calculate IP checksum in S/W */
	if (rc == -1)
		iph->check = ip_fast_csum(iph, iph->ihl);
#else
	UNUSED(rc);
	iph->check = ip_fast_csum(iph, iph->ihl);
#endif
	return (uint8_t *)(iph + 1);
}
