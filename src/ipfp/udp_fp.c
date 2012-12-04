#include "../common.h"
#include "../prads.h"
#include "ipfp.h"

void fp_udp4(packetinfo *pi, ip4_header * ip4, udp_header * udph, const uint8_t * end_ptr)
{

    uint8_t *opt_ptr;
    int32_t ilen, olen;
    uint32_t quirks = 0;
    uint8_t *payload = 0;

    /*
     * Decode variable length header options and remaining data in field 
     */
    olen = IP_HL(ip4) - 5;
    if (olen < 0) {             // Check for bad hlen
        olen = 0;
    } else {
        /*
         * Option length is number of 32 bit words 
         */
        olen = olen * 4;
        quirks |= QUIRK_IPOPT;
    }
    /*
     * If the declared length is shorter than the snapshot (etherleak
     * or such), truncate the package. 
     */
    opt_ptr = (uint8_t *) ip4 + ntohs(ip4->ip_len);
    if (end_ptr > opt_ptr)
        end_ptr = opt_ptr;

    ilen = ip4->ip_vhl & 15;
    /*
     * B0rked packet 
     */
    if (ilen < 5)
        return;

    if (ilen > 5) {
        quirks |= QUIRK_IPOPT;
    }
    /*
     * If IP header ends past end_ptr 
     */
    if ((uint8_t *) (ip4 + 1) > end_ptr)
        return;

    if ((uint8_t *) opt_ptr + ilen < end_ptr) {
        quirks |= QUIRK_DATA;
        payload = opt_ptr + ilen;
    }
    uint8_t udata = (uint8_t *) end_ptr - payload;

    if (!ip4->ip_id)
        quirks |= QUIRK_ZEROID;

    // Fingerprint format: $fplen,$ttl,$df,$io,$if,$fo
    gen_fp_udp(ntohs(ip4->ip_len) - ntohs(udph->len), udata, ip4->ip_ttl,
               (ntohs(ip4->ip_off) & IP_DF) != 0, olen, ntohs(ip4->ip_len),
               ip4->ip_off, ip4->ip_tos, quirks, 
               //ip_src, udph->src_port,AF_INET);
               pi);

//icmp_os_find_match($type,$code,$gttl,$df,$ipopts,$len,$ipflags,$foffset,$tos);

}
