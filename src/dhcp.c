#include "prads.h"
#include "config.h"
#include "sys_func.h"
#include "dhcp.h"

extern globalconfig config;

static const unsigned char vendcookie[] = { 99, 130, 83, 99 };
#define BOOTP_COOKIE_SIZE 4
#define PKT_MAXPAY 16

void dhcp_fingerprint(packetinfo *pi)
{
    plog("Got me a DHCP packet!\n");
    config.pr_s.dhcp_os_assets++;

    uint8_t dhcp_header_length;
    uint8_t *dhcp_mc;
    uint8_t *dhcp_options;
    dhcp_header *dhcph;
    uint8_t optlen = 0;
    uint8_t dhcp_opt_type = 0;
    uint8_t end_opt_parsing = 0;
    //char opts[512];
    //char mopts[512];

    dhcph = (dhcp_header *) (pi->payload);
    dhcp_header_length = sizeof(dhcp_header);
    dhcp_mc = (uint8_t *) (pi->payload + dhcp_header_length);

    plog("Magic Cookie: %d%d%d%d\n", *dhcp_mc, *(dhcp_mc+1), *(dhcp_mc+2), *(dhcp_mc+3)); // 99 130 83 99

    dhcp_options = (uint8_t *) dhcp_mc + BOOTP_COOKIE_SIZE;
    uint8_t *optptr = dhcp_options;
    uint8_t max_len = (pi->plen - dhcp_header_length - BOOTP_COOKIE_SIZE);

    plog("max_len: %d\n", max_len);
    plog("IP ttl : %d\n", pi->ip4->ip_ttl); 
    plog("Options: ");
    
    while (optlen < max_len) {
        uint8_t i;

        uint8_t opt      = *(optptr);
        uint8_t optsize  = *(optptr+1);
        uint8_t *optdata =   optptr+2;

        switch(opt) {
            case DHCP_OPTION_TYPE: /* 53 */
                if (optsize == 1) {
                    dhcp_opt_type = *optdata;
                    plog("%d(%d)", opt, dhcp_opt_type);
                }
                break;
            case DHCP_OPTION_OPTIONREQ: /* 55 */
                plog("%d", opt);
                if (optsize > 0) {
                    plog("(");
                    for (i=2; i < optsize+2; i++) {
                        u_int8_t ropt;
                        ropt = *(optptr+i);
                        plog("%d", ropt);
                        if (i < optsize+1) {
                            plog(",");
                        }
                    }
                }
                plog(")");
                break;
            case DHCP_OPTION_CLASS_IDENTIFIER: /* 60 */
                plog("%d", opt);
                if (optsize > 0) {
                    plog("(");
                    print_data(optdata, optsize);
                    plog(")");
                }
                break;
            case DHCP_OPTION_PAD: /* 0 */
                plog("%d", 0);
                break;
            case DHCP_OPTION_END: /* 255 */
                plog("%d", opt);
                end_opt_parsing = 1;
                break;
            default:
                plog("%d", opt);
        }

        optptr = optptr + optsize + 2;        

        optlen = optlen + optsize + 2;

        if (end_opt_parsing == 1) {
            break;
        } else {
            plog(",");
        }
        /* Just to be sure */
        if (*(optptr) != DHCP_OPTION_END) {
            if (optptr + *(optptr+1) + 2 > pi->payload + pi->plen) break;
        }
    }
    plog("\n");
    
    return;
}

void print_data(const uint8_t* data, uint16_t dlen) {
  uint8_t  tbuf[PKT_MAXPAY+2];
  uint8_t* t = tbuf;
  uint8_t  i;
  uint8_t  max = dlen > PKT_MAXPAY ? PKT_MAXPAY : dlen;

  if (!dlen) return;

  for (i=0;i<max;i++) {
    if (isprint(*data)) *(t++) = *data;
      else if (!*data)  *(t++) = '?';
      else *(t++) = '.';
    data++;
  }

  *t = 0;

  plog("%s",tbuf);
}
