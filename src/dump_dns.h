/* dump_dns.c - library function to emit decoded dns message on a FILE.
 *
 */

void
dump_dns(const u_char *payload, size_t paylen,
          FILE *trace, const char *endline,
          const char *src_ip, time_t ts);
