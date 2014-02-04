/**
 * \author Torgeir Natvig <torgeir.natvig@redpill-linpro.com>
 */

#include <sys/ipc.h>
#include <sys/shm.h>
#include "../prads.h"
#include "../sys_func.h" // u_ntop
#include "../cxt.h"
#include "log.h"
#include "log_ringbuffer.h"

static int shm_id;
output_plugin p_ringbuffer;

output_plugin *init_log_ringbuffer()
{
    void *buffer;
    key_t key;

    printf("init_log_ringbuffer\n\n");

    key = ftok("/etc/prads/prads.conf", 'R');
    shm_id = shmget(key, sizeof(struct log_ringbuffer), 0640 | IPC_CREAT );
    if (shm_id == -1) {
        perror("shmget");
        return NULL;
    }

    buffer = shmat(shm_id, (void *)0, 0);
    if (buffer == (char *)-1) {
        perror("shmat");
        return NULL;
    }

    memset(buffer, 0, sizeof(struct log_ringbuffer));

    output_plugin tmp = {
        .init = NULL,
        .arp = NULL,
        .os = NULL,
        .service = NULL,
        .connection = &log_ringbuffer_connection,
        .denit = &destory_log_ringbuffer,
        .data = buffer
    };
    p_ringbuffer = tmp;
    return &p_ringbuffer;
}

int destory_log_ringbuffer (output_plugin *plugin)
{
    int rc;

    rc = shmctl(shm_id, IPC_RMID, NULL);
    if (rc == -1)
        perror("shmctl");

    return rc;
}

void log_ringbuffer_connection (output_plugin *plugin, connection *cxt, int outputmode)
{
    unsigned int head;
    struct log_ringbuffer *rb;
    char stime[80], ltime[80];
    time_t tot_time;
//    uint32_t s_ip_t, d_ip_t;
    char src_s[INET6_ADDRSTRLEN];
    char dst_s[INET6_ADDRSTRLEN];

    strftime(stime, 80, "%F %H:%M:%S", gmtime(&cxt->start_time));
    strftime(ltime, 80, "%F %H:%M:%S", gmtime(&cxt->last_pkt_time));
    tot_time = cxt->last_pkt_time - cxt->start_time;

//    if (outputmode != CX_NONE || outputmode || cxt->af == AF_INET6) {
        if (!inet_ntop(cxt->af,
                      (cxt->af == AF_INET6 ? (void*)&cxt->s_ip : (void*)cxt->s_ip.s6_addr32),
                      src_s, sizeof(src_s)))
            perror("inet_ntop");

        if (!inet_ntop(cxt->af,
                      (cxt->af == AF_INET6 ? (void*)&cxt->d_ip : (void*)cxt->d_ip.s6_addr32),
                      dst_s, sizeof(dst_s)))
            perror("inet_ntop");
/*
    } else if (cxt->af == AF_INET) {
        s_ip_t = ntohl(cxt->s_ip.s6_addr32[0]);
        d_ip_t = ntohl(cxt->d_ip.s6_addr32[0]);
    }
*/
    rb = (struct log_ringbuffer*)plugin->data;
    snprintf(rb->items[rb->head].text, sizeof(rb->items[head].text),
        "%ld%09ju|%s|%s|%ld|%u|%s|%u|%s|%u|%ju|%ju|%ju|%ju|%u|%u|%d",
        cxt->start_time,
        cxt->cxid,
        stime,
        ltime,
        tot_time,
        cxt->proto,
        //
        src_s,
        ntohs(cxt->s_port),
        dst_s,
        ntohs(cxt->d_port),
        //
        cxt->s_total_pkts,
        cxt->s_total_bytes,
        cxt->d_total_pkts,
        cxt->d_total_bytes,
        cxt->s_tcpFlags,
        cxt->d_tcpFlags,
        //
        outputmode
    );
    rb->head++;
    if (rb->head >= RINGBUFFER_ITEMS)
        rb->head = 0;
}
