#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/types.h>
#include <errno.h>

#include "output-plugins/log_ringbuffer.h"

int shm_id;

// -------

void sighandler(int sig)
{
    printf("cleaning up\n");
    if (shmctl(shm_id, IPC_RMID, NULL) == -1)
        perror("shmctl");

    exit(0);
}

int init_ringbuffer(struct log_ringbuffer **rb) {
    key_t key;
    void *buffer;

    key = ftok("/etc/prads/prads.conf", 'R');
    shm_id = shmget(key, sizeof(struct log_ringbuffer), 0644 | 0);
    if (shm_id == -1) {
        printf("Could not open ringbuffer. Is prads running?\n");
        exit(1);
    }

    buffer = shmat(shm_id, (void *)0, 0);
    if (buffer == (char*)-1) {
        perror("shmat");
        exit(1);
    }

    *rb = buffer;

    return 0;
}

int main(int argc, char *argv[])
{
    int rc;
    int tail = 0;
    struct log_ringbuffer *ringbuffer;

    if ((rc = init_ringbuffer(&ringbuffer)) != 0) {
        fprintf(stderr, "Could not initialize ringbuffer\n");
        return rc;
    }

    signal(SIGINT, &sighandler);
    signal(SIGTERM, &sighandler);
    tail = ringbuffer->head;

    for(;;) {
        while (tail != ringbuffer->head) {
            printf("%s\n", ringbuffer->items[tail].text);

            tail = (tail == (RINGBUFFER_ITEMS -1)) ? 0 : tail+1;
        }

        usleep(50000);
    }

    return rc;
}

