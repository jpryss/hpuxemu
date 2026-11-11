/* System V IPC between a parent and a child: a shared memory segment, a semaphore
   handshake and a message queue. K&R C for HP's bundled cc. */
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include <sys/msg.h>

struct mymsg { long mtype; char text[32]; };

int main(argc, argv) int argc; char **argv; {
    int shmid, semid, msqid, i; char *p; struct sembuf op; struct mymsg m; struct shmid_ds ds;
    shmid = shmget(IPC_PRIVATE, 8192, IPC_CREAT | 0600);
    semid = semget(IPC_PRIVATE, 1, IPC_CREAT | 0600);
    msqid = msgget(IPC_PRIVATE, IPC_CREAT | 0600);
    if (shmid < 0 || semid < 0 || msqid < 0) { perror("get"); return 1; }
    semctl(semid, 0, SETVAL, 0);
    p = (char *) shmat(shmid, 0, 0);
    if (p == (char *) -1) { perror("shmat"); return 1; }
    strcpy(p, "nothing yet");
    if (fork() == 0) {
        for (i = 0; i < 4096; i++) p[4096 + i] = i;
        strcpy(p, "written by the child");
        op.sem_num = 0; op.sem_op = 1; op.sem_flg = 0;
        semop(semid, &op, 1);                  /* signal */
        m.mtype = 7; strcpy(m.text, "a message from the child");
        msgsnd(msqid, (char *) &m, strlen(m.text) + 1, 0);
        _exit(0);
    }
    op.sem_num = 0; op.sem_op = -1; op.sem_flg = 0;
    semop(semid, &op, 1);                      /* wait for the child */
    printf("shared memory says: %s\n", p);
    for (i = 0; i < 4096; i++) if (p[4096 + i] != (char) i) { printf("byte %d wrong\n", i); break; }
    if (msgrcv(msqid, (char *) &m, sizeof m.text, 7, 0) < 0) perror("msgrcv");
    printf("message type %ld: %s\n", m.mtype, m.text);
    shmctl(shmid, IPC_STAT, &ds);
    printf("segment of %d bytes, %d attached\n", ds.shm_segsz, ds.shm_nattch);
    wait(0);
    shmdt(p);
    shmctl(shmid, IPC_RMID, 0); semctl(semid, 0, IPC_RMID, 0); msgctl(msqid, IPC_RMID, 0);
    printf("done\n");
    return 0;
}
