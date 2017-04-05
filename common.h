#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <signal.h>
#include <errno.h>

#define VERSION "1.2"

extern char *str_replace(char *str, const char *src, const char *dest);
extern void error(char *info);

extern pthread_attr_t attr;
extern pthread_t th_id;
extern struct sockaddr_in addr;
extern socklen_t addr_len;
