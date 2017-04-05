#include <sys/stat.h>
//#include <netdb.h>

#define HTTPDNS_REQUEST "GET /d?dn=[D] HTTP/1.0\r\nHost: [H]\r\n\r\n"

extern void write_dns_cache();
extern void dns_loop();
extern int8_t read_cache_file();
extern int udp_listen(char *ip, int port);

//设置dns缓存的互斥锁，防止多线程环境下同时写入缓存文件导致缓存文件错误
extern pthread_mutex_t dns_cache_mutex;

