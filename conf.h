#include <regex.h>
#include <ctype.h>
#include <arpa/inet.h>

extern void read_conf(char *path);

struct modify {
    unsigned flag :3; //判断修请求头的操作
    char *str;
    regex_t reg_src;
    char *dest;
    struct modify *next;
};

struct tcp_conf {
    struct sockaddr_in dst;
    struct modify *m;
};

struct httpdns_conf {
    struct sockaddr_in dst;
    char *https_req;
    int https_req_len;
    char *http_req;
    char *cachePath;
    int cacheLimit;
};

struct config {
    //global部分
    unsigned long long http_download_max_size;
    unsigned mode :3;
    int uid;
    int client_timeout; //TCP首次读取客户端数据超时
    unsigned http_only_get_post :1;
    int tcp_listen_fd;
    int dns_listen_fd;

    //http部分
    struct tcp_conf http;    
    //https部分
    struct tcp_conf https;
    //httpdns部分
    struct httpdns_conf dns;
};


extern struct config conf;
