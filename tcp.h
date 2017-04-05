#include <netinet/in.h>

#define CONNECT_HEADER "CONNECT [H] HTTP/1.1\r\n\r\n"
/* 数据类型 */
#define OTHER 1
#define HTTP 2
#define HTTP_OTHERS 3
#define HTTP_CONNECT 4
/* 请求头修改操作 */
#define SET_FIRST 1
#define DEL_HDR 2
#define REGREP 3
#define STRREP 4
/* 处理TCP请求模式 */
#define WAP 1
#define WAP_CONNECT 2
#define NET_CONNECT 3
#define NET_PROXY 4

struct ssl_string {
    char *str;
    struct ssl_string *next;
};

struct tcp_req {
    char ori_ip[16]; //TCP包原始IP
    int cfd;
    int sfd;
    int data_len;
    char *data;
    char *host; //保存请求头中的Host
    uint16_t ori_port; //TCP包原始端口
    unsigned type :4; //请求的类型
};

extern int tcp_listen(char *ip, int port);
extern int8_t request_type(char *data);
extern void tcp_loop();
extern void rsp_stats_msg(struct tcp_req *tq, char *host);
extern int build_tcp_connection(struct sockaddr_in *dst);
extern int8_t make_CONNECT(struct tcp_req *tq, int sfd);
extern int8_t modify_request(struct tcp_req *tq);

extern struct ssl_string *ssl_str;
extern char *def_ssl_req, *http_port;
