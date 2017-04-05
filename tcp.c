#include <sys/epoll.h>
#include <limits.h>
#include <arpa/inet.h>
#include <linux/netfilter_ipv4.h>
#include "main.h"
#include "tcp.h"
#include "common.h"
#include "conf.h"

#define RESPONSE_SIZE 2048
#define BUFF_SIZE 4096

struct http_request {
    int other_len;
    int header_len;
    char *header;
    char *other;
    char *method;
    char *url;
    char *uri;
    char *host;
    char *version;
};

char *def_ssl_req, *http_port;
struct ssl_string *ssl_str;
int listen_port;

inline void free_http_request(struct http_request *http_req)
{
    free(http_req->header);
    free(http_req->other);
    free(http_req->method);
    free(http_req->version);
    if (http_req->url != http_req->uri)
        free(http_req->uri);
    free(http_req->host);
    free(http_req->url);
}

/* 判断请求类型 */
inline int8_t request_type(char *data)
{    
    if (strncmp(data, "GET", 3) == 0 || strncmp(data, "POST", 4) == 0)
        return HTTP;
    else if (strncmp(data, "CONNECT", 7) == 0)
        return HTTP_CONNECT;
    else if (strncmp(data, "HEAD", 4) == 0 ||
    strncmp(data, "PUT", 3) == 0 ||
    strncmp(data, "OPTIONS", 7) == 0 ||
    strncmp(data, "MOVE", 4) == 0 ||
    strncmp(data, "COPY", 4) == 0 ||
    strncmp(data, "TRACE", 5) == 0 ||
    strncmp(data, "DELETE", 6) == 0 ||
    strncmp(data, "LINK", 4) == 0 ||
    strncmp(data, "UNLINK", 6) == 0 ||
    strncmp(data, "PATCH", 5) == 0 ||
    strncmp(data, "WRAPPED", 7) == 0)
        return HTTP_OTHERS;
    else
        return OTHER;
}

inline void rsp_stats_msg(struct tcp_req *tq, char *host)
{
    #define STATUS_REQUEST "HTTP/1.0 200 OK\r\n"\
        "Content-Type: text/plain; charset=utf-8\r\n"\
        "\r\n"\
        "CProxy(" VERSION ") is running\r\n\r\n"\
        "HTTP:\r\n%s\r\n\r\nHTTPS:\r\n%s"
    char message[RESPONSE_SIZE], *https;

    https = str_replace(strdup(def_ssl_req), "[H]", host);
    write(tq->cfd, message, snprintf(message, RESPONSE_SIZE, STATUS_REQUEST, tq->data, https));
    free(https);
}

/* 正则表达式字符串替换，str为可用free释放的指针 */
inline char *reg_strrep(char *str, regex_t *src, char *dest)
{
    if (!str || !dest)
        return str;

    regmatch_t pm[10];
    int match_len, before_len, dest_len, i;
    char child_num[3] = {'\\', '0', '\0'}, *p, *real_dest, *child_match;

    p = str;
    while (regexec(src, p, 10, pm, 0) == 0)
    {
        //不进行不必要的字符串操作
        if (pm[1].rm_so >= 0)
        {
            /* 替换目标字符串中的子表达式 */
            real_dest = strdup(dest);
            if (real_dest == NULL)
            {
                free(str);
                return NULL;
            }
            for (i = 1; i < 10 && pm[i].rm_so >= 0; i++)
            {
                child_match = strndup(p + pm[i].rm_so, pm[i].rm_eo - pm[i].rm_so);
                if (child_match == NULL)
                {
                    free(str);
                    return NULL;
                }
                child_num[1] = i + 48;
                real_dest = str_replace(real_dest, child_num, child_match);
                free(child_match);
                if (real_dest == NULL)
                {
                    free(str);
                    return NULL;
                }
            }
        }
        else
            real_dest = dest;
        dest_len = strlen(real_dest);

        match_len = pm[0].rm_eo - pm[0].rm_so;
        p += pm[0].rm_so;
        //目标字符串不大于匹配字符串则不用分配新内存
        if (match_len >= dest_len)
        {
            strcpy(p, real_dest);
            if (match_len > dest_len)
                strcpy(p + dest_len, p + match_len);
            p += dest_len;
        }
        else
        {
            int str_len, diff;
            char *before_end;
        
            diff = dest_len - match_len;
            str_len = strlen(str) + diff;
            before_len = p - str;
            str = (char *)realloc(str, str_len + 1);
            if (str == NULL)
            {
                if (pm[1].rm_so >= 0)
                    free(real_dest);
                return NULL;
            }
            before_end = str + before_len;
            p = str + str_len;
            while (p - dest_len + 1 != before_end)
            {
                *p = *(p - diff);
                p--;
            }
            memcpy(before_end, real_dest, dest_len);
        }
        if (pm[1].rm_so >= 0)
            free(real_dest);
    }

    return str;
}

/* 获取Host的值 */
inline char *get_host(char *ori_header)
{
    char *begin, *end, *lowerkey_header;

    lowerkey_header = strdup(ori_header);
    if (lowerkey_header == NULL)
        return NULL;
    /* 查找Host的位置 */
    for (begin = strchr(lowerkey_header, '\n'); begin != NULL; begin = strchr(end, '\n'))
    {
        //转换为小写
        for (end = ++begin; *end != ':' && *end != '\0'; end++)
        {
            if (*end >= 65 && *end <= 90)
                *end = *end + 32;
        }
        if (strncmp(begin, "x-online-host", end - begin) == 0)
        {
            begin = end + 1; //这里的begin表示值的开始
            break;
        }
    }
    if (begin == NULL)
    {
        begin = strstr(lowerkey_header, "\nhost:");
        if (begin == NULL)
        {
            free(lowerkey_header);
            return NULL;
        }
        begin += 6;
    }
    
    /* 复制Host */
    while (*begin == ' ' || *begin == '\t')
        begin++;
    end = strchr(begin, '\r');
    if (end)
        begin = strndup(begin, end - begin);
    else
        begin = strdup(begin);

    free(lowerkey_header);
    return begin;
}

/* 删除请求头中的头域 */
inline int8_t del_hdr(char *ori_header, struct modify *head)
{
    struct modify *m;
    char *key_end, *line_begin, *line_end, *tolkey_header;

    tolkey_header = strdup(ori_header);
    if (tolkey_header == NULL)
        return 1;
    line_end = strstr(tolkey_header, "\n\r");
    line_begin = line_end - 2;
    do {
        while(--line_begin > tolkey_header && *line_begin != '\n');
        if (line_begin <= tolkey_header)
            break;
        line_begin++;
        //转换为小写
        for (key_end = line_begin; *key_end != ':' && *key_end != '\0'; key_end++)
        {
            if (*key_end >= 65 && *key_end <= 90)
                *key_end = *key_end + 32;
        }
        //连续删除头域
        m = head;
        do {
            if (strncmp(m->str, line_begin, key_end - line_begin) == 0)
            {
                strcpy(ori_header + (line_begin - tolkey_header), ori_header + (line_end - tolkey_header) + 1);
                break;
            }
            m = m->next;
        } while (m && m->flag == DEL_HDR);
        line_end = --line_begin;
    } while (line_end > tolkey_header);
    free(tolkey_header);

    return 0;
}

inline int8_t parse_connect_request(struct tcp_req *tq, struct http_request *http_req)
{
    char *url_end; //pb0指向请求方法后的空格，pb1指向http版本后的空格

    url_end = strchr(tq->data + 8, ' ');
    if (url_end == NULL)
        return 1;
    http_req->host = strndup(tq->data + 8, url_end - (tq->data + 8));
    if (http_req->host == NULL)
        return 1;
    http_req->header = tq->data;
    http_req->header_len = tq->data_len;

    return 0;
}

inline int8_t parse_http_request(struct tcp_req *tq, struct http_request *http_req)
{
    char *p;

    /* 分离请求头和请求数据 */
    http_req->header = tq->data;
    if ((p = strstr(tq->data, "\n\r")) != NULL && (http_req->header_len = p + 3 - tq->data) < tq->data_len)
    {
        http_req->other_len = tq->data_len - http_req->header_len;
        http_req->other = (char *)malloc(http_req->other_len + 1);
        if (http_req->other)
            memcpy(http_req->other, p + 3, http_req->other_len);
        else
            return 1;
        *(http_req->header + http_req->header_len) = '\0';
    }
    else
    {
        http_req->header_len = tq->data_len;
    }

    /*获取method url version*/
    p = strchr(http_req->header, ' ');
    if (p)
    {
        http_req->method = strndup(http_req->header, p - http_req->header);
        p++;
        http_req->version = strchr(p, '\r'); //http版本后的\r
        if (http_req->version)
        {
            http_req->url = strndup(p, http_req->version - p - 9);
            http_req->version = strndup(http_req->version - 8, 8);
        }
    }

    http_req->host = get_host(http_req->header);
     //如果请求头中没有Host，则设置为原始IP和端口
    if (http_req->host == NULL)
    {
         http_req->host = (char *)malloc(22); //IP最大长度(15) + :的长度(1) + 端口最大长度(5) + 1
         if (http_req->host == NULL)
             return 1;
         sprintf(http_req->host, "%s:%d", tq->ori_ip, tq->ori_port);
    }

    if (http_req->url)
    {
        if (*http_req->url != '/' && (p = strstr(http_req->url, "//")) != NULL)
        {
            p = strchr(p+2, '/');
            if (p)
                http_req->uri = strdup(p);
            else
                http_req->uri = strdup("/");
        }
        else
            http_req->uri = http_req->url;
    }

    return 0;
}

/*
    修改请求头
   返回值: -1为错误，0为需要代理的请求，1为不需要代理的请求
 */
int8_t modify_request(struct tcp_req *tq)
{
    struct http_request http_req;
    struct modify *mod;
    char *p, *new_header;
    int string_len;

    //判断数据类型
    switch(tq->type)
    {
        case HTTP_OTHERS:
            if (conf.http_only_get_post)
                return 1;
            //不禁止其他http请求则进行http处理

        case HTTP:
            mod = conf.http.m;
            memset((struct http_request *)&http_req, 0, sizeof(http_req));
            if (parse_http_request(tq, &http_req) != 0)
                goto error;
            break;

        case HTTP_CONNECT:
            mod = conf.https.m;
            memset((struct http_request *)&http_req, 0, sizeof(http_req));
            if (parse_connect_request(tq, &http_req) != 0)
                return -1;
            break;

        //不是http请求头，无需修改
        default:
            return 0;
    }

    while (mod)
    {
        switch (mod->flag)
        {
            case DEL_HDR:
                if (del_hdr(http_req.header, mod) != 0)
                    goto error;
                //del_hdr函数连续删除头域一次性操作
                while (mod->next && mod->next->flag == DEL_HDR)
                    mod = mod->next;
                break;
            
            case SET_FIRST:
                p = strchr(http_req.header, '\n');
                if (p == NULL)
                {
                    free(http_req.header);
                    http_req.header = strdup(mod->str);
                    if (http_req.header == NULL)
                        goto error;
                }
                else
                {
                    p++;
                    string_len = strlen(mod->str);
                    new_header = (char *)malloc(string_len + strlen(p) + 1);
                    if (new_header == NULL)
                        goto error;
                    strcpy(new_header, mod->str);
                    strcpy(new_header + string_len, p);
                    free(http_req.header);
                    http_req.header = new_header;
                }
                break;
            
            case STRREP:
                http_req.header = str_replace(http_req.header, mod->str, mod->dest);
                if (http_req.header == NULL)
                    goto error;
                break;
            
            //case REGREP:
            default:
                http_req.header = reg_strrep(http_req.header, &mod->reg_src, mod->dest);
                if (http_req.header == NULL)
                    goto error;
                break;
        }
        mod = mod->next;
    }
    if (tq->type != HTTP_CONNECT)
    {
        http_req.header = str_replace(http_req.header, "[M]", http_req.method);
        http_req.header = str_replace(http_req.header, "[U]", http_req.uri);
        http_req.header = str_replace(http_req.header, "[url]", http_req.url);
        http_req.header = str_replace(http_req.header, "[V]", http_req.version);
        if (conf.http_download_max_size > 0 && (p = strstr(http_req.header, "bytes=")) != NULL)
        {
            unsigned long long minsize, maxsize;
            char *lf;

            p += 6;
            minsize = strtoull(p, NULL, 10);
            lf = strchr(p, '\n');
            p = strchr(p, '-');
            if (p && (lf && p < lf))
            {
                maxsize = strtoull(++p, NULL, 10);
                if (maxsize == 0 || maxsize - minsize > conf.http_download_max_size)
                {
                    char dest[21]; //unsigned long long转换为字符串最长为20个字节
                    int before_len, diff, src_len, dest_len;
                    char *before_end;
                    
                    before_len = p - http_req.header;
                    src_len = lf - 1 - p;
                    dest_len = sprintf(dest, "%llu", minsize + conf.http_download_max_size);
                    diff = dest_len - src_len;
                    http_req.header_len = strlen(http_req.header) + diff;
                    http_req.header = (char *)realloc(http_req.header, http_req.header_len + 1);
                    if (http_req.header == NULL)
                        goto error;
                    before_end = http_req.header + before_len;
                    p = http_req.header + http_req.header_len;
                    while (p - dest_len + 1 != before_end)
                    {
                        *p = *(p - diff);
                        p--;
                    }
                    memcpy(before_end, dest, dest_len);
                }
            }
        }
    }
    http_req.header = str_replace(http_req.header, "[H]", http_req.host);
    if (http_req.header == NULL)
        goto error;
    http_req.header_len = strlen(http_req.header);

    /* 连接修改后的请求头和其他数据 */
    if (http_req.other == NULL)
    {
        tq->data = http_req.header;
        tq->data_len = http_req.header_len;
        http_req.header = NULL;
    }
    else
    {
        /*
        //修改多个请求头
        tq->data = http_req.other;
        tq->data_len = http_req.other_len;
        if (modify_request(tq) != 0)
        {
            goto error;
        }
        http_req.other = tq->data;
        http_req.other_len = tq->data_len;
        */
        tq->data_len = http_req.header_len + http_req.other_len;
        tq->data = (char *)realloc(http_req.header, tq->data_len + 1);
        http_req.header = NULL;
        if (tq->data == NULL)
            goto error;
        memcpy(tq->data + http_req.header_len, http_req.other, http_req.other_len);
        *(tq->data + tq->data_len) = '\0';
    }
    //检测状态uri
    if (http_req.uri && strcmp(http_req.uri, "/cp") == 0)
    {
        rsp_stats_msg(tq, http_req.host);
        free_http_request(&http_req);
        return 1;
    }
    //记录Host，之后构建CONNECT请求可能需要
    if (tq->host == NULL)
    {
        tq->host = http_req.host;
        http_req.host = NULL;
    }
    free_http_request(&http_req);
    return 0;

    error:
    tq->data = NULL;
    free_http_request(&http_req);
    return -1;
}

/*
    读取fd数据，主要用来读取完整的HTTP请求头，以便修改
*/
inline void read_data(char *buff, struct tcp_req *tq)
{
    int buff_len;
    //char *head, *tail;

    tq->data_len = 0;
    //tq->data = NULL;
    do {
        buff_len = read(tq->cfd, buff, BUFF_SIZE);
        if (buff_len <= 0)
        {
            free(tq->data);
            tq->data = NULL;
            return;
        }
        tq->data = realloc(tq->data, tq->data_len + buff_len + 1);
        if (tq->data == NULL)
            return;
        memcpy(tq->data + tq->data_len, buff, buff_len);
        tq->data_len += buff_len;
        *(tq->data + tq->data_len) = '\0';
    /*
        //多个HTTP请求读取完整才返回
        for (head = tq->data; ; head = tail + 3)
        {
            if (request_type(head) == OTHER)
                return;
            tail = strstr(head, "\n\r\n");
            if (tail == NULL)
                break;
        }
    } while (1);
    */
    //如果读取到的数据等于BUFF_SIZE则判断为还有数据可读
    } while ((tq->type = request_type(tq->data)) != OTHER && strstr(tq->data, "\n\r\n") == NULL);
}

int8_t make_CONNECT(struct tcp_req *tq, int sfd)
{
    char rsp_buff[RESPONSE_SIZE + 1];
    int rsp_len;
    char *connect_request, *p;

    /* 建立CONNECT请求 */
    if (tq->ori_port == listen_port && tq->host)
    {
        p = strchr(tq->host, ':');
        if (p == NULL)
        {
            int host_len = strlen(tq->host);
            tq->host = realloc(tq->host, host_len + 4);
            if (tq->host == NULL)
                return 1;
            strcpy(tq->host + host_len, ":80");
        }
        connect_request = str_replace(strdup(def_ssl_req), "[H]", tq->host);
    }
    else
    {
        char original_dest[22];
        sprintf(original_dest, "%s:%d", tq->ori_ip, tq->ori_port);
        connect_request = str_replace(strdup(def_ssl_req), "[H]", original_dest);
    }
    if (connect_request == NULL)
        return 1;
    /* 发送CONNECT请求 */
    if (write(sfd, connect_request, strlen(connect_request)) == -1)
    {
        free(connect_request);
        return 1;
    }
    free(connect_request);
    /* 读取回应 */
    rsp_len = read(sfd, rsp_buff, RESPONSE_SIZE);
    if (rsp_len <= 0)
        return 1;
    rsp_buff[rsp_len] = '\0';
    p = rsp_buff;
    while ((p = strstr(p, "\n\r\n")) == NULL)
    {
        p = rsp_buff + rsp_len;
        rsp_len = read(tq->sfd, p, RESPONSE_SIZE - rsp_len);
        if (rsp_len <= 0)
            return 1;
        p[rsp_len] = '\0';
        rsp_len += p - rsp_buff;
        p -= 2;
    }
    //如果\r\n\r\n后还有数据则可能为服务端返回给客户端的数据
    if (write(tq->cfd, p + 3, rsp_len - (p + 3 - rsp_buff)) == -1)
        return 1;

    return 0;
}

int build_tcp_connection(struct sockaddr_in *dst)
{
    int fd;

    /* 连接目标地址 */
    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
    {
        //perror("socket");
        return -1;
    }
    if (connect(fd, (struct sockaddr *)dst, sizeof(*dst)) != 0)
    {
        //perror("connect");
        close(fd);
        return -1;
    }

    return fd;
}

/* 处理连接数据 */
void handle_data(int *cfd)
{
    char buff[BUFF_SIZE];
    struct tcp_req tq;
    struct sockaddr_in ori_dst;
    struct epoll_event ev;
    struct ssl_string *https_string;
    int efd;
    int8_t first_connection, connect_handle; //判断是否做CONNECT处理

    tq.cfd = *cfd;
    free(cfd);
    tq.data = tq.host = NULL;
    tq.type = first_connection = connect_handle = 0;
    tq.sfd = -1;
    efd = epoll_create(2);
    if (efd < 0)
    {
        //perror("epoll_create");
        close(tq.cfd);
        return;
    }
    ev.events = EPOLLIN;
    ev.data.fd = tq.cfd;
    epoll_ctl(efd, EPOLL_CTL_ADD, tq.cfd, &ev);
    getsockopt(tq.cfd, SOL_IP, SO_ORIGINAL_DST, &ori_dst,  &addr_len);
    strcpy(tq.ori_ip, inet_ntoa(ori_dst.sin_addr));
    tq.ori_port = ntohs(ori_dst.sin_port);
    if (conf.client_timeout > 0)
    {
        switch (epoll_wait(efd, &ev, 1, conf.client_timeout))
        {
            case 0:
                first_connection = 1;
                break;

            case -1:
                goto end;
        }
    }
    else if (http_port)
    {
        char port_string[6];
        sprintf(port_string, "%d", tq.ori_port);
        if (strstr(http_port, port_string) == NULL)
            first_connection = 1;
    }
    if (first_connection == 0)
    {
        read_data(buff, &tq);
        if (tq.data == NULL || modify_request(&tq) != 0)
            goto end;
    }
    else
    {
        tq.type = OTHER;
        tq.data_len = 0;
    }

    //[不是普通http请求/wap_connect 所有数据]/[net_connect HTTP非80 8080端口]   CONNECT处理
    if (tq.type == OTHER ||
    conf.mode == WAP_CONNECT ||
    (conf.mode == NET_CONNECT && tq.ori_port != 80 && tq.ori_port != 8080))
    {
        connect_handle = 1;
        tq.sfd = build_tcp_connection(&conf.https.dst);
    }
    //[wap HTTP数据]/[net_proxy HTTP非80 8080端口]
    else if (conf.mode == WAP || (conf.mode == NET_PROXY && tq.ori_port != 80 && tq.ori_port != 8080))
    {
        //CONNECT处理字符串
        https_string = ssl_str;
        while (https_string)
        {
            if (strstr(tq.data, https_string->str) != NULL)
            {
                connect_handle = 1;
                break;
            }
            https_string = https_string->next;
        }
        if (connect_handle == 0 && tq.type != HTTP_CONNECT)
            tq.sfd = build_tcp_connection(&conf.http.dst);
        else
            tq.sfd = build_tcp_connection(&conf.https.dst);
    }
    //直连目标地址
    else
    {
        tq.sfd = build_tcp_connection(&ori_dst);
    }
    if (tq.sfd < 0)
        goto end;
    ev.data.fd = -1;
    //ev.data.fd = tq.sfd;
    ev.events = EPOLLIN;
    epoll_ctl(efd, EPOLL_CTL_ADD, tq.sfd, &ev);

    /* 发送首次读取到的客户端数据 */
    if (connect_handle && tq.type != HTTP_CONNECT && make_CONNECT(&tq, tq.sfd) != 0)
        goto end;
    if (write(tq.sfd, tq.data, tq.data_len) == -1)
    {
        //perror("write");
        goto end;
    }
    free(tq.data);
    tq.data = NULL;

    while (epoll_wait(efd, &ev, 1, -1) > 0)
    {
        if (ev.data.fd == tq.cfd)
        {
            read_data(buff, &tq);
            if (tq.data == NULL)
                break;
            if (first_connection == 1)
            {
                first_connection = 0;
                if (tq.type != OTHER && conf.mode != WAP_CONNECT && !(conf.mode == NET_CONNECT && tq.ori_port != 80 && tq.ori_port != 8080))
                {
                    for (https_string = ssl_str; https_string && strstr(tq.data, https_string->str) == NULL; https_string = https_string->next);
                    if (https_string == NULL)
                    {
                        epoll_ctl(efd, EPOLL_CTL_DEL, tq.sfd, NULL);
                        close(tq.sfd);
                        if (conf.mode == WAP || (conf.mode == NET_PROXY && tq.ori_port != 80 && tq.ori_port != 8080))
                            tq.sfd = build_tcp_connection(&conf.http.dst);
                        else
                            tq.sfd = build_tcp_connection(&ori_dst);
                        if (tq.sfd < 0)
                            break;
                        ev.data.fd = -1;
                        //ev.data.fd = tq.sfd;
                        epoll_ctl(efd, EPOLL_CTL_ADD, tq.sfd, &ev);
                    }
                }
            }
            if (modify_request(&tq) != 0 || write(tq.sfd, tq.data, tq.data_len) == -1)
                break;
            free(tq.data);
            tq.data = NULL;
        }
        else if (write(tq.cfd, buff, read(tq.sfd, buff, BUFF_SIZE)) <= 0)
            break;
    }

    end:
    close(tq.cfd);
    close(tq.sfd);
    close(efd);
    free(tq.host);
    free(tq.data);
    //printf("a  connection close.\n");
}

int tcp_listen(char *ip, int port)
{
    int fd, optval = 1;

    if ((fd = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    {
        perror("socket");
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (ip)
        addr.sin_addr.s_addr = inet_addr(ip);
    else
        addr.sin_addr.s_addr = INADDR_ANY;
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0)
    {
        close(fd);
        perror("setsockopt");
        return -1;
    }
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        perror("bind");
        return -1;
    }
    if (listen(fd, 10) != 0)
    {
        close(fd);
        perror("listen");
        return -1;
    }

    listen_port = port;
    return fd;
}

void tcp_loop()
{
    int *cfd;

    /* 循环处理请求 */
    while (1)
    {
        cfd = malloc(sizeof(int));
        if (cfd == NULL)
            continue;
        wait_new_connection:
        *cfd = accept(conf.tcp_listen_fd, (struct sockaddr *)&addr, &addr_len);
        if (*cfd < 0)
        {
            //perror("accept");
            if (errno == EINTR || errno == ENFILE || errno == ECONNABORTED)
            {
                sleep(3);
                goto wait_new_connection;
            }
            return;
        }
        pthread_create(&th_id, &attr, (void *)&handle_data, cfd);
    }
    close(conf.tcp_listen_fd);
}

