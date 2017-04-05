#include "main.h"
#include "conf.h"
#include "tcp.h"
#include "common.h"
#include "httpdns.h"

#define DNS_REQ_SIZE   512
#define HTTP_RSP_SIZE  1024

struct dnsarg {
    char udp_req[DNS_REQ_SIZE+1];
    struct sockaddr_in src_addr;
};
struct dns_request {
    char *host;
    char type;
    unsigned host_len :7; //域名最大长度64位
};
struct dns_cache {
    int question_len;
    char *question;
    char *answer;
    struct dns_cache *next;
};

//当请求为IP查询域名类型时，返回固定的域名，不联网检查以节省资源，开头的0为域名字段的长度，启动时会自动修改该值
char PTR_domain[] = {0, 3, 'w', 'w', 'w', 9, 'm', 'm', 'm', 'd', 'b', 'y', 'b', 'y', 'd', 4, 'c', 'l', 'u', 'b', 0};
/* 缓存变量 */
int cache_using;
FILE *cfp = NULL;
struct dns_cache *cache, *cache_temp;
pthread_mutex_t dns_cache_mutex;

int8_t read_cache_file()
{
    long file_size;
    char *buff, *answer, *question;

    cache = cache_temp = NULL;
    cache_using = 0;
    if ((cfp = fopen(conf.dns.cachePath, "rb+")) == NULL)
    {
        //保持文件打开状态，防止切换uid后权限不足导致无法写入文件
        if ((cfp = fopen(conf.dns.cachePath, "wb")) == NULL)
            return 1;
        else
            return 0;
    }

    //读取文件内容
    fseek(cfp, 0, SEEK_END);
    file_size = ftell(cfp);
    if ((buff = (char *)alloca(file_size+1)) == NULL)
    {
        fclose(cfp);
        return 1;
    }
    rewind(cfp);
    fread(buff, file_size, 1, cfp);
    //*(buff + file_size) = '\0';

    //读取缓存，一组缓存的内容为[ipDomain\0]，其中ip占5字节
    for (answer = buff; answer - buff < file_size; answer = question + cache->question_len + 2)
    {
        cache_temp = (struct dns_cache *)malloc(sizeof(*cache));
        if (cache_temp == NULL)
            return 1;
        cache_temp->next = cache;
        cache = cache_temp;
        cache_using++;
        cache->answer = strndup(answer, 5);
        question = answer + 5;
        cache->question = strdup(question);
        if (cache->question == NULL || cache->answer == NULL)
            return 1;
        cache->question_len = strlen(question)-1;
    }
    /* 删除重复记录 */
    struct dns_cache *before, *after;
    for (; cache_temp; cache_temp = cache_temp->next)
    {
        for (before = cache_temp; before && (after = before->next) != NULL; before = before->next)
        {
            if (strcmp(after->question, cache_temp->question) == 0)
            {
                before->next = after->next;
                free(after->question);
                free(after->answer);
                free(after);
            }
        }
    }

    fclose(cfp);
    cfp = fopen(conf.dns.cachePath, "wb");
    return 0;
}

void write_dns_cache()
{
    while (cache)
    {
        fputs(cache->answer, cfp);
        fputs(cache->question, cfp);
        fputc('\0', cfp);
        cache = cache->next;
    }

    exit(0);
}

inline char *cache_lookup(char *question, struct dns_request *dns_req)
{
    struct dns_cache *c;

    c = cache;
    while (c)
    {
        if (strcmp(c->question, question) == 0)
        {
            dns_req->host_len = c->question_len;
            dns_req->type = 1;
            return c->answer;
        }
        c = c->next;
    }

    return NULL;
}

inline void cache_record(char *question, int question_len, char *answer)
{
    pthread_mutex_lock(&dns_cache_mutex);
    cache_temp = (struct dns_cache *)malloc(sizeof(*cache));
    if (cache_temp == NULL)
        return;
    cache_temp->question = strdup(question);
    if (cache_temp->question == NULL)
    {
        free(cache_temp);
        return;
    }
    cache_temp->next = cache;
    cache = cache_temp;
    cache->question_len = question_len;
    cache->answer = answer;
    if (conf.dns.cacheLimit)
    {
        //到达缓存记录条目限制则释放前一半缓存
        if (conf.dns.cacheLimit <= cache_using)
        {
            int i;
            struct dns_cache *free_c;
            for (i = cache_using = conf.dns.cacheLimit / 2; i--; cache_temp = cache_temp->next);
            for (free_c = cache_temp->next, cache_temp->next = NULL; free_c; free_c = cache_temp)
            {
                cache_temp = free_c->next;
                free(free_c);
            }
        }
        cache_using++;
    }
    pthread_mutex_unlock(&dns_cache_mutex);
}

/* 分析DNS请求 */
inline int8_t parse_dns_request(char *udp_req, struct dns_request *dns_req)
{
    //跳到域名部分
    udp_req += 13;
    dns_req->host_len = strlen(udp_req);
    //判断请求类型
    switch ((dns_req->type = *(udp_req + 2 + dns_req->host_len)))
    {
        case 1:    //只查询ipv4地址
            dns_req->host = strdup(udp_req);
            if (dns_req->host == NULL)
                return 1;
            int len;
            for (len = *(--udp_req); udp_req[len+1] != 0; len += udp_req[len])
            {
                //防止越界
                if (len > dns_req->host_len)
                    return 1;
                dns_req->host[len++] = '.';
            }
            return 0;
        default:
            return 1;
    }
}

/* 建立DNS回应 */
void build_dns_reponse(struct sockaddr_in *client, struct dns_request *dns_req, char *reply, char *udp_req)
{
    char *dns_rsp, *p;
    int dns_rsp_len;

    //18: 查询资源的前(12字节)后(6字节)部分
    if (reply)
        dns_rsp_len = 18 + dns_req->host_len + 12 + *reply;
    else
        dns_rsp_len = 18 + dns_req->host_len;
    dns_rsp = (char *)alloca(dns_rsp_len);
    if (dns_req == NULL)
        return;
    /* 回应标识ID */
    dns_rsp[0] = udp_req[0];
    dns_rsp[1] = udp_req[1];
    /* 回应标志 */
    /*
    //在下面的代码赋值
    dns_rsp[2]
    dns_rsp[3]
    */
    /* 问题数 */
    dns_rsp[4] = 0;
    dns_rsp[5] = 1;
    /* 资源记录数 */
    dns_rsp[6] = 0;
    dns_rsp[7] = 0;
    /* 授权资源记录数 */
    dns_rsp[8] = 0;
    dns_rsp[9] = 0;
    /* 额外资源记录数 */
    dns_rsp[10] = 0;
    dns_rsp[11] = 0;
    /* 查询内容 */
    memcpy(dns_rsp + 12, udp_req + 12, dns_req->host_len + 6);
    /* 如果有回应内容(资源记录) */
    if (reply)
    {
        p = dns_rsp + 18 + dns_req->host_len;
        //资源记录数+1
        dns_rsp[7]++;
        /* 成功标志 */
        dns_rsp[2] = 133;
        dns_rsp[3] = 128;
        /* 指向主机域名 */
        p[0] = 192;
        p[1] = 12;
        /* 回应类型 */
        p[2] = 0;
        p[3] = dns_req->type;
        /* 区域类别 */
        p[4] = 0;
        p[5] = 1;
        /* 生存时间 (1 ora) */
        p[6] = 0;
        p[7] = 0;
        p[8] = 14;
        p[9] = 16;
        /* 回应长度 */
        p[10] = 0;
        //p[11] = 4;  //reply中包含回应长度
        strcpy(p+11, reply);
    }
    else
    {
        /* 失败标志 */
        dns_rsp[2] = 129;
        dns_rsp[3] = 130;
    }
    
    sendto(conf.dns_listen_fd, dns_rsp, dns_rsp_len, 0, (struct sockaddr *)client, sizeof(*client));
}


inline char *http_lookup(char *domain)
{
    char buff[HTTP_RSP_SIZE + 1];
    int sfd, len, i;
    //reply储存转换为10进制后的ip地址
    char *reply = NULL, *ip_ptr, *p, *http_request;

    sfd = build_tcp_connection(&conf.dns.dst);
    if (sfd < 0)
        return NULL;
    //建立CONNECT连接
    if (conf.dns.https_req)
    {
        if (write(sfd, conf.dns.https_req, conf.dns.https_req_len) == -1)
        {
            close(sfd);
            return NULL;
        }
        do {
            len = read(sfd, buff, HTTP_RSP_SIZE+1);
            if (len <= 0)
            {
                close(sfd);
                return NULL;
            }
        } while (len == HTTP_RSP_SIZE+1);
    }

    http_request = str_replace(strdup(conf.dns.http_req), "[D]", domain);
    if (http_request == NULL)
        goto error;
    if ((write(sfd, http_request, strlen(http_request))) == -1)
    {
        free(http_request);
        //perror("dns write");
        goto error;
    }
    free(http_request);
    len = read(sfd, buff, HTTP_RSP_SIZE);
    if (len <= 0)
        goto error;
    buff[len] = '\0';

    /* 读取HTTP回应包中的IP */
    p = strstr(buff, "\n\r\n");
    if (p == NULL)
        goto error;
    p += 3;
    //如果\r\n\r\n结束则再次读取数据
    if (*p == '\0')
    {
        len = read(sfd, buff, HTTP_RSP_SIZE);
        if (len <= 0)
            goto error;
        buff[len] = '\0';
        p = buff;
    }
    reply = (char *)malloc(6);
    if (reply == NULL)
        goto error;
    do {
        if (*p == '\n')
            p++;
        /* 匹配IP */
        if (*p  > 57 || *p < 49)
            continue;
        for (i = 0, ip_ptr = p, p = strchr(ip_ptr, '.'); ; p = strchr(ip_ptr, '.'))
        {
            if (i < 3)
            {
                if (p == NULL)
                    goto error;
                if (p - ip_ptr > 3)
                    break;
                reply[++i] = atoi(ip_ptr);
            }
            else
            {
                close(sfd);
                reply[++i] = atoi(ip_ptr);
                reply[0] = 4;
                reply[5] = '\0';
                return reply;
            }
            ip_ptr = p + 1;
        }
    } while ((p = strchr(p, '\n')) != NULL);

    error:
    close(sfd);
    free(reply);
    return NULL;
}

void handle_dns(struct dnsarg *arg)
{
    struct dns_request dns_req;
    char *reply;

    if (cfp == NULL || (reply = cache_lookup(arg->udp_req+12, &dns_req)) == NULL)
    {
        if (parse_dns_request(arg->udp_req, &dns_req) == 0)
        {
            if ((reply = http_lookup(dns_req.host)) != NULL && cfp)
                cache_record(arg->udp_req+12, dns_req.host_len, reply);
            free(dns_req.host);
        }
        else if (dns_req.type == 12)
            reply = PTR_domain;
        else
            reply = NULL;
    }
    build_dns_reponse(&arg->src_addr, &dns_req, reply, arg->udp_req);
    if (cfp == NULL && dns_req.type != 12)
        free(reply);
    free(arg);
}

void dns_loop()
{
    struct dnsarg *arg;
    int dns_req_len;

    PTR_domain[0] = sizeof(PTR_domain) - 1;
    while (1)
    {
        arg = (struct dnsarg *)malloc(sizeof(*arg));
        if (arg == NULL)
            continue;
        rewait:
        dns_req_len = recvfrom(conf.dns_listen_fd, arg->udp_req, DNS_REQ_SIZE, 0, (struct sockaddr *)&arg->src_addr, &addr_len);
        //DNS请求必须大于18字节
        if (dns_req_len <= 18)
            goto rewait;
        arg->udp_req[dns_req_len - 5] = 0; //防止非DNS请求导致数组越界
        arg->udp_req[dns_req_len] = '\0';
        pthread_create(&th_id, &attr, (void *)&handle_dns, arg);
    }
}

int udp_listen(char *ip, int port)
{
    int fd;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0)
    {
        perror("udp socket");
        return -1;
    }
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (ip)
        addr.sin_addr.s_addr = inet_addr(ip);
    else
        addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) != 0)
    {
        close(fd);
        perror("udp bind");
        return -1;
    }

    return fd;
}
