#include "main.h"
#include "tcp.h"
#include "common.h"
#include "httpdns.h"
#include "conf.h"

struct config conf;

/* HTTPS模式的字符串提前修改 */
char *ssl_req_replace(char *str)
{
    str = str_replace(str, "[M]", "CONNECT");
    str = str_replace(str, "[V]", "HTTP/1.1");
    str = str_replace(str, "[U]", "/");
    return str_replace(str, "[url]", "[H]");
}

/* 字符串预处理 */
char *string_pretreatment(char *str)
{
    //删除换行和缩进
    char *lf, *p;
    while ((lf = strchr(str, '\n')) != NULL)
    {
        for (p = lf + 1; *p == ' ' || *p == '\t' || *p == '\n' || *p == '\r'; p++);
        strcpy(lf, p);
    }
    str_replace(str, "\r", "");  //Windows换行是\r\n
    //替换转义字符
    str_replace(str, "\\t", "\t");
    str_replace(str, "\\r", "\r");
    return str_replace(str, "\\n", "\n");
}

/* 在content中，定位变量的首地址，值的位置首地址和末地址 */
int8_t location_var_val(char *content, char **var, char **val_begin, char **val_end)
{
    char *p, *pn;

    while (1)
    {
        if (content == NULL)
            return 1;

        for (;*content == ' ' || *content == '\t' || *content == '\r' || *content == '\n'; content++);
        if (*content == '\0')
            return 1;
        *var = content;
        pn = strchr(content, '\n');
        p = strchr(content, '=');
        if (p == NULL)
        {
            if (pn)
            {
                content = pn + 1;
                continue;
            }
            else
                return 1;
        }
        content = p;
        //将变量以\0结束
        for (p--; *p == ' ' || *p == '\t'; p--);
        *(p+1) = '\0';
        //值的首地址
        for (content++; *content == ' ' || *content == '\t'; content++);
        if (*content == '\0')
            return 1;
        //双引号引起来的值支持换行
        if (*content == '"')
        {
            *val_begin = content + 1;
            *val_end = strstr(*val_begin, "\";");
            if (*val_end != NULL)
                break;
        }
        else
            *val_begin = content;
        *val_end = strchr(content, ';');
        if (*val_end == NULL)
            return 1;
        if (pn && *val_end > pn)
        {
            content = pn + 1;
            continue;
        }
        break;
    }

    *(*val_end)++ = '\0';
    string_pretreatment(*val_begin);
    //printf("var[%s]\nbegin[%s]\n\n", *var, *val_begin);
    return 0;
}

/* 在buff中读取模块内容 */
char *read_module(char *buff, char *module_name)
{
    int len;
    char *p, *p0;

    len = strlen(module_name);
    p = buff;
    while (1)
    {
        while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
            p++;
        if (strncasecmp(p, module_name, len) == 0)
        {
            p += len;
            while (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')
                p++;
            if (*p == '{')
                break;
        }
        if ((p = strchr(p, '\n')) == NULL)
            return NULL;
    }
    if ((p0 = strchr(++p, '}')) == NULL)
        return NULL;

    //printf("%s\n%s", module_name, content);
    return strndup(p, p0 - p);
}

int8_t parse_global_module(char *content)
{
    char *var, *val_begin, *val_end, *p;
    uint16_t port;

    while (location_var_val(content, &var, &val_begin, &val_end) == 0)
    {
        if (strcasecmp(var, "mode") == 0)
        {
            if (strcasecmp(val_begin, "wap_connect") == 0)
                conf.mode = WAP_CONNECT;
           else  if (strcasecmp(val_begin, "wap") == 0)
                conf.mode = WAP;
           else  if (strcasecmp(val_begin, "net_connect") == 0)
                conf.mode = NET_CONNECT;
           else  if (strcasecmp(val_begin, "net_proxy") == 0)
                conf.mode = NET_PROXY;
        }
        else if (strcasecmp(var, "uid") == 0)
        {
            conf.uid = atoi(val_begin);
        }
        else if (strcasecmp(var, "client_timeout") == 0)
        {
            conf.client_timeout = atol(val_begin) * 1000;
        }
        else if (strcasecmp(var, "tcp_listen") == 0l)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                port = atoi(p + 1);
                conf.tcp_listen_fd = tcp_listen(val_begin, port);
            }
            else
            {
                port = atoi(val_begin);
                conf.tcp_listen_fd = tcp_listen(NULL, port);
            }
            if (conf.tcp_listen_fd < 0)
                error(NULL);
        }
        else if (strcasecmp(var, "dns_listen") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                port = atoi(p + 1);
                conf.dns_listen_fd = udp_listen(val_begin, port);
            }
            else
            {
                port = atoi(val_begin);
                conf.dns_listen_fd = udp_listen(NULL, port);
            }
            if (conf.dns_listen_fd < 0)
                error(NULL);
        }

        content = strchr(val_end, '\n');
    }

    return 0;
}

/* 读取TCP模块 */
int8_t parse_tcp_module(char *content, struct tcp_conf *tcp,int8_t https)
{
    struct modify *m, *m_save;
    struct ssl_string *s;
    char *var, *val_begin, *val_end, *p, *src_end, *dest_begin;

    m = NULL;
    s = ssl_str;
    while(location_var_val(content, &var, &val_begin, &val_end) == 0)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ((p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                *p = '\0';
                tcp->dst.sin_addr.s_addr = inet_addr(val_begin);
                tcp->dst.sin_port = htons(atoi(p + 1));
            }
            else
            {
                tcp->dst.sin_addr.s_addr = inet_addr(val_begin);
                tcp->dst.sin_port = htons(80);
            }
            goto next_line;
        }

        /* 以下判断为链表操作 */
        m_save = m; //保存前一个结构体指针
        if (m)
            m = m->next = (struct modify *)malloc(sizeof(*m));
        else
           tcp->m = m = (struct modify *)malloc(sizeof(*m));
        if (m == NULL)
            return 1;
        memset((struct modify *)m, 0, sizeof(*m));
        if (strcasecmp(var, "del_hdr") == 0)
        {
            m->flag = DEL_HDR;
            m->str = strdup(val_begin);
            //字母转换为小写
            for (p = m->str; *p != '\0'; p++)
                *p = tolower(*p);
        }
        else if (strcasecmp(var, "set_first") == 0)
        {
            m->str = strdup(val_begin);
            //https模块首先替换部分字符串
            if (https)
                m->str = ssl_req_replace(m->str);
            if (m->str == NULL)
                return 1;
            m->flag = SET_FIRST;
        }
        else if (strcasecmp(var, "strrep") == 0 || strcasecmp(var, "regrep") == 0)
        {
            //定位 [源字符串结束地址] 和 [目标字符串首地址]
            p = strstr(val_begin, "->");
            if (p == NULL)
                return 1;
            for (src_end = p - 1; *src_end != '"'; src_end--)
            {
                if (src_end == val_begin)
                    return 1;
            }
            for (dest_begin = p + 2; *dest_begin != '"'; dest_begin++)
            {
                if (dest_begin == val_end)
                    return 1;
            }
            //复制原字符串
            m->str = strndup(val_begin, src_end - val_begin);
            //https模块首先替换部分字符串
            if (https)
                m->str = ssl_req_replace(m->str);
            if (m->str == NULL)
                return 1;
            //复制目标字符串
            if (val_end - dest_begin - 1 <= 0) //如果目标字符串为空
            {
                if ((m->dest = (char *)calloc(1, sizeof(char))) == NULL)
                    return 1;
            }
            else
            {
                m->dest = strdup(dest_begin + 1);
                if (m->dest == NULL)
                    return 1;
                if (*var == 's') //如果是普通字符串替换
                    m->flag = STRREP;
                else //正则表达式字符串替换
                {
                    m->flag = REGREP;
                    regcomp(&m->reg_src, m->str, REG_NEWLINE|REG_ICASE|REG_EXTENDED);
                    free(m->str);
                }
            }
        }
        else if (https == 0)
        {
            if (strcasecmp(var, "only_get_post") == 0 && strcasecmp(val_begin, "on") == 0)
            {
                conf.http_only_get_post = 1;
            }
            else if (strcasecmp(var, "download_max_size") == 0)
            {
                if (*(val_end-2) == 'M' || *(val_end-2) == 'm')
                    conf.http_download_max_size = strtoull(val_begin, NULL, 10) << 20;
                else
                    conf.http_download_max_size = strtoull(val_begin, NULL, 10);
            }
            else if (strcasecmp(var, "http_port") == 0)
            {
                http_port = strdup(val_begin);
            }
            else if (strcasecmp(var, "proxy_https_string") == 0)
            {
                if (s == NULL)
                    ssl_str = s = (struct ssl_string *)malloc(sizeof(*s));
                else
                    s = s->next = (struct ssl_string *)malloc(sizeof(*s));
                if (s == NULL)
                    return 1;
                s->str = strdup(val_begin);
                if (s->str == NULL)
                    return 1;
                s->next = NULL;
            }
        }
        if (m->flag == 0)
        {
            free(m);
            if (m_save)
            {
                m = m_save;
                m->next = NULL;
            }
            else
                tcp->m = m = NULL;
        }

        next_line:
        content = strchr(val_end, '\n');
    }

    return 0;
}

/* 读取HTTPDNS模块 */
int8_t parse_httpdns_module(char *content)
{
    char *var, *val_begin, *val_end, *p, *ip;
    uint16_t port;

    ip = NULL;
    port = 0;
    while (location_var_val(content, &var, &val_begin, &val_end) == 0)
    {
        if (strcasecmp(var, "addr") == 0)
        {
            if ( (p = strchr(val_begin, ':')) != NULL && p - val_begin <= 15)
            {
                ip = val_begin;
                *p = '\0';
                conf.dns.dst.sin_addr.s_addr = inet_addr(val_begin);
                port = atoi(p + 1);
            }
            else
            {
                ip = val_begin;
                port = 80;
            }
            conf.dns.dst.sin_addr.s_addr = inet_addr(ip);
            conf.dns.dst.sin_port = htons(port);
        }
        else if(strcasecmp(var, "http_req") == 0)
        {
            conf.dns.http_req = strdup(val_begin);
            if (conf.dns.http_req == NULL)
                return 1;
        }
        else if (strcasecmp(var, "cachePath") == 0)
        {
            conf.dns.cachePath = strdup(val_begin);
            if (conf.dns.cachePath != NULL)
            {
                if (read_cache_file() != 0)
                    return 1;
                pthread_mutex_init(&dns_cache_mutex, NULL);
            }
        }
        else if (strcasecmp(var, "cacheLimit") == 0)
        {
            conf.dns.cacheLimit = atoi(val_begin);
        }

        content = strchr(val_end, '\n');
    }
    
    if (ip == NULL || port == 0)
        error("dns module no 'addr'.");
    //构建请求头格式
    char dest[22];
    sprintf(dest, "%s:%d", ip, port);
    if (conf.dns.http_req == NULL)
    {
        struct tcp_req http;

        http.data = str_replace(strdup(HTTPDNS_REQUEST), "[H]", dest);
        if (http.data == NULL)
            return 1;
        http.data_len = strlen(http.data);
        http.type = HTTP;
        http.host = (char *)1; //如果为NULL，modify_request函数可能会使其指向动态分配内存
        if (modify_request(&http) != 0)
            return 1;
        conf.dns.http_req = http.data;
        if (conf.mode == WAP || (conf.mode == NET_PROXY && port != 80 && port != 8080))
            memcpy(&conf.dns.dst, &conf.http.dst, sizeof(conf.dns.dst));
    }
    else
    {
        conf.dns.http_req = str_replace(conf.dns.http_req, "[M]", "GET");
        conf.dns.http_req = str_replace(conf.dns.http_req, "[url]", "/d?dn=[D]");
        conf.dns.http_req = str_replace(conf.dns.http_req, "[U]", "/d?dn=[D]");
        conf.dns.http_req = str_replace(conf.dns.http_req, "[V]", "HTTP/1.0");;
        conf.dns.http_req = str_replace(conf.dns.http_req, "[H]", dest);
    }
    if (conf.mode == WAP_CONNECT || (conf.mode == NET_CONNECT && port != 80 && port != 8080))
    {
        //构建CONNECT请求头
        conf.dns.https_req = str_replace(strdup(def_ssl_req), "[H]", dest);
        if (conf.dns.https_req == NULL)
            return 1;
        conf.dns.https_req_len = strlen(conf.dns.https_req);
        memcpy(&conf.dns.dst, &conf.https.dst, sizeof(conf.dns.dst));
    }

    return 0;
}

void read_conf(char *path)
{
    char *buff, *global, *http, *https, *httpdns;
    FILE *file;
    long file_size;

    /* 读取配置文件到缓冲区 */
    file = fopen(path, "r");
    if (file == NULL)
        error("cannot open config file.");
    fseek(file, 0, SEEK_END);
    file_size = ftell(file);
    buff = (char *)alloca(file_size + 1);
    if (buff == NULL)
        error("out of memory.");
    rewind(file);
    fread(buff, file_size, 1, file);
    fclose(file);
    buff[file_size] = '\0';

    /* 读取global模块内容 */
    if (((global = read_module(buff, "global")) == NULL) || parse_global_module(global) != 0)
        error("wrong config file or out of memory.");
    free(global);

    if (conf.tcp_listen_fd)
    {
        /* 读取http模块内容 */
        if (((http = read_module(buff, "http")) == NULL) || parse_tcp_module(http, &conf.http, 0) != 0)
            error("wrong config file or out of memory.");
        free(http);
    
        /* 读取https模块 */
        if (((https = read_module(buff, "https")) == NULL) || parse_tcp_module(https, &conf.https, 1) != 0)
            error("wrong config file or out of memory.");
        free(https);
        //构建模式CONNECT请求
        struct tcp_req ssl;
        ssl.data = strdup(CONNECT_HEADER);
        if (ssl.data == NULL)
            error("out of memory.");
        ssl.data_len = strlen(CONNECT_HEADER);
        ssl.type = HTTP_CONNECT;
        ssl.host = (char *)1; //不保存Host
        if (modify_request(&ssl) != 0)
            error("out of memory.");
        def_ssl_req = ssl.data;
    }

    /* 读取httpdns模块 */
    if (conf.dns_listen_fd >= 0)
    {
        if ((httpdns = read_module(buff, "httpdns")) == NULL || parse_httpdns_module(httpdns) != 0)
            error("wrong config file or out of memory.");
        free(httpdns);
    }
}
