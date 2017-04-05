#include "main.h"
#include "common.h"
#include "tcp.h"
#include "httpdns.h"
#include "conf.h"

pthread_t th_id;
struct sockaddr_in addr;
pthread_attr_t attr;
socklen_t addr_len;

void error(char *error_info)
{
    if (error_info)
    {
        fputs(error_info, stderr);
        fputs("\n\n", stderr);
    }
    exit(1);
}

/* 字符串替换，str为可以用free释放的指针 */
char *str_replace(char *str, const char *src, const char *dest)
{
    if (!str || !src || !dest)
        return str;

    char *p;

    p = strstr(str, src);
    if (p == NULL)
        return str;

    int i, diff, src_len, dest_len;
    src_len = strlen(src);
    dest_len = strlen(dest);

    if (src_len == dest_len)
    {
        for (; p; p = strstr(p, src))
        {
            for (i = 0; i < dest_len; i++)
                p[i] = dest[i];
            p += i;
        }
    }
    else if (src_len < dest_len)
    {
        int str_len, before_len;
        char *before_end;

        diff = dest_len - src_len;
        for (str_len = strlen(str); p; p = strstr(p, src))
        {
            str_len += diff;
            before_len = p - str;
            str = (char *)realloc(str, str_len + 1);
            if (str == NULL)
                return NULL;
            p = str + str_len;
            before_end = str + before_len;
            while (p - dest_len + 1 != before_end)
            {
                *p = *(p - diff);
                p--;
            }
            memcpy(before_end, dest, dest_len);
        }
    }
    else if (src_len > dest_len)
    {
        diff = src_len - dest_len;
        for (; p; p = strstr(p, src))
        {
            for (i = 0; i < dest_len; i++)
                p[i] = dest[i];
            p += i;
            strcpy(p, p + diff);
        }
    }

    return str;
}
