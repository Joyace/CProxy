#include <dirent.h>
#include "main.h"
#include "tcp.h"
#include "common.h"
#include "httpdns.h"
#include "conf.h"

#define SERVICE_TYPE_STOP 1
#define SERVICE_TYPE_STATUS 2

/* 初始化变量 */
void initialize()
{
    addr_len = sizeof(addr);
    http_port = NULL;
    ssl_str = NULL;
    //忽略PIPE信号，设置程序退出时把DNS缓存写入文件
    signal(SIGPIPE, SIG_IGN);
    signal(SIGTERM, write_dns_cache);
    //设置线程属性
    pthread_attr_init(&attr);
    pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);
    //conf结构体默认值
    memset((struct config *)&conf, 0, sizeof(conf));
    conf.http.dst.sin_family = conf.https.dst.sin_family = conf.dns.dst.sin_family = AF_INET;
    conf.uid = getuid();
    conf.dns_listen_fd = conf.tcp_listen_fd = -1;
}

char *get_proc_name(char *path)
{
    char proc_name[257];
    FILE *fp;
    int readsize;
    
    fp = fopen(path, "r");
    if (fp == NULL)
        return NULL;
    readsize = fread(proc_name, 1, 256, fp);
    /*
    if (readsize <= 0)
    {
        fclose(fp);
        return NULL;
    }
    fclose(fp);
    proc_name[readsize] = '\0';
    char *p = strchr(proc_name, '/');
    if (p++)
        return strndup(p, readsize - (p - proc_name) - 1);
    else
        return strndup(proc_name, readsize - 1);
    */
    fclose (fp);
    return strndup(proc_name, readsize - 1);
}

uint8_t additional_service(char *self_name, uint8_t service_type)
{
    char commpath[50];
    DIR *DP;
    struct dirent *dp;
    char *proc_name;
    pid_t self_pid;

    chdir("/proc");
    DP = opendir(".");
    if (DP == NULL)
        return 1;
    proc_name = strrchr(self_name, '/');
    if (proc_name)
        self_name = proc_name + 1;
    self_pid = getpid();
    while ((dp = readdir(DP)) != NULL)
    {
        if (dp->d_type != DT_DIR)
            continue;
        if (strcmp(dp->d_name, ".") == 0 || strcmp(dp->d_name, "..") == 0 || atoi(dp->d_name) == self_pid)
            continue;
        snprintf(commpath, 50, "%s/comm", dp->d_name);
        proc_name = get_proc_name(commpath);
        if (proc_name == NULL)
            continue;
        if (strcmp(proc_name, self_name) == 0)
        {
            if (service_type == SERVICE_TYPE_STOP)
                kill(atoi(dp->d_name), SIGTERM);
            else
            {
                printf("✔  %s(" VERSION ") 正在运行\n", self_name);
                free(proc_name);
                closedir(DP);
                return 0;
            }
        }
        free(proc_name);
    }
    closedir(DP);

    if (service_type == SERVICE_TYPE_STATUS)
        printf("✘  %s(" VERSION ") 没有运行\n", self_name);
    return 0;
}

int main(int argc, char *argv[])
{
    /* 命令行选项 */
    if (argc < 2 || strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0)
    {
        printf("CProxy(" VERSION ")\n"
        "启动命令:\n    CProxy CProxy.conf\n"
        "结束命令:\n    CProxy stop\n"
        "检测命令:\n    CProxy status\n\n");
        return argc < 2 ? 1 : 0;
    }
    if (strcasecmp(argv[1], "stop") == 0)
        return additional_service(argv[0], SERVICE_TYPE_STOP);
    else if (strcasecmp(argv[1], "status") == 0)
        return additional_service(argv[0], SERVICE_TYPE_STATUS);
    /* 初始化 */
    initialize();
    read_conf(argv[1]);
    /* 开始服务 */
    if (setgid(conf.uid) == -1 || setuid(conf.uid) == -1)
        perror("set uid");
    if (daemon(1, 0) == -1)
    {
        perror("daemon");
        error(NULL);
    }
    if (conf.dns_listen_fd >= 0 && conf.tcp_listen_fd >= 0)
    {
        pthread_create(&th_id, &attr, (void *)dns_loop, NULL);
        tcp_loop();
    }
    else if (conf.tcp_listen_fd >= 0)
        tcp_loop();
    else if (conf.dns_listen_fd >= 0)
        dns_loop();

    return 0;
}



