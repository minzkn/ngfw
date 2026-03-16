#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "ngfw/engine.h"
#include "ngfw/config.h"
#include "ngfw/logger.h"
#include "ngfw/cli.h"
#include "ngfw/web.h"
#include "ngfw/monitor.h"

static volatile bool g_running = true;
static ngfw_engine_t *g_engine = NULL;

static void signal_handler(int sig)
{
    (void)sig;
    g_running = false;
    
    if (g_engine) {
        ngfw_engine_stop(g_engine);
    }
}

static void print_version(void)
{
    printf("NGFW - Next-Generation Firewall\n");
    printf("Version: 1.0.0\n");
    printf("Build: %s %s\n", __DATE__, __TIME__);
}

static void print_usage(const char *prog)
{
    printf("Usage: %s [OPTIONS]\n\n", prog);
    printf("Options:\n");
    printf("  -c, --config FILE    Configuration file (default: /etc/ngfw/ngfw.conf)\n");
    printf("  -d, --daemon         Run as daemon\n");
    printf("  -f, --foreground     Run in foreground (default)\n");
    printf("  -p, --pid FILE      PID file (default: /var/run/ngfw.pid)\n");
    printf("  -l, --log FILE      Log file (default: /var/log/ngfw.log)\n");
    printf("  -L, --loglevel LVL  Log level (debug, info, warn, error)\n");
    printf("  -w, --workers NUM   Number of worker threads (default: 4)\n");
    printf("  -i, --interface IF  Network interface to bind\n");
    printf("  -v, --version       Show version\n");
    printf("  -h, --help          Show this help\n");
    printf("\n");
}

static int parse_arguments(int argc, char *argv[], ngfw_engine_config_t *config)
{
    static struct option long_options[] = {
        {"config",    required_argument, 0, 'c'},
        {"daemon",    no_argument,       0, 'd'},
        {"foreground",no_argument,       0, 'f'},
        {"pid",       required_argument, 0, 'p'},
        {"log",       required_argument, 0, 'l'},
        {"loglevel",  required_argument, 0, 'L'},
        {"workers",   required_argument, 0, 'w'},
        {"interface", required_argument, 0, 'i'},
        {"version",   no_argument,       0, 'v'},
        {"help",      no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };
    
    memset(config, 0, sizeof(ngfw_engine_config_t));
    strcpy(config->config_file, "/etc/ngfw/ngfw.conf");
    strcpy(config->pid_file, "/var/run/ngfw.pid");
    strcpy(config->log_file, "/var/log/ngfw.log");
    config->daemon_mode = false;
    config->debug = false;
    config->worker_threads = 4;
    config->packet_queue_size = 4096;
    config->enable_netfilter = true;
    config->enable_hwaccel = true;
    config->enable_dpdk = false;
    
    int opt;
    int option_index = 0;
    
    while ((opt = getopt_long(argc, argv, "c:dfp:l:L:w:i:vh", long_options, &option_index)) != -1) {
        switch (opt) {
            case 'c':
                strncpy(config->config_file, optarg, sizeof(config->config_file) - 1);
                break;
            case 'd':
                config->daemon_mode = true;
                break;
            case 'f':
                config->daemon_mode = false;
                break;
            case 'p':
                strncpy(config->pid_file, optarg, sizeof(config->pid_file) - 1);
                break;
            case 'l':
                strncpy(config->log_file, optarg, sizeof(config->log_file) - 1);
                break;
            case 'L':
                if (strcmp(optarg, "debug") == 0) {
                    config->debug = true;
                }
                break;
            case 'w':
                config->worker_threads = atoi(optarg);
                if (config->worker_threads == 0) config->worker_threads = 4;
                break;
            case 'i':
                break;
            case 'v':
                print_version();
                exit(0);
            case 'h':
                print_usage(argv[0]);
                exit(0);
            default:
                print_usage(argv[0]);
                return -1;
        }
    }
    
    return 0;
}

static int write_pid_file(const char *pid_file)
{
    FILE *fp = fopen(pid_file, "w");
    if (!fp) {
        fprintf(stderr, "Failed to create PID file: %s\n", strerror(errno));
        return -1;
    }
    
    fprintf(fp, "%d\n", getpid());
    fclose(fp);
    
    return 0;
}

static int daemonize(void)
{
    pid_t pid = fork();
    
    if (pid < 0) {
        fprintf(stderr, "fork() failed: %s\n", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    if (setsid() < 0) {
        fprintf(stderr, "setsid() failed: %s\n", strerror(errno));
        return -1;
    }
    
    signal(SIGHUP, SIG_IGN);
    
    pid = fork();
    if (pid < 0) {
        fprintf(stderr, "fork() failed: %s\n", strerror(errno));
        return -1;
    }
    
    if (pid > 0) {
        exit(0);
    }
    
    umask(0);
    
    if (chdir("/") < 0) {
        fprintf(stderr, "chdir() failed: %s\n", strerror(errno));
        return -1;
    }
    
    close(STDIN_FILENO);
    close(STDOUT_FILENO);
    close(STDERR_FILENO);
    
    int fd = open("/dev/null", O_RDWR);
    if (fd >= 0) {
        dup2(fd, STDIN_FILENO);
        dup2(fd, STDOUT_FILENO);
        dup2(fd, STDERR_FILENO);
        if (fd > 2) close(fd);
    }
    
    return 0;
}

static int load_config(ngfw_engine_t *engine, const char *config_file)
{
    (void)engine;
    
    config_t *config = config_create();
    if (!config) {
        fprintf(stderr, "Failed to create config\n");
        return -1;
    }
    
    if (config_load(config, config_file) != 0) {
        fprintf(stderr, "Failed to load config from %s\n", config_file);
        config_destroy(config);
        return -1;
    }
    
    printf("Configuration loaded from %s\n", config_file);
    
    config_destroy(config);
    return 0;
}

int main(int argc, char *argv[])
{
    ngfw_engine_config_t engine_config;
    
    if (parse_arguments(argc, argv, &engine_config) < 0) {
        return 1;
    }
    
    if (engine_config.daemon_mode) {
        if (daemonize() < 0) {
            return 1;
        }
    }
    
    if (engine_config.pid_file[0]) {
        write_pid_file(engine_config.pid_file);
    }
    
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);
    
    printf("NGFW - Starting Next-Generation Firewall\n");
    
    g_engine = ngfw_engine_create();
    if (!g_engine) {
        fprintf(stderr, "Failed to create NGFW engine\n");
        return 1;
    }
    
    if (ngfw_engine_init(g_engine, &engine_config) != NGFW_OK) {
        fprintf(stderr, "Failed to initialize NGFW engine\n");
        ngfw_engine_destroy(g_engine);
        return 1;
    }
    
    if (engine_config.config_file[0]) {
        load_config(g_engine, engine_config.config_file);
    }
    
    if (ngfw_engine_start(g_engine) != NGFW_OK) {
        fprintf(stderr, "Failed to start NGFW engine\n");
        ngfw_engine_destroy(g_engine);
        return 1;
    }
    
    printf("NGFW engine started successfully\n");
    printf("  Workers: %u\n", engine_config.worker_threads);
    printf("  PID file: %s\n", engine_config.pid_file);
    printf("  Log file: %s\n", engine_config.log_file);
    
    while (g_running) {
        sleep(1);
    }
    
    printf("NGFW - Shutting down...\n");
    
    ngfw_engine_stop(g_engine);
    ngfw_engine_destroy(g_engine);
    
    if (engine_config.pid_file[0]) {
        unlink(engine_config.pid_file);
    }
    
    printf("NGFW - Stopped\n");
    
    return 0;
}
