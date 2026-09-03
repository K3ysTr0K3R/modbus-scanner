#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <pthread.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <modbus/modbus.h>

#define MODBUS_PORT 502
#define TIMEOUT_SEC 2
#define MAX_IP_RANGE 65536

typedef struct {
    char start[16];
    char end[16];
    int id;
    pthread_mutex_t* lock;
    FILE* log;
    int* done;
    int* hits;
} job_t;

void usage(char* p);
void* worker(void* arg);
void save_hit(const char* ip, int port, FILE* log, pthread_mutex_t* lock);
int check_modbus(const char* ip, int port);
void calc_range(const char* ip, const char* net, char* start, char* end);
void show_progress(int done, int total, int hits);
int is_bad_ip(uint32_t ip);

volatile int running = 1;
pthread_mutex_t print_mutex = PTHREAD_MUTEX_INITIALIZER;

void sigint_handler(int sig) {
    running = 0;
    printf("\n\n[!] Ctrl+C caught, wrapping up...\n");
}

int main(int argc, char* argv[]) {
    char ip[32] = {0};
    char net[16] = {0};
    int threads = 0;
    char outfile[256] = {0};
    int c;
    
    signal(SIGINT, sigint_handler);
    
    while ((c = getopt(argc, argv, "i:s:t:o:h")) != -1) {
        switch (c) {
            case 'i': strncpy(ip, optarg, sizeof(ip)-1); break;
            case 's': strncpy(net, optarg, sizeof(net)-1); break;
            case 't': threads = atoi(optarg); if (threads < 1) threads = 1; break;
            case 'o': strncpy(outfile, optarg, sizeof(outfile)-1); break;
            case 'h':
            default: usage(argv[0]); return 0;
        }
    }
    
    if (ip[0] == 0 || net[0] == 0 || threads == 0 || outfile[0] == 0) {
        usage(argv[0]);
        return 1;
    }
    
    printf("[*] I need a whiskey :0\n");
    
    char start_ip[16], end_ip[16];
    calc_range(ip, net, start_ip, end_ip);
    
    struct in_addr sa, ea;
    if (inet_pton(AF_INET, start_ip, &sa) != 1 || inet_pton(AF_INET, end_ip, &ea) != 1) {
        fprintf(stderr, "[!] Bad IP address format\n");
        return 1;
    }
    
    uint32_t s = ntohl(sa.s_addr);
    uint32_t e = ntohl(ea.s_addr);
    int total = e - s + 1;
    
    if (total > MAX_IP_RANGE) {
        fprintf(stderr, "[!] Range too big (%d hosts), try smaller subnet\n", total);
        return 1;
    }
    
    FILE* log = fopen(outfile, "w");
    if (!log) {
        fprintf(stderr, "[!] Can't write to %s: %s\n", outfile, strerror(errno));
        return 1;
    }
    
    pthread_t* workers = malloc(threads * sizeof(pthread_t));
    job_t* jobs = malloc(threads * sizeof(job_t));
    pthread_mutex_t lock = PTHREAD_MUTEX_INITIALIZER;
    
    int scanned = 0;
    int found = 0;
    int per_thread = total / threads;
    int leftover = total % threads;
    
    for (int i = 0; i < threads; i++) {
        uint32_t start = s + (i * per_thread);
        uint32_t end = start + per_thread - 1;
        if (i == threads - 1) end += leftover;
        
        struct in_addr a, b;
        a.s_addr = htonl(start);
        b.s_addr = htonl(end);
        
        inet_ntop(AF_INET, &a, jobs[i].start, sizeof(jobs[i].start));
        inet_ntop(AF_INET, &b, jobs[i].end, sizeof(jobs[i].end));
        jobs[i].id = i;
        jobs[i].lock = &lock;
        jobs[i].log = log;
        jobs[i].done = &scanned;
        jobs[i].hits = &found;
        
        pthread_create(&workers[i], NULL, worker, &jobs[i]);
    }
    
    int last_pct = -1;
    while (scanned < total && running) {
        int pct = (scanned * 100) / total;
        if (pct != last_pct) {
            show_progress(scanned, total, found);
            last_pct = pct;
        }
        usleep(200000);
    }
    
    if (!running) {
        printf("\n[!] Scan interrupted by user\n");
    }
    
    for (int i = 0; i < threads; i++) {
        pthread_cancel(workers[i]);
        pthread_join(workers[i], NULL);
    }
    
    printf("\n\n[+] Scanned: %d | Found: %d Modbus\n", scanned, found);
    printf("[+] Results saved to: %s\n", outfile);
    
    fclose(log);
    free(workers);
    free(jobs);
    return 0;
}

void usage(char* p) {
    printf("Usage: %s -i IP -s SUBNET -t THREADS -o FILE\n", p);
    printf("  -i IP        Network to scan\n");
    printf("  -s SUBNET    CIDR mask (e.g. /24)\n");
    printf("  -t THREADS   Parallel threads\n");
    printf("  -o FILE      Output file\n");
    printf("  -h           This help\n");
    printf("\nExample:\n");
    printf("  %s -i 192.168.1.0 -s /24 -t 10 -o results.txt\n", p);
}

void* worker(void* arg) {
    job_t* job = (job_t*)arg;
    struct in_addr cur, end;
    
    inet_pton(AF_INET, job->start, &cur);
    inet_pton(AF_INET, job->end, &end);
    
    uint32_t c = ntohl(cur.s_addr);
    uint32_t e = ntohl(end.s_addr);
    char ipbuf[16];
    
    while (c <= e && running) {
        if (!is_bad_ip(c)) {
            struct in_addr addr;
            addr.s_addr = htonl(c);
            inet_ntop(AF_INET, &addr, ipbuf, sizeof(ipbuf));
            
            if (check_modbus(ipbuf, MODBUS_PORT)) {
                pthread_mutex_lock(job->lock);
                save_hit(ipbuf, MODBUS_PORT, job->log, job->lock);
                (*job->hits)++;
                pthread_mutex_unlock(job->lock);
            }
        }
        
        c++;
        
        pthread_mutex_lock(job->lock);
        (*job->done)++;
        pthread_mutex_unlock(job->lock);
    }
    
    return NULL;
}

/*
 * Try to read input registers first (function code 0x04).
 * If that fails, try reading coils (function code 0x01).
 * A successful read indicates a Modbus device.
 */
int check_modbus(const char* ip, int port) {
    modbus_t* ctx = modbus_new_tcp(ip, port);
    if (!ctx) return 0;
    
    modbus_set_response_timeout(ctx, TIMEOUT_SEC, 0);
    modbus_set_byte_timeout(ctx, 1, 0);
    
    if (modbus_connect(ctx) == -1) {
        modbus_free(ctx);
        return 0;
    }
    
    uint16_t reg;
    int r = modbus_read_input_registers(ctx, 0, 1, &reg);
    
    if (r == -1) {
        uint8_t bits[1];
        r = modbus_read_bits(ctx, 0, 1, bits);
    }
    
    modbus_close(ctx);
    modbus_free(ctx);
    
    return (r != -1);
}

void save_hit(const char* ip, int port, FILE* log, pthread_mutex_t* lock) {
    pthread_mutex_lock(&print_mutex);
    printf("\033[2K\r");                // clear progress bar line
    printf("[+] Modbus detected: %s:%d\n", ip, port);
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
    
    fprintf(log, "[+] Modbus detected: %s:%d\n", ip, port);
    fflush(log);
}

void calc_range(const char* ip, const char* net, char* start, char* end) {
    struct in_addr addr;
    inet_pton(AF_INET, ip, &addr);
    uint32_t ipn = ntohl(addr.s_addr);
    
    int cidr = atoi(net + 1);
    if (cidr < 8 || cidr > 30) cidr = 24;
    
    uint32_t mask = 0xFFFFFFFF << (32 - cidr);
    uint32_t network = ipn & mask;
    uint32_t broadcast = network | ~mask;
    
    struct in_addr a, b;
    a.s_addr = htonl(network + 1);
    b.s_addr = htonl(broadcast - 1);
    
    inet_ntop(AF_INET, &a, start, 16);
    inet_ntop(AF_INET, &b, end, 16);
}

void show_progress(int done, int total, int hits) {
    int pct = (done * 100) / total;
    int bar = (pct * 40) / 100;
    char buf[128];
    
    int pos = sprintf(buf, "\r[");
    for (int i = 0; i < 40; i++) {
        if (i < bar) pos += sprintf(buf + pos, "=");
        else if (i == bar) pos += sprintf(buf + pos, ">");
        else pos += sprintf(buf + pos, " ");
    }
    sprintf(buf + pos, "] %3d%% | %d/%d | Found: %d", pct, done, total, hits);
    
    pthread_mutex_lock(&print_mutex);
    printf("%s", buf);
    fflush(stdout);
    pthread_mutex_unlock(&print_mutex);
}

int is_bad_ip(uint32_t ip) {
    uint8_t last = ip & 0xFF;
    return (last == 0 || last == 255);
}
