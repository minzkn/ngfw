#include "ngfw/platform.h"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>

void cpu_detect(cpu_capability_t *cap)
{
    if (!cap) return;
    
    memset(cap, 0, sizeof(cpu_capability_t));
    
#if defined(__x86_64__) || defined(_M_X64)
    strcpy(cap->arch, "x86_64");
#elif defined(__aarch64__)
    strcpy(cap->arch, "arm64");
#elif defined(__riscv)
    strcpy(cap->arch, "riscv64");
#elif defined(__arm__)
    strcpy(cap->arch, "arm");
#else
    strcpy(cap->arch, "unknown");
#endif

#if defined(__AES__)
    cap->has_aesni = true;
#endif

#if defined(__AVX__)
    cap->has_avx = true;
#endif

#if defined(__AVX2__)
    cap->has_avx2 = true;
#endif

#if defined(__AVX512F__)
    cap->has_avx512 = true;
#endif

#if defined(__SSE4_2__)
    cap->has_sse42 = true;
#endif

#if defined(__PCLMUL__)
    cap->has_pclmulqdq = true;
#endif

#if defined(__RDRAND__)
    cap->has_rdrand = true;
#endif

#if defined(__ARM_NEON) || defined(__NEON)
    cap->has_neon = true;
#endif

#if defined(__ARM_FEATURE_CRYPTO)
    cap->has_arm_crypto = true;
#endif

#if defined(__riscv_v)
    cap->has_riscv_vector = true;
#endif

    cap->cache_line_size = 64;
    cap->num_cores = sysconf(_SC_NPROCESSORS_ONLN);
    
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
        char line[512];
        while (fgets(line, sizeof(line), fp)) {
            if (strncmp(line, "model name", 10) == 0) {
                char *colon = strchr(line, ':');
                if (colon) {
                    strncpy(cap->cpu_model, colon + 2, sizeof(cap->cpu_model) - 1);
                    char *nl = strchr(cap->cpu_model, '\n');
                    if (nl) *nl = '\0';
                }
            }
        }
        fclose(fp);
    }
    
    if (cap->cpu_model[0] == '\0') {
        strcpy(cap->cpu_model, "Unknown CPU");
    }
}

void sysinfo_get(system_info_t *info)
{
    if (!info) return;
    
    memset(info, 0, sizeof(system_info_t));
    
    struct utsname uts;
    if (uname(&uts) == 0) {
        strncpy(info->kernel_version, uts.release, sizeof(info->kernel_version) - 1);
        info->kernel_version[sizeof(info->kernel_version) - 1] = '\0';
        sscanf(uts.release, "%d.%d.%d", &info->kernel_major, &info->kernel_minor, &info->kernel_patch);
    }
    
    info->num_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    
    long pages = sysconf(_SC_PHYS_PAGES);
    long page_size = sysconf(_SC_PAGESIZE);
    if (pages > 0 && page_size > 0) {
        info->total_memory = (u64)pages * (u64)page_size / (1024 * 1024);
    }
    
    pages = sysconf(_SC_AVPHYS_PAGES);
    if (pages > 0 && page_size > 0) {
        info->free_memory = (u64)pages * (u64)page_size / (1024 * 1024);
    }
    
    info->num_numa_nodes = 1;
}
