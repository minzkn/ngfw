# NGFW 계층적 아키텍처 설계 문서

## 개요

NGFW 는 5 계층 아키텍처로 구성되어 있으며, 각 계층은 명확한 책임과 인터페이스를 가집니다.

```
┌─────────────────────────────────────────────────────────┐
│              Application Layer (app/)                   │
│  - ngfw_engine: 메인 패킷 처리 엔진                     │
│  - cli: 명령줄 인터페이스                               │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                Services Layer (services/)               │
│  - config: 설정 관리                                    │
│  - logger: 로깅 시스템                                  │
│  - monitor: 모니터링 및 메트릭스                        │
│  - web: 웹 인터페이스                                   │
│  - snmp: SNMP                                           │
│  - prometheus: Prometheus 메트릭스                      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│               Security Layer (security/)                │
│  - session: 세션 트래킹 (상태적 연결 관리)              │
│  - filter: 패킷 필터링 (ACL 기반)                       │
│  - ips: 침입 방지 시스템 (Aho-Corasick 매칭)            │
│  - nat: 네트워크 주소 변환                              │
│  - ddos: DDoS 방어                                      │
│  - vpn: VPN 터널 (IPsec)                                │
│  - urlfilter: URL 필터링                                │
│  - antivirus: 안티바이러스                              │
│  - qos: QoS 및 트래픽 쉐이핑                            │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│               Network Layer (network/)                  │
│  - packet: 패킷 버퍼 관리                               │
│  - proto: 프로토콜 헤더 (Ethernet, IP, TCP, UDP)        │
│  - iface: 네트워크 인터페이스 관리                      │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│                 Core Layer (core/)                      │
│  - memory: 메모리 관리 (Slab, Pool, Ring Buffer)        │
│  - ds: 데이터구조 (List, Hash, Tree, Bitmap)            │
│  - match: 패턴 매칭 (BMH, Aho-Corasick)                 │
│  - sync: 동기화 (Spinlock, RW Lock, Barrier)            │
│  - utils: 유틸리티 (Timer, String, Rate Limit)          │
└─────────────────────────────────────────────────────────┘
                          ↓
┌─────────────────────────────────────────────────────────┐
│             HAL - Hardware Abstraction Layer            │
│  - cpu: CPU 정보, Affinity, NUMA                        │
│  - memory: 메모리 할당, NUMA-aware                      │
│  - netif: 네트워크 인터페이스 (Kernel, DPDK)            │
│  - accel: 하드웨어 가속 (Crypto, Checksum)              │
│  - dpdk: DPDK 통합 (선택적)                             │
└─────────────────────────────────────────────────────────┘
```

## 계층별 책임

### 1. HAL (Hardware Abstraction Layer)

**책임**: 하드웨어 리소스에 대한 균일한 인터페이스 제공

**주요 함수**:
- `hal_cpu_init()`, `hal_cpu_get_id()`, `hal_cpu_set_affinity()`
- `hal_mem_alloc()`, `hal_mem_free()`, `hal_mem_alloc_numa()`
- `hal_netif_open()`, `hal_netif_receive()`, `hal_netif_transmit()`
- `hal_accel_aes_encrypt()`, `hal_accel_sha256()`
- `hal_dpdk_init()`, `hal_dpdk_port_start()`

**의존성**: 없음 (최하위 계층)

---

### 2. Core Layer

**책임**: 기본 데이터구조, 메모리 관리, 유틸리티 제공

**주요 함수**:
- `slab_cache_create()`, `slab_alloc()`, `slab_free()`
- `mem_pool_create()`, `mem_pool_alloc()`, `mem_pool_free()`
- `list_create()`, `list_append()`, `list_remove()`
- `hash_create()`, `hash_insert()`, `hash_lookup()`
- `bmh_compile()`, `bmh_find()`, `ac_matcher_create()`
- `spinlock_init()`, `spinlock_lock()`, `spinlock_unlock()`
- `timerwheel_create()`, `timerwheel_add()`, `timerwheel_tick()`

**의존성**: HAL

---

### 3. Network Layer

**책임**: 네트워크 프로토콜 파싱 및 패킷 처리

**주요 함수**:
- `packet_create()`, `packet_destroy()`, `packet_reset()`
- `packet_get_eth()`, `packet_get_ip()`, `packet_get_tcp()`
- `ip_checksum()`, `tcp_calculate_checksum()`
- `netif_enumerate()`, `netif_get_info_by_name()`

**의존성**: Core, HAL

---

### 4. Security Layer

**책임**: 보안 기능 구현 (필터링, IPS, NAT 등)

**주요 함수**:
- `session_table_create()`, `session_table_lookup()`, `session_get()`, `session_put()`
- `filter_create()`, `filter_add_rule()`, `filter_process_packet()`
- `ips_create()`, `ips_add_signature()`, `ips_check_packet()`
- `nat_create()`, `nat_add_rule()`, `nat_translate_packet()`
- `ddos_create()`, `ddos_check_packet()`, `ddos_block_ip()`
- `vpn_create()`, `vpn_create_tunnel()`, `vpn_encrypt_packet()`
- `urlfilter_create()`, `urlfilter_check_url()`
- `antivirus_create()`, `antivirus_scan_packet()`
- `qos_create()`, `qos_add_class()`, `qos_enqueue()`, `qos_dequeue()`

**의존성**: Network, Core

---

### 5. Services Layer

**책임**: 시스템 서비스 (설정, 로깅, 모니터링)

**주요 함수**:
- `config_load()`, `config_save()`, `config_get()`
- `logger_init()`, `logger_log()`, `logger_rotate()`
- `monitor_start()`, `monitor_get_stats()`
- `web_server_create()`, `web_register_route()`, `web_start()`
- `snmp_create()`, `snmp_send_trap()`
- `prometheus_create()`, `prometheus_register_metric()`

**의존성**: Security, Core

---

### 6. Application Layer

**책임**: 메인 애플리케이션 로직

**주요 함수**:
- `ngfw_engine_create()`, `ngfw_engine_init()`, `ngfw_engine_start()`
- `ngfw_engine_process_packet()`, `ngfw_engine_get_stats()`
- `cli_create()`, `cli_register_command()`, `cli_start()`

**의존성**: Services, Security

---

## 데이터 흐름

### 패킷 처리 파이프라인

```
1. HAL (netif_receive)
   ↓
2. Network (packet_parse)
   ↓
3. Security (session_lookup)
   ↓
4. Security (filter_check)
   ↓
5. Security (ips_check)
   ↓
6. Security (nat_translate)
   ↓
7. Security (qos_classify)
   ↓
8. Network (packet_transmit)
   ↓
9. HAL (netif_transmit)
```

### 설정 로드 흐름

```
1. Application (engine_init)
   ↓
2. Services (config_load)
   ↓
3. Security (module_config)
   ↓
4. Network (interface_config)
   ↓
5. HAL (cpu_affinity, memory_init)
```

---

## 인터페이스 정의

### HAL 인터페이스

```c
// cpu.h
ngfw_ret_t hal_cpu_init(void);
u32 hal_cpu_get_id(void);
ngfw_ret_t hal_cpu_set_affinity(u32 cpu_id);

// memory.h
void *hal_mem_alloc(size_t size);
void hal_mem_free(void *ptr);
void *hal_mem_alloc_numa(size_t size, u32 numa_node);

// netif.h
ngfw_ret_t hal_netif_open(const hal_netif_config_t *config, hal_netif_t **netif);
ngfw_ret_t hal_netif_receive(hal_netif_t *netif, void **pkts, u32 *count);
ngfw_ret_t hal_netif_transmit(hal_netif_t *netif, void **pkts, u32 count);
```

### Core 인터페이스

```c
// memory.h
slab_cache_t *slab_cache_create(const char *name, size_t size);
void *slab_alloc(slab_cache_t *cache);
void slab_free(slab_cache_t *cache, void *obj);

// ds.h
hash_table_t *hash_create(u32 size, hash_func_t hash, hash_equal_t equal);
ngfw_ret_t hash_insert(hash_table_t *table, void *key, void *value);
void *hash_lookup(hash_table_t *table, const void *key);

// match.h
ac_matcher_t *ac_matcher_create(u32 max_patterns);
ngfw_ret_t ac_matcher_add_pattern(ac_matcher_t *m, const u8 *p, u32 len, u32 id);
ngfw_ret_t ac_matcher_find(ac_matcher_t *m, const u8 *data, u32 len, u32 *matches);
```

### Security 인터페이스

```c
// session.h
session_table_t *session_table_create(u32 max_sessions);
session_t *session_table_lookup(session_table_t *table, const session_key_t *key);
ngfw_ret_t session_table_insert(session_table_t *table, session_t *session);

// filter.h
filter_t *filter_create(void);
ngfw_ret_t filter_add_rule(filter_t *filter, filter_rule_t *rule);
filter_action_t filter_process_packet(filter_t *filter, packet_t *pkt);

// ips.h
ips_t *ips_create(void);
ngfw_ret_t ips_add_signature(ips_t *ips, ips_signature_t *sig);
ngfw_ret_t ips_check_packet(ips_t *ips, packet_t *pkt, ips_alert_t *alert);
```

### Application 인터페이스

```c
// engine.h
ngfw_engine_t *ngfw_engine_create(void);
ngfw_ret_t ngfw_engine_init(ngfw_engine_t *engine, const ngfw_engine_config_t *config);
ngfw_ret_t ngfw_engine_start(ngfw_engine_t *engine);
ngfw_ret_t ngfw_engine_process_packet(ngfw_engine_t *engine, packet_t *pkt);
```

---

## 메모리 관리 계층

```
Application
    ↓ (ngfw_malloc/ngfw_free)
Core (slab_alloc, mem_pool)
    ↓ (hal_mem_alloc/hal_mem_free)
HAL (malloc/free, NUMA-aware)
    ↓
OS Kernel
```

---

## 동시성 모델

### Per-CPU 데이터

```c
// 각 CPU 는 자신의 데이터에 접근 (락 불필요)
DEFINE_PER_CPU(session_table_t *, session_table);
DEFINE_PER_CPU(u64, packet_count);
```

### 세그먼트 락 (해시 테이블)

```c
// 16 개 세그먼트로 락 경합 감소
struct hash_table {
    hash_segment_t segments[16];
};

hash_rdlock(table);  // 세그먼트 해시로 락 획득
hash_wrlock(table);
hash_unlock(table);
```

### 참조 카운팅

```c
// 세션은 참조 카운팅으로 안전한 메모리 관리
session_get(session);  // refcnt++
session_put(session);  // refcnt--, 0 이면 해제
```

---

## 확장 포인트

### 새 보안 모듈 추가

1. `include/ngfw/security/newmodule.h` 생성
2. `src/security/newmodule.c` 구현
3. `Makefile` 에 소스 추가
4. `include/ngfw/security/security.h` 에 include 추가

### 새 HAL 백엔드 추가

1. `include/ngfw/hal/newif.h` 생성
2. `src/hal/hal_newif.c` 구현
3. `hal_netif_t` 에 새 타입 추가

### 새 서비스 추가

1. `include/ngfw/services/newsvc.h` 생성
2. `src/services/newsvc.c` 구현
3. 엔진 초기화 시 호출 추가

---

## 성능 고려사항

1. **Per-CPU 파티셔닝**: 락 경합 최소화
2. **Slab 할당자**: 빈번한 할당/해제 최적화
3. **Aho-Corasick**: O(n) 다중 패턴 매칭
4. **세그먼트 락**: 해시 테이블 동시성
5. **NUMA 인식**: 메모리 locality 최적화

---

## 버전 정보

- 문서 버전: 1.0
- 작성일: 2026-05-25
- 대상 NGFW 버전: 2.0
