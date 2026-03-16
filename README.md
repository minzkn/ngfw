# NGFW (Next-Generation Firewall)

차세대 방화벽(NGFW) 프로젝트는 Linux Kernel 6.x를 위한 고성능 C 기반 방화벽 솔루션입니다. 최소 외부 의존성을 목표로 하며, 다양한 CPU 아키텍처를 지원합니다.

## 주요 기능

### 핵심 보안 기능
- **상태적 패킷 검사 (SPI)**: TCP/UDP 연결 상태 추적
- **패킷 필터링**: ACL 기반 필터링 (Accept, Drop, Reject, Log)
- **침입 방지 시스템 (IPS)**: 시그니처 기반 위협 탐지 및 차단
- **세션 관리**: 동시 연결 관리 및 타임아웃 처리

### 네트워크 기능
- **패킷 처리**: Ethernet, IPv4, IPv6 프로토콜 지원
- **프로토콜 지원**: TCP, UDP, ICMP
- **네트워크 인터페이스**: 인터페이스 정보 조회 및 관리

### 암호화
- **대칭 암호화**: AES-128/192/256 (CBC 모드)
- **해시 함수**: SHA-256, MD5
- **무작위 생성**: /dev/urandom 기반

### 플랫폼 지원
- **아키텍처**: x86_64, ARM64, RISC-V
- **커널**: Linux 6.x (6.0 ~ 6.14+)

## 프로젝트 구조

```
ngfw/
├── Makefile              # 빌드 시스템
├── CMakeLists.txt       # CMake 빌드 (준비중)
├── include/ngfw/        # 공개 헤더
│   ├── types.h          # 기본 타입 정의
│   ├── memory.h         # 메모리 관리
│   ├── list.h           # 연결 리스트
│   ├── hash.h           # 해시 테이블
│   ├── log.h            # 로깅
│   ├── packet.h         # 패킷 구조
│   ├── session.h        # 세션 관리
│   ├── filter.h         # 필터링
│   ├── ips.h            # 침입 방지
│   ├── crypto.h         # 암호화
│   └── platform.h       # 플랫폼 추상화
├── src/
│   ├── core/            # 코어 유틸리티
│   │   ├── memory.c
│   │   ├── list.c
│   │   ├── hash.c
│   │   ├── log.c
│   │   ├── timer.c
│   │   ├── spinlock.c
│   │   └── bitmap.c
│   ├── network/         # 네트워크 모듈
│   │   ├── packet.c
│   │   ├── interface.c
│   │   ├── ip.c
│   │   ├── tcp.c
│   │   ├── udp.c
│   │   └── icmp.c
│   ├── crypto/          # 암호화 모듈
│   │   ├── aes.c
│   │   ├── sha.c
│   │   ├── md5.c
│   │   ├── random.c
│   │   └── crc.c
│   ├── security/        # 보안 모듈
│   │   ├── session.c
│   │   ├── filter.c
│   │   ├── ips.c
│   │   └── urlfilter.c
│   └── platform/        # 플랫폼 모듈
│       ├── cpu.c
│       ├── thread.c
│       ├── time.c
│       └── sysinfo.c
├── tests/               # 테스트
├── scripts/             # 유틸리티 스크립트
└── etc/                 # 설정 파일
```

## 빌드

### 기본 빌드 (x86_64)
```bash
make
```

### 디버그 빌드
```bash
make DEBUG=1
```

### 특정 아키텍처
```bash
make ARCH=arm64          # ARM64
make ARCH=riscv64        # RISC-V
```

### 전체 기능 활성화
```bash
make ENABLE_IPS=1 ENABLE_VPN=1 ENABLE_ANTIVIRUS=1
```

### 빌드 후 정렬
```bash
make clean               # 오브젝트 파일 삭제
make distclean           # 모든 빌드 파일 삭제
```

## 사용 예시

### 패킷 필터링
```c
#include <ngfw/filter.h>
#include <ngfw/packet.h>

filter_t *filter = filter_create();

filter_rule_t rule = {
    .action = FILTER_ACTION_DROP,
    .dir = FILTER_DIR_IN,
    .proto = FILTER_PROTO_TCP,
    .dst_port_start = 80,
    .dst_port_end = 80,
    .enabled = true,
    .priority = 100
};

filter_add_rule(filter, &rule);

// 패킷 처리
packet_t *pkt = packet_create(1500);
// ... 패킷 데이터 설정 ...
filter_action_t action = filter_process_packet(filter, pkt, NULL);

filter_destroy(filter);
```

### 세션 관리
```c
#include <ngfw/session.h>

session_table_t *table = session_table_create(100000);

session_key_t key = {
    .src_ip = 0x0100000A,  // 10.0.0.1
    .dst_ip = 0x0200000A,  // 10.0.0.2
    .src_port = 12345,
    .dst_port = 80,
    .protocol = IP_PROTO_TCP
};

session_t *session = session_create(&key);
session_table_insert(table, session);

// 세션 조회
session = session_table_lookup(table, &key);

// 정리
session_table_destroy(table);
```

### IPS 시그니처
```c
#include <ngfw/ips.h>

ips_t *ips = ips_create();

ips_signature_t sig = {
    .id = 1001,
    .action = IPS_ACTION_DROP,
    .severity = 3,
    .protocol = IP_PROTO_TCP,
    .pattern = {0x45, 0x00, 0x00},
    .pattern_len = 3,
    .enabled = true
};

ips_add_signature(ips, &sig);

// 패킷 검사
ips_action_t action = ips_process_packet(ips, pkt);

ips_destroy(ips);
```

### 암호화
```c
#include <ngfw/crypto.h>

aes_context_t ctx;
u8 key[16] = {0};
u8 iv[16] = {0};
u8 plaintext[16] = "Hello World!";
u8 ciphertext[16];

aes_setkey(&ctx, key, AES_KEY_128);
aes_cbc_encrypt(&ctx, iv, plaintext, ciphertext, 16);
```

## 설정 옵션

| 옵션 | 기본값 | 설명 |
|------|--------|------|
| `ARCH` | x86_64 | 대상 아키텍처 |
| `ENABLE_CORE` | 1 | 코어 모듈 활성화 |
| `ENABLE_NETWORK` | 1 | 네트워크 모듈 활성화 |
| `ENABLE_IPS` | 1 | IPS 모듈 활성화 |
| `ENABLE_VPN` | 0 | VPN 모듈 활성화 |
| `ENABLE_URLFILTER` | 1 | URL 필터 활성화 |
| `ENABLE_ANTIVIRUS` | 0 | 안티바이러스 활성화 |
| `ENABLE_QOS` | 1 | QoS 모듈 활성화 |

## 성능 목표

| 모드 | 최소 | 권장 |
|------|------|------|
| 기본 필터링 | 20 Gbps | 40 Gbps |
| IPS 활성화 | 15 Gbps | 30 Gbps |
| SSL 검사 | 10 Gbps | 20 Gbps |

## 개발 가이드라인

### 코드 스타일
- 들여쓰기: 4 spaces
- 줄 길이: 최대 100자
- 중괄호: K&R 스타일
- 명명: snake_case

### 오류 처리
- 성공: 0 반환
- 실패: 음수 오류 코드 반환

### 메모리
- 항상 NULL 검사
- 할당 실패 시 NULL 반환
- 할당 해제 역순으로 수행

## 라이선스

MIT License

## 기여

버그 리포트 및 피드백은 GitHub Issues를 통해 제출해주세요.
