# NGFW (차세대 방화벽) 요구사항 정의서

## 문서 정보

| 항목 | 내용 |
|------|------|
| 문서 버전 | 2.0 |
| 작성일 | 2026-03-13 |
| 프로젝트 명 | NGFW (Next-Generation Firewall) |
| 구현 언어 | C (ISO C99 이상) |
| 대상 커널 | Linux Kernel 6.x (6.0 ~ 6.x) |
| 문서 상태 | 초안 |

---

## 1. 프로젝트 개요

### 1.1 목적

본 문서는 완전한 기능을 갖춘 차세대 방화벽(Next-Generation Firewall, 이하 NGFW) 시스템의 개발 및 구현을 위한 모든 요구사항을 정의한다. NGFW는 기존의 상태적 패킷 검사(Stateful Packet Inspection) 방화벽을 기반으로 애플리케이션 레벨 검사(Application-Level Inspection), 침입 방지 시스템(IPS), SSL/TLS 검사, URL 필터링, 맬웨어 방지, VPN, DDoS 완화 등 고급 보안 기능을 통합한 기업급 네트워크 보안 솔루션이다.

본 NGFW 시스템은 다음과 같은 핵심 목표를 달성해야 한다:

- 네트워크 트래픽의 실시간 모니터링 및 제어
- 알려진 및 알려지지 않은 위협에 대한 방지
- 암호화된 통신의 안전한 검사
- 사용자 및 그룹 기반 보안 정책 적용
- 네트워크 가용성 보장 및 서비스 거부 공격 완화
- 규정 준수 및 감사 요구사항 충족

**구현 원칙:**

- 외부 의존성 최소화: 상용 또는 공개소스 라이브러리 사용을 자제하고, 모든 핵심 기능은 순수 C로 직접 구현
- 이식성: x86, ARM, RISC-V, MIPS 등 다양한 CPU 아키텍처 지원
- 커널 호환: Linux Kernel 6.x 전 버전 지원
- 확장성: 모듈식 설계로 향후 기능 추가 및 유지보수 용이
- MVC 패턴: 아키텍처 설계 시 Model-View-Controller 패턴 적용

### 1.2 범위

본 요구사항 문서는 기업급 NGFW 솔루션에 필요한 모든 핵심 기능을 포함한다. 구체적으로는 패킷 필터링, 상태적 검사, 애플리케이션 컨트롤, 침입 방지, SSL 검사, URL 필터링, 맬웨어 방지, VPN, DDoS 완화, 중앙 집중식 관리, 로깅 및 모니터링, 고가용성, 규정 준수 보고 등의 기능이 포함된다.

또한 본 문서는 하드웨어 및 소프트웨어 아키텍처, 성능 요구사항, 배포 옵션, 관리 인터페이스, 보안 요구사항, 테스트 및 검증 기준을 포함한다.

### 1.3 용어 정의

| 용어 | 정의 |
|------|------|
| NGFW | 차세대 방화벽 - 애플리케이션 레벨 검사를 지원하는 고급 방화벽 |
| DPI | Deep Packet Inspection - 심층 패킷 검사 |
| IPS | Intrusion Prevention System - 침입 방지 시스템 |
| IDS | Intrusion Detection System - 침입 탐지 시스템 |
| SSL/TLS Inspection | 암호화된 트래픽의 복호화 후 검사 |
| NAT | Network Address Translation - 네트워크 주소 변환 |
| HA | High Availability - 고가용성 |
| QoS | Quality of Service - 서비스 품질 |
| VPN | Virtual Private Network - 가상 사설망 |
| DDoS | Distributed Denial of Service - 분산 서비스 거부 공격 |
| RBAC | Role-Based Access Control - 역할 기반 접근 제어 |
| SIEM | Security Information and Event Management - 보안 정보 및 이벤트 관리 |
| MVC | Model-View-Controller - 소프트웨어 아키텍처 패턴 |
| Netfilter | Linux 커널의 패킷 처리 프레임워크 |
| iptables/netfilter | Linux 방화벽 인프라스트럭처 |
| nftables | Linux 커널의 새 방화벽 프레임워크 |
| eBPF | Extended Berkeley Packet Filter |
| DPDK | Data Plane Development Kit |

---

## 2. 핵심 아키텍처 요구사항

### 2.1 아키텍처 설계 원칙

#### 2.1.1 모듈식 설계

NGFW 시스템은 독립적인 모듈로 구성되어야 하며, 각 보안 기능별 모듈은 느슨하게 결합(loosely coupled)되어 있어야 한다. 이러한 설계는 개별 모듈의 업그레이드나 수정이 다른 모듈에 영향을 미치지 않도록 보장한다.

모듈식 아키텍처의 핵심 구성 요소는 다음과 같다:

1. **모델 (Model)**: 데이터 및 비즈니스 로직 담당
   - 패킷 처리 모듈: 네트워크 패킷의 수신, 분석, 전송을 담당
   - 상태 관리 모듈: 세션 테이블 및 연결 상태 추적
   - 정책 적용 모듈: 보안 정책의 해석 및 적용
   - 검증 모듈: DPI, IPS, 안티맬웨어, URL 필터링 등 기능 수행
   - 로깅 모듈: 모든 이벤트 및 트래픽 정보 기록

2. **뷰 (View)**: 사용자 인터페이스 담당
   - 웹 UI 렌더링
   - CLI 출력 형식
   - 로그 및 보고서 포맷팅

3. **컨트롤러 (Controller)**: 요청 처리 및 흐름 제어
   - 관리 모듈: 시스템 설정 및 사용자 인터페이스 제공
   - API 핸들러: REST API 요청 처리
   - 이벤트 디스패처: 모듈 간 통신 조정

#### 2.1.2 레이어드 아키텍처

```
┌─────────────────────────────────────────────────────────────┐
│                    Presentation Layer                        │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │   Web UI    │  │    CLI      │  │      REST API      │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Controller Layer                          │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │   Policy    │  │   Session   │  │    Event Manager   │   │
│  │  Controller │  │  Controller │  │                    │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Business Logic Layer                      │
│  ┌────────┐ ┌────────┐ ┌────────┐ ┌────────┐ ┌──────────┐ │
│  │  IPS   │ │  App   │ │  URL   │ │ Anti-  │ │   VPN    │ │
│  │ Module │ │Control │ │Filter   │ │Malware │ │  Module  │ │
│  └────────┘ └────────┘ └────────┘ └────────┘ └──────────┘ │
├─────────────────────────────────────────────────────────────┤
│                    Data Access Layer                         │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │   Session   │  │    Policy   │  │      Log Store      │   │
│  │   Table     │  │   Store     │  │                     │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Kernel Interface Layer                    │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │ Netfilter/  │  │    eBPF      │  │   Kernel Module     │   │
│  │  nftables   │  │   Hooks      │  │     Interface       │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
├─────────────────────────────────────────────────────────────┤
│                    Platform Abstraction Layer                │
│  ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │
│  │  Arch Abst. │  │  Hardware   │  │   Memory Manager    │   │
│  │             │  │  Driver     │  │                     │   │
│  └─────────────┘  └─────────────┘  └─────────────────────┘   │
└─────────────────────────────────────────────────────────────┘
```

### 2.2 Linux Kernel 호환성 요구사항

#### 2.2.1 Kernel 버전 지원

다음 Linux Kernel 버전과 호환되어야 한다:

| Kernel 버전 | 지원 여부 | 비고 |
|-------------|----------|------|
| 6.0.x | 필수 | 초기 지원 버전 |
| 6.1.x | 필수 | LTS 버전 |
| 6.2.x | 필수 | |
| 6.3.x | 필수 | |
| 6.4.x | 필수 | |
| 6.5.x | 필수 | |
| 6.6.x | 필수 | LTS 버전 |
| 6.7.x | 필수 | |
| 6.8.x | 필수 | |
| 6.9.x | 필수 | |
| 6.10.x | 필수 | |
| 6.11.x | 필수 | |
| 6.12.x | 필수 | |
| 6.13.x | 필수 | |
| 6.14.x | 필수 | |
| 6.x (최신) | 권장 | |

#### 2.2.2 Kernel 인터페이스 호환

각 Kernel 버전별 API 호환성 유지를 위한 처리:

- **netfilter API**: nftables 및 기존 iptables API 모두 지원
- **netdevice API**: 네트워크 디바이스 인터페이스 호환
- **socket API**: 네트워크 소켓 통신
- **procfs/sysfs**: 커널 정보 읽기
- **eBPF**: 커널 6.x에서 eBPF 기능 활용
- **io_uring**: 고성능 I/O 작업 지원

#### 2.2.3 커널 모듈 의존성 최소화

- 가능하면 커널 모듈 대신 사용자 공간에서 동작
- 필요한 커널 모듈은 최소한으로 유지
- 커널 Symbol 버전 관리 (EXPORT_SYMBOL_GPL 호환)

### 2.3 프로그래밍 언어 요구사항

#### 2.3.1 주 언어: C

모든 핵심 기능은 C 언어로 구현:

- **표준**: ISO C99 (C11/C17 가능)
- **컴파일러**: GCC 10+, Clang 12+, MSVC (Windows 호환 시)
- **빌드 시스템**: Makefile, CMake

#### 2.3.2 최소 의존성 원칙

외부 라이브러리 사용 최소화:

| 라이브러리 | 사용 여부 | 대안 |
|-----------|----------|------|
| OpenSSL/LibreSSL | 선택 | 자체 구현 (권장하지 않음) |
| libnetfilter | 필수 | Netfilter 직접 연동 |
| libpcap | 선택 | Raw Socket 사용 |
| libjson | 선택 | 자체 JSON 파서 구현 |
| libcurl | 선택 | 소켓 기반 HTTP 구현 |
| database | 선택 | SQLite 내장 또는 파일 기반 |

#### 2.3.3 자체 구현 필수 요소

다음 요소들은 반드시 순수 C로 직접 구현:

- HTTP/HTTPS 클라이언트 및 서버
- JSON 인코딩/디코딩
- 정규 표현식 엔진
- 암호화 (AES, ChaCha20, SHA, MD5 등)
- 압축 (zlib 대체)
- XML 파서
- 날짜/시간 처리
- 문자열 처리 유틸리티

### 2.4 시스템 아키텍처

#### 2.4.1 데이터 평면과 제어 평면 분리

NGFW는 데이터 평면(Data Plane)과 제어 평면(Control Plane)을 명확하게 분리해야 한다.

- **데이터 평면**: 패킷 처리, 필터링, 검사, 전송 등의 실제 네트워크 트래픽 처리 담당. 고성능 처리를 위해 사용자 공간(User Space)에서 실행되어야 한다.
- **제어 평면**: 정책 관리, 시스템 설정, 로깅 설정, 사용자 인증 등의 관리 기능 담당.

#### 2.4.2 커널 우회 기술 (선택적)

최대 처리량을 달성하기 위해 Linux 커널을 우회하는 기술 지원 (선택 구현):

- Intel DPDK 통합
- Raw Socket을 통한 직접 수신
- PACKET_MMAP 활용
- io_uring 기반 I/O

#### 2.4.3 다중 스레딩 및 멀티코어 지원

수평적 확장을 위해 다중 코어를 활용하는 아키텍처를 지원해야 한다:

- 각 CPU 코어에서 독립적으로 패킷을 처리할 수 있어야 함
- 코어 간 부하 분산이 가능해야 함
- 스레드 친화성(Thread Affinity)을 고려한 설계
- Lock-free 데이터 구조 활용

### 2.5 성능 요구사항

NGFW 시스템은 기업 환경에서 요구되는 고성능 처리를 제공해야 한다:

#### 2.5.1 처리량 (Throughput)

| 모드 | 최소 요구사항 | 권장 요구사항 |
|------|---------------|---------------|
| 기본 필터링 only | 20 Gbps | 40 Gbps |
| IPS 활성화 | 15 Gbps | 30 Gbps |
| SSL 검사 활성화 | 10 Gbps | 20 Gbps |
| 전체 기능 활성화 | 10 Gbps | 15 Gbps |

#### 2.5.2 지연 시간 (Latency)

인라인(Inline) 트래픽 처리 시 평균 지연 시간은 1ms 이하이어야 하며, 최대 지연 시간은 5ms를 초과하지 않아야 한다. SSL 검사 활성화 시 추가 지연은 2ms를 초과하지 않아야 한다.

#### 2.5.3 동시 연결

최소 100만 개의 동시 TCP 연결을 지원해야 하며, 권장 요구사항은 500만 연결이다. 초당 새로운 연결 처리 능력(CPS)은 최소 10만 연결/초 이상이어야 한다.

#### 2.5.4 패킷 처리율

64바이트 패킷에 대해 최소 14.88 Mpps(Million packets per second) 이상을 처리해야 한다. 1518바이트 패킷에 대해서는 최소 1.5 Mpps 이상 처리해야 한다.

### 2.6 하드웨어 오프로딩 요구사항

#### 2.6.1 하드웨어 오프로딩 개요

NGFW 시스템은 다양한 하드웨어 가속 및 오프로딩 기술을 활용하여 최대 처리량과 최소 지연 시간을 달성해야 한다. 하드웨어 오프로딩은 선택적(Optional) 기능으로, 지원되는 하드웨어가 있는 경우 자동으로 활용하고, 없는 경우 소프트웨어 기반 처리로 폴백(Fallback)해야 한다.

**오프로딩 아키텍처:**
```
┌─────────────────────────────────────────────────────────────────────────┐
│                        NGFW Processing Pipeline                          │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [NIC Hardware Offload]  →  [Kernel Bypass]  →  [CPU Processing]       │
│  ┌──────────────────┐    ┌────────────────┐   ┌────────────────────┐   │
│  │  RSS/RSS          │    │   DPDK         │   │   Security Modules │   │
│  │  Checksum Offload │    │   io_uring     │   │   - IPS            │   │
│  │  TSO/GSO          │    │   AF_XDP       │   │   - App Control    │   │
│  │  LRO/GRO          │    │   Raw Socket   │   │   - URL Filter     │   │
│  │  VLAN Offload     │    │                │   │   - Anti-Malware   │   │
│  │  MACsec Offload   │    │                │   │   - VPN            │   │
│  └──────────────────┘    └────────────────┘   └────────────────────┘   │
│                                                                          │
│  [Crypto Hardware]    →   [Pattern Matching]  →   [Queuing]           │
│  ┌──────────────────┐    ┌────────────────┐   ┌────────────────────┐   │
│  │  AES-NI          │    │   RegEx HW     │   │   Hardware Queues  │   │
│  │  Intel QAT       │    │   TCAM         │   │   QoS Scheduling   │   │
│  │  ARM Crypt-ext   │    │   GPU Accel    │   │   Priority Queue   │   │
│  │  RISC-V Vector   │    │                │   │                    │   │
│  │  SmartNIC        │    │                │   │                    │   │
│  └──────────────────┘    └────────────────┘   └────────────────────┘   │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 2.6.2 네트워크 카드 오프로딩

##### 2.6.2.1 RSS (Receive Side Scaling)

다중 코어에서의 병렬 처리를 위한 RSS 지원:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| RSS Hash | 수신 패킷을 여러 큐에 분산 | 필수 |
| Indirection Table | 큐 할당 테이블 | 필수 |
| Hash Key | 해시 키 설정/변경 | 필수 |
| Toeplitz Hash | Intel RSS 해시 | 권장 |
| IPv4/IPv6 RSS | IPv4 및 IPv6 지원 | 필수 |
| UDP RSS | UDP 4-tuple 해시 | 권장 |

```c
// RSS 구성 구조
typedef struct rss_config {
    uint32_t hash_engine;       // Toeplitz, CRC, etc.
    uint32_t hash_flags;        // HASH_FLAG_*
    uint8_t  hash_key[40];     // RSS hash key
    uint16_t indirection_table[128];  // Queue mapping
    uint8_t  queue_count;       // Number of queues
} rss_config_t;
```

##### 2.6.2.2 Checksum Offload

패킷 체크섬 계산 오프로딩:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| RX Checksum | 수신 체크섬 검증 오프로드 | 필수 |
| TX Checksum | 송신 체크섬 계산 오프로드 | 필수 |
| IPv4 Checksum | IPv4 헤더 체크섬 | 필수 |
| TCP/UDP Checksum | 전송 계층 체크섬 | 필수 |
| IPv6 Checksum | IPv6 체크섬 | 권장 |

##### 2.6.2.3 TSO/GSO (TCP/Generic Segmentation Offload)

대용량 데이터 전송을 위한 세그멘테이션 오프로딩:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| TSO | TCP 세그멘테이션 오프로드 | 권장 |
| GSO | 일반 세그멘테이션 오프로드 | 권장 |
| TSO6 | IPv6 TSO | 권장 |
| GSO6 | IPv6 GSO | 권장 |
| TSO Max Size | 최대 세그먼트 크기 설정 | 권장 |

##### 2.6.2.4 LRO/GRO (Large/Generic Receive Offload)

수신 측의 패킷 통합 오프로딩:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| LRO | Large Receive Offload | 권장 |
| GRO | Generic Receive Offload | 권장 |
| GRO IPv4 | IPv4 GRO | 권장 |
| GRO IPv6 | IPv6 GRO | 권장 |
| GRO Frag | 프래그먼트 통합 | 권장 |

##### 2.6.2.5 VLAN Offload

VLAN 태그 처리 오프로딩:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| VLAN Insert | VLAN 태그 삽입 | 권장 |
| VLAN Strip | VLAN 태그 제거 | 권장 |
| VLAN Filter | VLAN 필터링 | 권장 |
| VLAN HW Acceleration | VLAN 하드웨어 가속 | 권장 |

##### 2.6.2.6 MACsec Offload

MACsec (802.1AE) 암호화 오프로딩:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| MACsec TX | 송신 암호화 오프로드 | 선택 |
| MACsec RX | 수신 복호화 오프로드 | 선택 |
| MACsec SC | Secure Channel | 선택 |
| MACsec SA | Secure Association | 선택 |

#### 2.6.3 암호화 오프로딩

##### 2.6.3.1 AES-NI (Advanced Encryption Standard - New Instructions)

Intel/AMD CPU의 AES-NI 명령어 활용:

| 명령어 | 기능 | 용도 |
|--------|------|------|
| AESENC | AES 암호화 | AES-CBC 암호화 |
| AESENCLAST | 마지막 라운드 | AES-CBC |
| AESDEC | AES 복호화 | AES-CBC 복호화 |
| AESDECLAST | 마지막 복호화 | AES-CBC |
| AESKEYGENASSIST | 키 스케줄 생성 | 키 확장 |
| PCLMULQDQ | Carry-less 곱셈 | AES-GCM |
| RDRAND | 하드웨어 Random | Random 생성 |

**구현 요구사항:**
- AES-CBC 128/256-bit 하드웨어 가속
- AES-GCM 128/256-bit 하드웨어 가속
- AES-CTR 모드 지원
- AES-XTS 모드 지원

```c
// AES-NI 가속 인터페이스
typedef struct aes_ni_cipher {
    int (*cbc_encrypt)(const uint8_t *key, size_t key_len,
                       const uint8_t *iv, const uint8_t *input,
                       uint8_t *output, size_t len);
    int (*cbc_decrypt)(const uint8_t *key, size_t key_len,
                       const uint8_t *iv, const uint8_t *input,
                       uint8_t *output, size_t len);
    int (*gcm_encrypt)(const uint8_t *key, size_t key_len,
                       const uint8_t *iv, const uint8_t *aad, size_t aad_len,
                       const uint8_t *input, uint8_t *output, size_t len,
                       uint8_t *tag);
    int (*gcm_decrypt)(const uint8_t *key, size_t key_len,
                       const uint8_t *iv, const uint8_t *aad, size_t aad_len,
                       const uint8_t *input, uint8_t *output, size_t len,
                       const uint8_t *tag);
    bool (*is_available)(void);
} aes_ni_cipher_t;
```

##### 2.6.3.2 Intel QAT (QuickAssist Technology)

Intel QAT 가속 카드 활용:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| Symmetric Crypto | 대칭 암호화 가속 | 선택 |
| Asymmetric Crypto | 비대칭 암호화 가속 | 선택 |
| Compression | 압축 가속 (zlib) | 선택 |
| Prime Generation | 소수 생성 | 선택 |
| SSL/TLS Offload | SSL/TLS 가속 | 선택 |
| IPsec Offload | IPsec 가속 | 선택 |

**QAT 드라이버 지원:**
- QAT Gen1/C2xxx (구세대)
- QAT Gen3 (DH895xcc, C6xx)
- QAT Gen4 (4xxx-M, C7xx, PHE)
- VFIO Passthrough
- VF (Virtual Function) 지원

##### 2.6.3.3 ARM Cryptography Extension (ARMv8.2+)

ARM NEON 및 Crypto Extension 활용:

| 명령어 | 기능 | 용도 |
|--------|------|------|
| AESE | AES Encrypt | AES 암호화 |
| AESD | AES Decrypt | AES 복호화 |
| PMULL | Polynomial Multiply | AES-GCM |
| SHA1 | SHA-1 해시 | SHA-1 |
| SHA256 | SHA-256 해시 | SHA-256 |

**구현 요구사항:**
- ARMv8-A (AArch64) Crypto Extension 지원
- ARMv8.2-A (AArch64) PMULL 지원
- NEON SIMD 활용

##### 2.6.3.4 RISC-V Cryptography Extension

RISC-V 벡터 연산 및 암호화 확장 활용:

| 확장 | 기능 | 용도 |
|------|------|------|
| RV64GCV | 벡터 연산 | 병렬 처리 |
| Zbkb | Bitmanip | 키 처리 |
| Zbkc | Carry-less 곱셈 | AES-GCM |
| Zknd/zKNE | AES 가속 | AES-NI 유사 |
| Zksh | SHA-2 가속 | SHA-256/512 |
| Zkne/zknd | NIST AES | AES-NI 유사 |

##### 2.6.3.5 GPU 가속 (선택)

NVIDIA GPU를 활용한 대용량 암호화/복호화:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| CUDA Support | CUDA 프로그래밍 | 선택 |
| cuBLAS | 대용량 행렬 연산 | 선택 |
| Bulk Encryption | 대량 암호화 | 선택 |
| Malware Scanning | 맬웨어 스캐닝 | 선택 |
| RegEx Processing | 정규식 처리 | 선택 |

#### 2.6.4 SmartNIC 오프로딩

##### 2.6.4.1 Mellanox BlueField/CX

NVIDIA Mellanox SmartNIC 활용:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| ConnectX-6 Dx | 100GbE 네트워크 카드 | 선택 |
| ConnectX-7 | 200GbE 네트워크 카드 | 선택 |
| BlueField-2 | 내장 CPU + 네트워크 카드 | 선택 |
| BlueField-3 | 200GbE 네트워크 카드 | DPU 모델 | 선택 |
| BlueField-3 | DPU 모델 | 선택 |
| OVS Offload | OVS 가속 | 선택 |
| ASAP² | 메타데이터 가속 | 선택 |

##### 2.6.4.2 Pensando DSC

Pensando Distributed Services Card:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| DSC-100 | 100GbE SmartNIC | 선택 |
| Flow Processing | 플로우 처리 가속 | 선택 |
| Policy Engine | 정책 엔진 가속 | 선택 |
| Crypto Offload | 암호화 가속 | 선택 |

##### 2.6.4.3 Intel (구 Nitro/C originale)

Intel Ethernet 서비니스 카드:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| E810-XXVAM2 | 100GbE 네트워크 카드 | 선택 |
| N3000 | 10GbE SmartNIC | 선택 |
| N-Serie | 네트워크 가속 | 선택 |

#### 2.6.5 패턴 매칭 오프로딩

##### 2.6.5.1 TCAM (Ternary Content-Addressable Memory)

하드웨어 패턴 매칭:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| ACL TCAM | ACL 규칙 하드웨어 처리 | 선택 |
| Flow Table | 플로우 테이블 하드웨어 | 선택 |
| Pattern Match | 시그니처 패턴 매칭 | 선택 |
| Wildcard Matching | 와일드카드 매칭 | 선택 |
| Multi-match | 다중 규칙 매칭 | 선택 |

##### 2.6.5.2 RegEx 하드웨어 가속

정규 표현식 패턴 매칭 하드웨어:

| 솔루션 | 설명 | 요구사항 |
|--------|------|----------|
| Intel QuickAssist (RegEx) | RegEx 가속 | 선택 |
| Cavium/XPliant | RegEx 가속 | 선택 |
| Netronome Agilio | RegEx 가속 | 선택 |

##### 2.6.5.3 GPU 기반 패턴 매칭

GPU를 활용한 대용량 패턴 매칭:

```c
// GPU 패턴 매칭 인터페이스
typedef struct gpu_pattern_matcher {
    int (*init)(uint32_t max_patterns, uint32_t max_length);
    int (*add_pattern)(const uint8_t *pattern, size_t len, uint32_t id);
    int (*compile)(void);
    int (*scan_buffer)(const uint8_t *buffer, size_t len, uint32_t *matches, uint32_t *match_count);
    int (*free)(void);
    bool (*is_available)(void);
} gpu_pattern_matcher_t;
```

#### 2.6.6 메모리 오프로딩

##### 2.6.6.1 Huge Pages

대용량 페이지 활용:

| 페이지 크기 | 용도 | 요구사항 |
|------------|------|----------|
| 2MB Pages | 일반 사용 | 필수 |
| 1GB Pages | 대용량 버퍼 | 권장 |
| Transparent Huge Pages | 자동 관리 | 권장 |

##### 2.6.6.2 DMA (Direct Memory Access)

DMA를 활용한 메모리 전송:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| DMA Engine | DMA 엔진 | 선택 |
| IOMMU | IOMMU 활용 | 권장 |
| PRU | Programmable Realtime Unit | 선택 |

##### 2.6.6.3 RDMA (Remote Direct Memory Access)

원격 직접 메모리 접근:

| 프로토콜 | 설명 | 요구사항 |
|----------|------|----------|
| RoCE v2 | RDMA over Converged Ethernet | 선택 |
| iWARP | Internet Wide Area RDMA | 선택 |
| InfiniBand | InfiniBand RDMA | 선택 |

#### 2.6.7 타임스탬프 및 동기화 오프로딩

##### 2.6.7.1 PTP (Precision Time Protocol)

정밀 시간 동기화:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| PTP Hardware Clock | 하드웨어 클록 | 권장 |
| PTP v2 (IEEE 1588) | PTP 프로토콜 | 권장 |
| One-step Clock | 원스텝 클록 | 권장 |
| Two-step Clock | 투스텝 클록 | 권장 |

##### 2.6.7.2 Hardware Timestamping

패킷 타임스탬프:

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| TX Timestamp | 송신 시간 기록 | 권장 |
| RX Timestamp | 수신 시간 기록 | 권장 |
| Software Timestamp | 소프트웨어 타임스탬프 | 필수 |
| Hardware Timestamp | 하드웨어 타임스탬프 | 권장 |

#### 2.6.8 런타임 자동 감지 및 동적 적응

##### 2.6.8.1 런타임 감지 아키텍처

NGFW는 컴파일 시점이 아닌 **런타임 시** 시스템의 하드웨어 및 소프트웨어 환경을 자동으로 감지하고, 사용 가능한 기능에 따라 동적으로 동작 방식을 결정해야 한다. 이 방식은 다양한 하드웨어 구성에서 단일 바이너리로 동작 가능하게 한다.

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     NGFW Runtime Detection Architecture                  │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                    Initialization Phase                           │    │
│   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │    │
│   │   │ CPU Feature │  │   Network   │  │   OS/Kernel         │   │    │
│   │   │   Detector  │  │   Detector  │  │   Detector          │   │    │
│   │   │             │  │             │  │                     │   │    │
│   │   │ - AES-NI   │  │ - RSS       │  │ - Kernel Version   │   │    │
│   │   │ - AVX512   │  │ - TSO/GSO  │  │ - Netfilter        │   │    │
│   │   │ - NEON     │  │ - GRO       │  │ - eBPF             │   │    │
│   │   │ - RISC-V   │  │ - Checksum  │  │ - io_uring        │   │    │
│   │   │ - SIMD     │  │ - VLAN      │  │ - Capabilities     │   │    │
│   │   └──────┬──────┘  └──────┬──────┘  └──────────┬────────┘   │    │
│   └──────────┼────────────────┼───────────────────┼────────────┘    │
│              │                │                    │                  │
│              ▼                ▼                    ▼                  │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                  Capability Registry                             │    │
│   │   ┌─────────────────────────────────────────────────────────┐  │    │
│   │   │  hw_capabilities = {                                    │  │    │
│   │   │      .cpu_aesni = true,                                 │  │    │
│   │   │      .cpu_avx512 = false,                               │  │    │
│   │   │      .net_rss = true,                                   │  │    │
│   │   │      .net_tso = true,                                   │  │    │
│   │   │      .net_gro = true,                                   │  │    │
│   │   │      .net_offload = { .tx_csum = true, .rx_csum = true },│ │    │
│   │   │      .kernel_nftables = true,                           │  │    │
│   │   │      .kernel_ebpf = true,                               │  │    │
│   │   │      .crypto_qat = false,                               │  │    │
│   │   │      .net_smartnic = false,                             │  │    │
│   │   │  }                                                       │  │    │
│   │   └─────────────────────────────────────────────────────────┘  │    │
│   └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                  Runtime Adaptation Engine                       │    │
│   │   ┌─────────────┐  ┌─────────────┐  ┌─────────────────────┐   │    │
│   │   │   Packet    │  │   Crypto    │  │   Network          │   │    │
│   │   │   Processing│  │   Engine    │  │   Offload         │   │    │
│   │   │   Mode      │  │   Mode      │  │   Mode            │   │    │
│   │   │             │  │             │  │                     │   │    │
│   │   │ - RSS or   │  │ - HW Crypto │  │ - SmartNIC or    │   │    │
│   │   │   Single   │  │   or SW     │  │   Standard NIC   │   │    │
│   │   └─────────────┘  └─────────────┘  └─────────────────────┘   │    │
│   └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                  Fallback Pipeline                               │    │
│   │   HW Offload → SW Implementation → Reduced Functionality     │    │
│   │   (Best)       (Acceptable)        (Minimum)                   │    │
│   └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

##### 2.6.8.2 CPU 기능 런타임 감지

```c
// CPU 기능 감지 인터페이스
typedef struct cpu_feature_detector {
    // x86/x86_64
    bool (*detect_aesni)(void);          // AES-NI
    bool (*detect_avx)(void);           // AVX
    bool (*detect_avx2)(void);          // AVX2
    bool (*detect_avx512f)(void);       // AVX-512 Foundation
    bool (*detect_avx512bw)(void);      // AVX-512 Byte/Word
    bool (*detect_avx512vl)(void);      // AVX-512 Vector Length
    bool (*detect_pclmulqdq)(void);     // PCLMULQDQ (AES-GCM)
    bool (*detect_rdrand)(void);        // RDRAND (Random)
    bool (*detect_rdseed)(void);         // RDSEED (Entropy)
    bool (*detect_sse42)(void);         // SSE4.2
    bool (*detect_xsave)(void);         // XSAVE/XRSTOR

    // ARM64
    bool (*detect_neon)(void);          // NEON SIMD
    bool (*detect_crypto)(void);        // ARM Crypto Extension
    bool (*detect_armv8_1)(void);       // ARMv8.1+
    bool (*detect_armv8_2)(void);       // ARMv8.2+ (PMULL)
    bool (*detect_armv8_3)(void);       // ARMv8.3+ (Dot Product)

    // RISC-V
    bool (*detect_riscv_i)(void);       // Base Integer
    bool (*detect_riscv_m)(void);       // Multiply/Divide
    bool (*detect_riscv_a)(void);       // Atomic
    bool (*detect_riscv_f)(void);       // Float
    bool (*detect_riscv_d)(void);       // Double
    bool (*detect_riscv_v)(void);       // Vector (RVV)
    bool (*detect_riscv_zbkc)(void);   // Bitmanip Carry-less
    bool (*detect_riscv_zkne)(void);   // AES (NIST)
    bool (*detect_riscv_zknd)(void);   // AES (NIST)
    bool (*detect_riscv_zksh)(void);   // SHA2

    // 공통
    uint32_t (*get_cache_line_size)(void);
    uint32_t (*get_num_cores)(void);
    uint32_t (*get_num_numa_nodes)(void);
    uint64_t (*get_cpu_freq)(void);
} cpu_feature_detector_t;

// 감지 결과 구조
typedef struct cpu_capability {
    // 암호화
    bool has_aesni;
    bool has_avx512;
    bool has_avx2;
    bool has_neon;
    bool has_arm_crypto;
    bool has_riscv_crypto;
    bool has_riscv_vector;

    // 시메틱
    bool has_sse42;
    bool has_avx;
    bool has_neon_simd;

    // Random
    bool has_rdrand;
    bool has_rdseed;

    // 시스템
    uint32_t cache_line_size;
    uint32_t num_cores;
    uint32_t num_numa_nodes;
    uint64_t cpu_freq_mhz;
    char cpu_model[128];
    char cpu_architecture[32];
} cpu_capability_t;
```

##### 2.6.8.3 네트워크 기능 런타임 감지

```c
// 네트워크 기능 감지
typedef struct network_capability_detector {
    // 인터페이스별 감지
    int (*detect_rss)(const char *ifname, bool *supported);
    int (*detect_rss_queues)(const char *ifname, uint32_t *queue_count);
    int (*detect_tso)(const char *ifname, bool *supported);
    int (*detect_gso)(const char *ifname, bool *supported);
    int (*detect_lro)(const char *ifname, bool *supported);
    int (*detect_gro)(const char *ifname, bool *supported);
    int (*detect_rx_checksum)(const char *ifname, bool *supported);
    int (*detect_tx_checksum)(const char *ifname, bool *supported);
    int (*detect_vlan_offload)(const char *ifname, bool *supported);
    int (*detect_vxlan_offload)(const char *ifname, bool *supported);
    int (*detect_geneve_offload)(const char *ifname, bool *supported);
    int (*detect_hw_strip_csum)(const char *ifname, bool *supported);

    // SmartNIC 감지
    bool (*detect_smartnic)(const char *ifname);
    bool (*detect_eswitch_mode)(const char *ifname);
    int (*detect_switchdev)(const char *ifname, bool *supported);
    int (*detect_sriov)(const char *ifname, uint16_t *num_vfs);

    // 드라이버 감지
    int (*get_driver_name)(const char *ifname, char *driver, size_t len);
    int (*get_driver_version)(const char *ifname, char *version, size_t len);
} network_capability_detector_t;

// 네트워크 기능 결과
typedef struct network_capability {
    char ifname[32];
    char driver[32];
    char driver_version[32];

    // RSS
    bool rss_supported;
    uint32_t rss_queue_count;
    uint8_t rss_hash_functions;  // Toeplitz, CRC, etc.

    // 세그멘테이션
    bool tso_supported;
    bool gso_supported;

    // 통합
    bool lro_supported;
    bool gro_supported;

    // 체크섬
    bool rx_csum_supported;
    bool tx_csum_supported;

    // 터널
    bool vxlan_offload_supported;
    bool geneve_offload_supported;

    // 가상화
    bool smartnic_detected;
    bool switchdev_mode;
    uint16_t sriov_num_vfs;
} network_capability_t;
```

##### 2.6.8.4 커널 기능 런타임 감지

```c
// 커널 기능 감지
typedef struct kernel_capability_detector {
    // 버전 감지
    int (*get_kernel_version)(int *major, int *minor, int *patch);
    bool (*check_version)(int major, int minor);

    // Netfilter 감지
    bool (*has_nftables)(void);
    bool (*has_iptables)(void);
    bool (*has_iptables_legacy)(void);
    bool (*has_conntrack)(void);
    bool (*has_nat)(void);

    // eBPF 감지
    bool (*has_ebpf)(void);
    bool (*has_ebpf_jit)(void);
    bool (*has_xdp)(void);
    bool (*has_xdp_native)(void);

    // io_uring 감지
    bool (*has_io_uring)(void);
    bool (*has_io_uring_setup)(void);

    // 시스템 기능
    bool (*has_huge_pages)(void);
    bool (*has_1gb_huge_pages)(void);
    bool (*hasTransparentHugePages)(void);
    bool (*has_numa)(void);
    bool (*has_seccomp)(void);
    bool (*has_selinux)(void);

    // 장치
    int (*get_cpu_count)(void);
    int (*get_numa_node_count)(void);
    uint64_t (*get_total_memory)(void);
    uint64_t (*get_free_memory)(void);
} kernel_capability_detector_t;

// 커널 기능 결과
typedef struct kernel_capability {
    int kernel_major;
    int kernel_minor;
    int kernel_patch;

    // Netfilter
    bool nftables_supported;
    bool iptables_supported;
    bool conntrack_supported;
    bool nat_supported;

    // eBPF
    bool ebpf_supported;
    bool ebpf_jit_supported;
    bool xdp_supported;
    bool xdp_native_supported;

    // io_uring
    bool io_uring_supported;

    // 메모리
    bool huge_pages_supported;
    bool huge_pages_1gb_supported;
    bool thp_supported;

    // NUMA
    bool numa_supported;
    uint32_t numa_node_count;

    // 보안
    bool seccomp_supported;
    bool selinux_supported;

    // 리소스
    uint32_t cpu_count;
    uint64_t total_memory_mb;
    uint64_t free_memory_mb;
} kernel_capability_t;
```

##### 2.6.8.5 암호화 가속 하드웨어 감지

```c
// 암호화 가속 감지
typedef struct crypto_accel_detector {
    // Intel QAT
    int (*detect_qat)(void);
    int (*detect_qat_device)(int *device_id, int *num_devices);

    // GPU 감지
    int (*detect_gpu)(void);
    int (*detect_nvidia_gpu)(void);
    int (*detect_amd_gpu)(void);
    int (*get_gpu_info)(char *name, size_t len);

    // TPM
    bool (*detect_tpm)(void);
    bool (*detect_tpm2)(void);

    // HSM
    int (*detect_pkcs11)(void);
    int (*detect_softHSM)(void);
} crypto_accel_detector_t;

// 암호화 기능 결과
typedef struct crypto_capability {
    // Intel
    bool qat_available;
    int qat_device_count;
    bool aesni_available;
    bool avx512_available;

    // ARM
    bool arm_crypto_available;
    bool neon_available;

    // RISC-V
    bool riscv_crypto_available;
    bool riscv_vector_available;

    // GPU
    bool gpu_available;
    bool nvidia_gpu_available;
    bool amd_gpu_available;
    char gpu_name[64];

    // 보안 모듈
    bool tpm_available;
    bool tpm2_available;
    bool pkcs11_available;

    // 사용 권장 엔진
    enum crypto_engine_type preferred_engine;  // HW_CRYPTO, QAT, GPU, SOFTWARE
} crypto_capability_t;
```

##### 2.6.8.6 종합 런타임 감지 매니저

```c
// 종합 감지 매니저
typedef struct runtime_detector {
    // 초기화
    int (*init)(void);
    void (*cleanup)(void);

    // 종합 감지 실행
    int (*detect_all)(void);

    // 개별 감지
    cpu_capability_t* (*get_cpu_capability)(void);
    network_capability_t* (*get_network_capability)(const char *ifname);
    kernel_capability_t* (*get_kernel_capability)(void);
    crypto_capability_t* (*get_crypto_capability)(void);

    // 권장 모드 반환
    enum processing_mode (*get_recommended_mode)(void);
    enum crypto_mode (*get_recommended_crypto_mode)(void);

    // 설정 가능
    int (*set_preferred_mode)(enum processing_mode mode);
    int (*force_feature)(const char *feature, bool enabled);
} runtime_detector_t;

// 처리 모드
typedef enum processing_mode {
    MODE_AUTO,              // 자동 감지 (기본)
    MODE_FULL_HW_OFFLOAD,  // 전체 하드웨어 오프로딩
    MODE_HYBRID,           // 혼합 모드
    MODE_SOFTWARE,         // 소프트웨어 only
    MODE_REDUCED           // 최소 기능 모드
} processing_mode_t;

// 암호화 모드
typedef enum crypto_mode {
    CRYPTO_AUTO,            // 자동 감지
    CRYPTO_HW_AESNI,       // AES-NI 강제
    CRYPTO_HW_QAT,         // QAT 강제
    CRYPTO_HW_GPU,         // GPU 강제
    CRYPTO_SOFTWARE,       // 소프트웨어 only
    CRYPTO_HYBRID          // 가능한 경우 HW, 아니면 SW
} crypto_mode_t;
```

##### 2.6.8.7 동적 폴백 메커니즘

```c
// 동적 폴백 체인
typedef struct fallback_chain {
    // 계층 구조 (순서 중요 - 높은 우선순위에서 낮은 순서)
    typedef enum fallback_priority {
        FALLBACK_PRIORITY_HW_NIC,     // 1순위: 하드웨어 NIC 오프로딩
        FALLBACK_PRIORITY_HW_CRYPTO,  // 2순위: 하드웨어 암호화
        FALLBACK_PRIORITY_KERNEL,     // 3순위: 커널 기능 활용
        FALLBACK_PRIORITY_USERSPACE,  // 4순위: 사용자 공간 구현
        FALLBACK_PRIORITY_REDUCED,    // 5순위: 축소 기능
    } fallback_priority_t;

    // 폴백 핸들러 등록
    int (*register_handler)(
        fallback_priority_t priority,
        const char *feature_name,
        void *(*try_init)(void),
        bool (*is_available)(void),
        void (*fallback)(void *ctx)
    );

    // 폴백 실행
    void* (*execute)(const char *feature_name);

    // 상태 확인
    bool (*is_using_fallback)(const char *feature_name);
    const char* (*get_active_impl)(const char *feature_name);
} fallback_chain_t;

// 폴백 시나리오 예시
typedef struct fallback_scenario {
    const char *feature;
    void *(*try_hw_offload)(void);    // 하드웨어 오프로딩 시도
    void *(*try_kernel_bypass)(void);  // 커널 바이패스 시도
    void *(*try_software)(void);       // 소프트웨어 구현 시도
    void *(*try_reduced)(void);        // 축소 기능 시도
} fallback_scenario_t;
```

##### 2.6.8.8 런타임 환경 감지 및 적응 흐름

```
┌─────────────────────────────────────────────────────────────────────────┐
│                    Runtime Adaptation Flow                               │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  [1] System Startup                                                      │
│      │                                                                  │
│      ▼                                                                  │
│  [2] CPU Feature Detection                                              │
│      ├─ Read /proc/cpuinfo (x86)                                       │
│      ├─ Read /proc/self/auxv (ARM)                                     │
│      ├─ Read /proc/cpuinfo (RISC-V)                                    │
│      └─ Cache detected features                                         │
│                                                                          │
│      ▼                                                                  │
│  [3] Network Device Detection                                            │
│      ├─ Enumerate network interfaces (ioctl SIOCGIFCONF)               │
│      ├─ Query ethtool for capabilities                                  │
│      ├─ Check driver (sysfs /sys/class/net/)                           │
│      └─ Test actual offload status                                      │
│                                                                          │
│      ▼                                                                  │
│  [4] Kernel Capability Detection                                        │
│      ├─ Check kernel version (uname)                                    │
│      ├─ Probe netfilter (nft --version)                                 │
│      ├─ Probe eBPF (bpf() syscall)                                      │
│      ├─ Check io_uring availability                                     │
│      └─ Check memory/NUMA                                               │
│                                                                          │
│      ▼                                                                  │
│  [5] Crypto Hardware Detection                                          │
│      ├─ Try open /dev/qat_* (QAT)                                      │
│      ├─ Try nvidia-smi (GPU)                                           │
│      ├─ Probe TPM (/dev/tpm0)                                          │
│      └─ CPU feature check                                               │
│                                                                          │
│      ▼                                                                  │
│  [6] Build Capability Registry                                           │
│      ├─ Combine all detected capabilities                              │
│      ├─ Calculate available feature sets                               │
│      └─ Store in runtime configuration                                 │
│                                                                          │
│      ▼                                                                  │
│  [7] Select Implementation Paths                                         │
│      │                                                                  │
│      ├─[Packet Processing]                                              │
│      │  IF SmartNIC + switchdev: Use HW offload                        │
│      │  ELSE IF RSS available: Use multi-queue                         │
│      │  ELSE: Use single queue                                         │
│      │                                                                  │
│      ├─[Crypto Operations]                                              │
│      │  IF AES-NI available: Use AES-NI                                 │
│      │  ELSE IF QAT available: Use QAT                                 │
│      │  ELSE: Use software AES                                        │
│      │                                                                  │
│      ├─[Network Offload]                                                │
│      │  IF TSO/GSO available: Enable                                  │
│      │  ELSE: Disable                                                  │
│      │                                                                  │
│      └─[Filtering Engine]                                               │
│         IF nftables available: Use nftables                             │
│         ELSE IF iptables: Use iptables                                 │
│         ELSE: Use raw socket + userspace                               │
│                                                                          │
│      ▼                                                                  │
│  [8] Runtime Monitoring & Fallback                                       │
│      │                                                                  │
│      ├─ Monitor HW availability                                         │
│      │  IF HW fails: Trigger fallback                                  │
│      │  IF HW recovers: Optionally restore                             │
│      │                                                                  │
│      └─ Allow dynamic reconfiguration                                   │
│         CLI > set crypto-mode auto                                      │
│         CLI > show hardware-capabilities                               │
│         CLI > reload                                                    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

##### 2.6.8.9 폴백 전략 상세

| 기능 | 1차 선택 | 2차 선택 | 3차 선택 | 4차 선택 |
|------|---------|---------|---------|---------|
| 패킷 수신 | SmartNIC + RSS | 표준 NIC RSS | PACKET_MMAP | Raw Socket |
| 암호화 | AES-NI + AVX512 | AES-NI only | QAT | OpenSSL SW |
| 체크섬 | HW Offload | Kernel Checksum | SW Checksum | Disable |
| TSO/GSO | HW TSO/GSO | Software TSO | Disable | N/A |
| GRO | HW GRO | Kernel GRO | Disable | N/A |
| 필터링 | nftables | iptables | Userspace | Basic |
| 터널 | HW VXLAN | Kernel VXLAN | Software Tunnel | Disable |
| IPsec | HW Offload | Linux Kernel | StrongSwan SW | Disable |
| 패턴 매칭 | TCAM | GPU | Hyperscan | Aho-Corasick |

##### 2.6.8.10 런타임 설정 변경

```c
// 런타임 설정 변경 API
typedef struct runtime_config_manager {
    // 모드 변경
    int (*set_processing_mode)(processing_mode_t mode);
    processing_mode_t (*get_processing_mode)(void);

    // 개별 기능 토글
    int (*enable_feature)(const char *feature_name);
    int (*disable_feature)(const char *feature_name);
    bool (*is_feature_enabled)(const char *feature_name);

    // 폴백 트리거
    int (*trigger_fallback)(const char *feature_name);
    int (*reset_fallback)(const char *feature_name);

    // 모니터링
    typedef struct feature_stats {
        const char *feature_name;
        uint64_t try_count;
        uint64_t success_count;
        uint64_t fallback_count;
        bool is_using_fallback;
        void *current_impl;
    } feature_stats_t;

    feature_stats_t* (*get_stats)(const char *feature_name);
    feature_stats_t* (*get_all_stats)(void);

    // 리로드
    int (*reload_configuration)(void);
    int (*hot_reload)(void);  // 무중단 재구성
} runtime_config_manager_t;
```

##### 2.6.8.11 CLI 및 API를 통한 런타임 제어

```bash
# 런타임 하드웨어 감지 및 설정 CLI 예시

# 하드웨어 기능 표시
> show hardware-capabilities
CPU Features:
  AES-NI: Available
  AVX2: Available
  AVX512: Not Available
  NEON: Not Available (x86_64)

Network Features:
  Interface: eth0
    Driver: mlx5_core
    RSS: Available (8 queues)
    TSO: Available
    GRO: Available
    VXLAN Offload: Available

Kernel Features:
  nftables: Available (v1.0.8)
  eBPF: Available
  io_uring: Available

# 처리 모드 설정
> set processing-mode auto
Processing mode set to AUTO

> set crypto-mode hardware
Crypto mode set to HW_AESNI

# 개별 기능 활성화/비활성화
> enable feature tso
TSO enabled

> disable feature gro
GRO disabled

# 폴백 상태 확인
> show fallback-status
Feature      Current Impl    Fallback Level
-----------  -------------   ---------------
Crypto       AES-NI          Primary
Packet RX    RSS (8Q)        Primary
Checksum     Hardware        Primary
Filter       nftables        Primary

# 강제 폴백
> fallback feature crypto
Crypto forced to software mode

# 설정 재로드
> reload
Configuration reloaded
```

```json
// REST API를 통한 런타임 제어
// GET /api/v1/hardware/capabilities
{
  "cpu": {
    "aesni": true,
    "avx512": false,
    "model": "Intel(R) Xeon(R) CPU E5-2680 v4"
  },
  "network": {
    "eth0": {
      "driver": "mlx5_core",
      "rss_queues": 8,
      "tso": true,
      "gro": true
    }
  },
  "kernel": {
    "version": "6.6.0",
    "nftables": true,
    "ebpf": true
  }
}

// POST /api/v1/runtime/mode
{
  "processing_mode": "auto",
  "crypto_mode": "auto"
}

// GET /api/v1/runtime/fallback-status
{
  "crypto": {
    "current": "aesni",
    "fallback_available": true,
    "fallback_to": "software"
  }
}
```

#### 2.6.11 오프로딩 감지 및 폴백 요약

본 NGFW는 위에서 설명한 런타임 감지 아키텍처(2.6.8.1 ~ 2.6.8.10)를 기반으로 자동 감지 및 폴백을 수행한다. 구체적인 폴백 전략은 다음과 같다:

| 오프로딩 유형 | 1차 | 2차 | 3차 | 4차 |
|--------------|-----|-----|-----|-----|
| 패킷 수신 | SmartNIC + RSS | 표준 NIC RSS | PACKET_MMAP | Raw Socket |
| 암호화 | AES-NI + AVX512 | AES-NI only | QAT | OpenSSL SW |
| 체크섬 | HW Offload | Kernel Checksum | SW Checksum | Disable |
| TSO/GSO | HW TSO/GSO | Software TSO | Disable | N/A |
| GRO | HW GRO | Kernel GRO | Disable | N/A |
| 필터링 | nftables | iptables | Userspace | Basic |
| 터널 | HW VXLAN | Kernel VXLAN | Software Tunnel | Disable |
| IPsec | HW Offload | Linux Kernel | StrongSwan SW | Disable |
| 패턴 매칭 | TCAM | GPU | Hyperscan | Aho-Corasick |

---

#### 2.6.12 오프로딩 성능 벤치마크

##### 2.6.9.1 벤치마크 항목

| 테스트 항목 | 기준 | 측정 방법 |
|------------|------|----------|
| AES-GCM 10G throughput | > 5 Gbps | iperf3 + crypto test |
| AES-CBC throughput | > 3 Gbps | openssl speed |
| RSS scalability | 선형 확장 | 다중 코어 테스트 |
| TSO throughput | > 20 Gbps | pktgen |
| GRO effectiveness | > 90% 통합율 | 패킷 캡처 분석 |
| IPS throughput (with HW) | > 15 Gbps | Snort test |
| Pattern matching | > 10 Gbps | Hyperscan benchmark |

#### 2.6.13 오프로딩 설정 관리

##### 2.6.10.1 설정 인터페이스

```c
// 오프로딩 설정 구조
typedef struct offload_config {
    bool enable_rss;
    uint8_t rss_queue_count;
    bool enable_tso;
    bool enable_gro;
    bool enable_csum_offload;
    bool enable_aesni;
    bool enable_qat;
    bool enable_gpu;
    bool enable_smartnic;
    uint8_t crypto_engine;  // HW_PREFERENCE_AUTO, HW_PREFERENCE_CRYPTO, HW_PREFERENCE_SOFTWARE
} offload_config_t;
```

##### 2.6.10.2 런타임 설정 변경

- 온라인 오프로딩 활성화/비활성화
- RSS 큐 수 동적 조정
- 암호화 엔진 런타임 전환
- 성능 프로파일切换

### 2.7 인터페이스 요구사항

#### 2.6.1 네트워크 인터페이스

다음과 같은 다양한 속도의 이더넷 인터페이스를 지원해야 한다:

- 1Gbps RJ45/SFP 인터페이스
- 10Gbps SFP+ 인터페이스
- 25Gbps SFP28 인터페이스
- 100Gbps QSFP28 인터페이스

인터페이스는 자동 협상(Auto-negotiation)을 지원하되, 수동 설정 옵션도 제공해야 한다.

#### 2.6.2 관리 인터페이스

별도의 带域 管理 포트(out-of-band management)를 제공해야 한다:

- 10/100/1000Mbps 자동 협상
- Dedicated IP 주소 할당 가능
- management VRF 분리 지원
- 원격 관리 프로토콜 (HTTP, HTTPS, SSH)

#### 2.6.3 고가용성 인터페이스

HA 클러스터링을 위한 전용 인터페이스를 지원해야 한다:

- HA 상태 동기화 전용 포트
- 하트비트 전송 전용
- 데이터 동기화 (설정, 세션, 상태 정보)

#### 2.6.4 스토리지 인터페이스

로그 및 보고서 저장을 위한 외부 스토리지 연결을 지원해야 한다:

- NFS 마운트 지원
- SMB/CIFS 마운트 지원
- iSCSI 연결 지원
- 로컬 SSD 스토리지 (최소 512GB)

---

## 3. 다양한 아키텍처 및 하드웨어 호환 요구사항

### 3.1 CPU 아키텍처 지원

#### 3.1.1 지원 대상 아키텍처

다양한 CPU 아키텍처를 지원해야 한다:

| 아키텍처 |.bits| 지원 수준 | 비고 |
|---------|-----|----------|------|
| x86-64 | 64 | 필수 | Intel/AMD |
| x86 | 32 | 권장 | 레거시 |
| ARM64 (AArch64) | 64 | 필수 | ARMv8+ |
| ARM (AArch32) | 32 | 권장 | ARMv7 |
| RISC-V (RV64GC) | 64 | 권장 | RISC-V 64-bit |
| RISC-V (RV32GC) | 32 | 선택 | RISC-V 32-bit |
| MIPS (MIPS64) | 64 | 선택 | Loongson 등 |
| MIPS (MIPS32) | 32 | 선택 | 레거시 |
| PowerPC (PPC64) | 64 | 선택 | IBM POWER |

#### 3.1.2 엔디언 (Endianness)

각 아키텍처의 엔디언 호환:

- Little-endian: x86, ARM64, RISC-V (LE), MIPS (LE)
- Big-endian: 일부 ARM, MIPS (BE), PowerPC
- Bi-endian 지원: RISC-V

#### 3.1.3.word 크기

- 32-bit 아키텍처 지원
- 64-bit 아키텍처 지원

### 3.2 플랫폼 추상화 계층 (PAL)

#### 3.2.1 아키텍처 추상화

```c
// 플랫폼 추상화 예시 구조
typedef struct {
    uint32_t arch_type;
    uint32_t word_size;
    uint32_t endianness;
    uint32_t cache_line_size;
    uint32_t num_cores;
    uint64_t page_size;
    bool     has_atomic_ops;
    bool     has_sse;
    bool     has_avx;
    bool     has_neon;
    bool     has_riscv_xthead;
} platform_info_t;
```

#### 3.2.2 컴파일러 추상화

```c
// 컴파일러 및 플랫폼 감지 매크로
#if defined(__x86_64__) || defined(_M_X64)
    #define ARCH_X86_64
#elif defined(__i386__) || defined(_M_IX86)
    #define ARCH_X86
#elif defined(__aarch64__) || defined(_M_ARM64)
    #define ARCH_ARM64
#elif defined(__arm__) || defined(_M_ARM)
    #define ARCH_ARM
#elif defined(__riscv) && __riscv_xlen == 64
    #define ARCH_RISCV64
#elif defined(__riscv) && __riscv_xlen == 32
    #define ARCH_RISCV32
#endif
```

### 3.3 하드웨어 이식성

#### 3.3.1 네트워크 카드 지원

다양한 네트워크 카드 드라이버 지원 (각 카드의 오프로딩 기능 포함):

**Intel:**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| ice | Ethernet 800 Series | 1G/10G/25G/100G | RSS, TSO, GSO, GRO, Checksum, VXLAN, Geneve |
| i40e | Ethernet X710/XXV710 | 10G/25G | RSS, TSO, GSO, GRO, Checksum, DCB |
| ixgbe | Ethernet X550/X540 | 1G/10G | RSS, TSO, GSO, GRO, Checksum |
| igb | Ethernet I350/I210 | 1G | RSS, TSO, GRO, Checksum |
| ixgbevf | Intel VF | 10G | RSS, TSO, VXLAN VF |
| ice | E810 Series | 10G/25G/100G/200G | RSS, TSO, GSO, GRO, PTP, SyncE, ADQ |

**Broadcom/Emulex:**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| bnx2x | BCM578xx | 10G/40G | RSS, TSO, GRO, MC, Multi-Cos |
| be2net | BCM578xx | 10G/25G/40G/100G | RSS, TSO, GRO, VXLAN, NVGRE |
| bnxt_en | BCM575xx | 10G/25G/50G/100G/200G | RSS, TSO, GRO, GSO, eBPF, RoCE, PTP |
| cnic | CNIC | - | iSCSI, FCoE 오프로딩 |

**Mellanox (NVIDIA):**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| mlx5_core | ConnectX-5 | 10G/25G/50G/100G/200G | RSS, TSO, GRO, GSO, VXLAN, Geneve, RoCE, ASO, ASAP² |
| mlx5_core | ConnectX-6 Dx | 100G/200G | RSS, TSO, GRO, VXLAN, Geneve, Flex Parsing, ASO4 |
| mlx5_core | ConnectX-7 | 200G/400G | RSS, TSO, GRO, OVS Hardware Offload, BlueField integration |
| mlx5_core | BlueField-2 | 100G/200G | 내장 CPU + SmartNIC, OVS, TLS Offload, RegEx |
| mlx5_core | BlueField-3 | 200G/400G | DPU, OVS/OVN Offload, IPsec, TLS, RegEx, Storage Offload |

**AMD/Pensando:**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| amd-xgbe | XGBE | 10G | RSS, TSO, GRO, Checksum |
| ionic | Ionic | 10G/25G/40G/100G | RSS, TSO, GRO, VXLAN, Flow Director |
| (Pensando) | DSC-100 | 100G | Distributed Services, Policy Engine, Crypto |
| (Pensando) | DSC-200 | 100G/200G | Full Data Path Offload |

**Marvell/Cavium:**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| qede | QLogic 25G/100G | 25G/100G | RSS, TSO, GRO, VXLAN |
| thunderx | ThunderX | 10G/25G/40G | RSS, TSO, GRO, ARM64 Native |
| octeontx | Octeon TX/TX2 | 1G-100G | Inline IPSec, Pattern Matching, Flow Processing |

**Realtek:**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| r8169 | RTL8169 | 1G | 기본 오프로딩 (제한적) |
| r8125 | RTL8125 | 2.5G | 기본 오프로딩 |
| r8126 | RTL8126 | 10G | RSS, TSO, Checksum |

**Solarflare (AMD/Xilinx):**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| sfc | SFC9020/9140 | 10G/40G | RSS, TSO, GRO, Onload (Kernel Bypass), PTP |
| sfc | SFC9250 | 25G/100G | RSS, TSO, GRO, Onload, SolarCapture |
| efx | EF100 | 10G/25G/100G | Kernel Bypass, Onload, Flow Processing |

**Fungible:**
| 드라이버 | 칩셋 | 속도 | 주요 오프로딩 기능 |
|----------|------|------|-------------------|
| fungible | F1 | 100G/200G | Multi-die Processing, Inline Crypto, Flow Table |

#### 3.3.2 오프로딩별 상세 요구사항

##### 3.3.2.1 Kernel Bypass 프레임워크

| 프레임워크 | 설명 | 요구사항 |
|------------|------|----------|
| DPDK | Intel Data Plane Development Kit | 권장 |
| io_uring | Linux 5.1+ 비동기 I/O | 권장 |
| AF_XDP | eXpress Data Path | 권장 |
| libpcap | Packet Capture Library | 선택 |
| Raw Socket | 소켓 기반 직접 수신 | 필수 |
| PACKET_MMAP | 메모리 매핑 수신 | 권장 |

##### 3.3.2.2 드라이버별 오프로딩 매트릭스

| 드라이버 | RSS | TSO | GRO | VXLAN | Geneve | IPsec | PTP | RDMA |
|----------|-----|-----|-----|-------|--------|-------|-----|------|
| ice | Yes | Yes | Yes | Yes | Yes | Yes | Yes | - |
| mlx5 | Yes | Yes | Yes | Yes | Yes | Yes | Yes | Yes |
| bnxt_en | Yes | Yes | Yes | Yes | Yes | - | Yes | Yes |
| ionic | Yes | Yes | Yes | Yes | Yes | - | - | - |
| sfc | Yes | Yes | Yes | Yes | - | - | Yes | - |
| r8126 | Yes | Yes | - | - | - | - | - | - |

#### 3.3.3 내장 스위치 (Embedded Switch/eSwitch) 지원

##### 3.3.3.1 eSwitch (Embedded Switch) 개요

대부분의 modern SmartNIC에는 내장 스위치(eSwitch 또는 eSwitch Mode)가 포함되어 있다. eSwitch는 하이퍼바이저/VF 간의 트래픽을 하드웨어에서 직접 처리하여 성능을 제공한다.

| eSwitch 유형 | 설명 | 카드 |
|-------------|------|------|
| Legacy eSwitch | 기본 스위치 기능 | 구세대 SmartNIC |
| switchdev | Linux 스위치dev 프레임워크 | Mellanox, etc |
| sriov | SR-IOV 기반 가상화 | 모든 지원 카드 |
| ASO | Accelerated Switch and Ops | Mellanox BlueField |

##### 3.3.3.2 Switchdev (스위치dev) 지원

Linux kernel의 switchdev 프레임워크를 활용한 하드웨어 스위치 오프로딩:

**지원 드라이버 및 카드:**
| 드라이버 | 카드 | 스위치 모드 |
|----------|------|------------|
| mlx5_core | ConnectX-5/6/7 | switchdev mode |
| mlx5_core | BlueField-2/3 | switchdev mode |
| bnxt_en | Broadcom 575xx | switchdev mode |
| ionic | Pensando Ionic | switchdev mode |
| ice | Intel E810 | switchdev mode |

**스위치dev 기능:**
| 기능 | 설명 | 요구사항 |
|------|------|----------|
| HW FDB | Hardware Forwarding Database | 필수 |
| VLAN Offload | VLAN 태그 처리 | 필수 |
| Mirroring | 포트 미러링 (SPAN/RSPAN) | 권장 |
| ACL Offload | ACL 규칙 하드웨어 처리 | 권장 |
| QoS Offload | QoS 정책 하드웨어 처리 | 권장 |
| NAT Offload | NAT 변환 하드웨어 처리 | 선택 |
| Tunnel Offload | VXLAN/Geneve 오프로딩 | 권장 |

```c
// switchdev 설정 구조
typedef struct switchdev_config {
    char device_name[32];
    uint8_t mode;           // SWITCHDEV_MODE_LEGACY, SWITCHDEV_MODE_SWITCHDEV
    uint8_t representors[32];
    uint32_t num_representors;
    bool enable_vlan_filter;
    bool enable_native_bridge;
    bool enable_roce;
} switchdev_config_t;
```

##### 3.3.3.3 SR-IOV (Single Root I/O Virtualization) 지원

SR-IOV를 통한 가상 기능(VF) 할당:

**SR-IOV 아키텍처:**
```
┌─────────────────────────────────────────────────────────────────┐
│                        Physical Function (PF)                   │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────────┐   │
│  │  eSwitch      │  │  Physical     │  │   Control Plane   │   │
│  │  (HW Switch) │  │  Ports        │  │   (PF Driver)     │   │
│  └───────┬───────┘  └───────┬───────┘  └───────────────────┘   │
│          │                  │                                    │
│  ┌───────┴───────┐  ┌───────┴───────┐  ┌───────────────────┐   │
│  │    VF 0       │  │    VF 1       │  │     VF N          │   │
│  │  (Virtual     │  │  (Virtual     │  │   (Virtual        │   │
│  │   Function)   │  │   Function)   │  │    Function)      │   │
│  └───────────────┘  └───────────────┘  └───────────────────┘   │
└─────────────────────────────────────────────────────────────────┘
```

**VF 설정 요구사항:**
| 항목 | 설명 | 요구사항 |
|------|------|----------|
| Max VFs | 최대 VF 수 | 카드별 상이 |
| VF MAC | VF MAC 주소 할당 | 필수 |
| VF VLAN | VF VLAN 설정 | 권장 |
| VF Rate Limiting | VF 带域 제한 | 권장 |
| VF Trust | VF 트러스트 설정 | 권장 |
| VF RSS | VF RSS 설정 | 권장 |

```c
// SR-IOV 설정 구조
typedef struct sriov_config {
    uint16_t num_vfs;           // 생성할 VF 수
    uint16_t max_vfs;           // 카드에서 지원되는 최대 VF
    bool    enable_mac_vlan;    // MAC/VLAN 필터 활성화
    bool    enable_promisc;     // 프로미스커스 모드
    bool    enable_allmulti;    // 올멀티캐스트 모드
    uint32_t tx_rate;           // TX 带域限制 (Mbps)
    uint32_t rx_rate;           // RX 带域限制 (Mbps)
    bool    trust_mode;         // 트러스트 모드
    char    pf_name[32];        // PF 디바이스 이름
} sriov_config_t;
```

##### 3.3.3.4 Representor Ports

PF에 연결된 VF를 나타내는 representor 포트:

| 유형 | 설명 | 용도 |
|------|------|------|
| PF Representor | PF 자체 포트 | VM/컨테이너 간 통신 |
| VF Representor | VF별 포트 | 개별 VM/컨테이너 연결 |
| Host PF Representor | 호스트 PF | 호스트 네트워크 연결 |
| Embedded Port | 내장 포트 |物理 포트 연결 |

##### 3.3.3.5 내장 스위치 오프로딩 매트릭스

| 카드 | eSwitch | switchdev | SR-IOV | VLAN Offload | Tunnel Offload | ACL Offload |
|------|---------|-----------|--------|--------------|-----------------|--------------|
| Mellanox CX-5 | Yes | Yes | Yes | Yes | Yes | Yes |
| Mellanox CX-6 Dx | Yes | Yes | Yes | Yes | Yes | Yes |
| Mellanox CX-7 | Yes | Yes | Yes | Yes | Yes | Yes |
| BlueField-2 | Yes | Yes | Yes | Yes | Yes | Yes |
| BlueField-3 | Yes | Yes | Yes | Yes | Yes | Yes |
| Intel E810 | Yes | Yes | Yes | Yes | Yes | Yes |
| Broadcom 575xx | Yes | Yes | Yes | Yes | Yes | - |
| Pensando Ionic | Yes | Yes | Yes | Yes | Yes | - |

#### 3.3.4 Open vSwitch (OVS) 지원

##### 3.3.4.1 OVS 아키텍처 지원

Open vSwitch는 가상 스위치 솔루션으로, 하드웨어 오프로딩을 통해 성능을 향상시킬 수 있다.

**OVS 구성 요소:**
| 구성 요소 | 설명 | 오프로딩 |
|----------|------|----------|
| vswitchd | vswitch 데몬 | - |
| ovsdb-server | 데이터베이스 서버 | - |
| datapath | 데이터 경로 | HW Offload |
| ofproto | OpenFlow 프로토콜 | HW Offload |
| conntrack | 연결 추적 | HW Offload |

##### 3.3.4.2 OVS Hardware Offload (HW Offload)

| 오프로딩 유형 | 설명 | 카드 |
|--------------|------|------|
| ASAP² | Accelerated Switching and Packet Processing | Mellanox |
| tc-fulldp | TC Flower + eSwitch | Mellanox |
| rte_flow | DPDK Flow API | Intel, Broadcom |
| switchdev | switchdev + tc | Broadcom, Intel |
| sfc | Solarflare Onload | Solarflare |

**ASAP² (Mellanox):**
| 기능 | 설명 |
|------|------|
| KTLS Offload | Kernel TLS 가속 |
| IPsec Offload | IPsec 가속 |
| RegEx Offload | 정규식 가속 |
| Decap/Encap | 터널 캡슐화/역캡슐화 |
| Multi-buffer | 멀티 버퍼 처리 |

```c
// OVS HW Offload 설정
typedef struct ovs_offload_config {
    char datapath_name[64];
    uint8_t offload_type;    // ASAP2, TC, RTE_FLOW
    bool enable_ipsec;
    bool enable_ktls;
    bool enable_regex;
    bool enable_tunnel;
    uint32_t max_flows;      // 하드웨어 플로우 테이블 크기
} ovs_offload_config_t;
```

##### 3.3.4.3 OVS with DPDK

DPDK 기반 OVS 구성:

**구성 옵션:**
| 모드 | 성능 | CPU 사용 | 하드웨어 오프로딩 |
|------|------|----------|-----------------|
|-userspace | 높음 | 높음 | Limited |
| -hw-offload | 매우 높음 | 낮음 | Full |
| -tc-offload | 높음 | 낮음 | Partial |

**DPDK vswitchd 옵션:**
```bash
# HW Offload 활성화
vswitchd --dpdk -c 0x1 -n 4 --socket-mem 1024,0 -- \
    --hw-offload \
    --max-flows 1000000 \
    --enable-vhost-user-multiqueue
```

##### 3.3.4.4 OVS 플로우 오프로딩

**오프로딩 가능한 플로우:**
| 플로우 항목 | 오프로딩 |
|------------|----------|
| L2 (MAC, VLAN) | Yes |
| L3 (IP, IPv6) | Yes |
| L4 (TCP, UDP, SCTP) | Yes |
| Tunnel (VXLAN, GRE, Geneve) | Yes |
| NAT | Yes (일부) |
| Conntrack | Yes |
| ACL | Yes |
| QoS (Rate Limit) | Yes |
| mirroring | Yes |

##### 3.3.4.5 OVS 지원 매트릭스

| OVS 버전 | DPDK 지원 | HW Offload | switchdev | tc flower |
|---------|-----------|------------|-----------|-----------|
| 2.10 | Yes | Yes | - | - |
| 2.11 | Yes | Yes | Yes | - |
| 2.12 | Yes | Yes | Yes | Yes |
| 2.13 | Yes | Yes | Yes | Yes |
| 2.14+ | Yes | Yes | Yes | Yes |
| 3.0+ | Yes | Yes | Yes | Yes |

##### 3.3.4.6 OVS 디버깅 및 모니터링

**모니터링 명령어:**
```bash
# HW offload 상태 확인
ovs-vsctl get Open_vSwitch . other_config:hw-offload

# 플로우 테이블 확인
ovs-dpctl dump-flows -m

# HW 플로우 확인
ovs-appctl ofproto/trace

# 성능メ트릭
ovs-vsctl get Interface <if> statistics
```

#### 3.3.5 기타 가상 스위치 지원

##### 3.3.5.1 OVN (Open Virtual Network)

OVN은 OVS 기반의 가상 네트워크 솔루션:

| 기능 | 지원 |
|------|------|
| Logical Switch | Yes |
| Logical Router | Yes |
| ACL | Yes |
| Load Balancer | Yes |
| NAT | Yes |
| DHCP | Yes |
| DNS | Yes |
| HW Offload | Yes (Mellanox) |

##### 3.3.5.2 SR-IOV + VFIO Passthrough

VFIO를 통한 VF 할당:

| 방식 | 설명 | 성능 |
|------|------|------|
| VFIO No-IOMMU | IOMMU 비활성화 | 가장 높음 |
| VFIO IOMMU | IOMMU 활성화 | 중간 |
| vhost-user | virtio 후킹 | 중간 |

##### 3.3.5.3 컨테이너 네트워킹 지원

| 플러그인 | 오프로딩 지원 |
|---------|--------------|
| CNI (Container Network Interface) | - |
| macvlan/ipvlan | Yes |
| flannel (VXLAN) | Yes |
| calico (VXLAN/BGP) | Yes |
| weave (VXLAN) | Yes |
| cilium (eBPF) | Yes (Limited) |

#### 3.3.6 가상 스위치 통합 아키텍처

```
┌─────────────────────────────────────────────────────────────────────────┐
│                         NGFW Virtual Switch Architecture                 │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                    Control Plane (vswitchd)                     │    │
│   │   ┌────────────┐  ┌────────────┐  ┌────────────────────────┐   │    │
│   │   │  OVS DB    │  │ OpenFlow   │  │   OVSDB (Southbound)   │   │    │
│   │   │  Server    │  │  Controller│  │                        │   │    │
│   │   └────────────┘  └────────────┘  └────────────────────────┘   │    │
│   └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                      │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                     Data Plane (Datapath)                       │    │
│   │   ┌─────────────────────────────────────────────────────────┐  │    │
│   │   │              Software Datapath (fallback)                │  │    │
│   │   │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │  │    │
│   │   │   │  Flow   │  │ Conn    │  │  NAT    │  │  ACL   │    │  │    │
│   │   │   │  Table  │  │ Track   │  │ Table   │  │ Table  │    │  │    │
│   │   │   └─────────┘  └─────────┘  └─────────┘  └─────────┘    │  │    │
│   │   └─────────────────────────────────────────────────────────┘  │    │
│   │                              │                                     │    │
│   │                              ▼                                     │    │
│   │   ┌─────────────────────────────────────────────────────────┐  │    │
│   │   │              Hardware Offload (eSwitch)                   │  │    │
│   │   │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐    │  │    │
│   │   │   │  HW     │  │  HW     │  │  HW     │  │  HW    │    │  │    │
│   │   │   │  Flow   │  │  Conn   │  │  NAT    │  │  ACL   │    │  │    │
│   │   │   │  TCAM   │  │  Track  │  │ Offload │  │ Offload│    │  │    │
│   │   │   └─────────┘  └─────────┘  └─────────┘  └─────────┘    │  │    │
│   │   └─────────────────────────────────────────────────────────┘  │    │
│   └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                      │
│   ┌─────────────────────────────────────────────────────────────────┐    │
│   │                      Physical/SmartNIC                           │    │
│   │   ┌─────────┐  ┌─────────┐  ┌─────────┐  ┌─────────┐          │    │
│   │   │ PF0/1   │  │ VF0-N   │  │ Represent│  │  eSwitch│          │    │
│   │   │ Ports   │  │         │  │  ors    │  │         │          │    │
│   │   └─────────┘  └─────────┘  └─────────┘  └─────────┘          │    │
│   └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

#### 3.3.7 가상 스위치 설정 예시

##### 3.3.7.1 switchdev 모드 설정

```bash
# Mellanox 스위치dev 활성화
# /etc/modprobe.d/mlx5_core.conf
options mlx5_core enable_enhanced_nic=1

# switchdev 모드로 전환
echo 0000:03:00.0 > /sys/bus/pci/drivers/mlx5_core/unbind
echo 0000:03:00.0 > /sys/bus/pci/drivers/mlx5_core/bind
devlink dev eswitch set pci/0000:03:00.0 mode switchdev

# VF 생성
echo 4 > /sys/class/net/p0p1s0f0/device/sriov_numvfs

# VF를 switchdev에 연결
ip link set p0p1s0f0_0 master eth0
```

##### 3.3.7.2 OVS HW Offload 설정

```bash
# OVS 시작 (HW Offload)
ovs-vsctl set Open_vSwitch . other_config:hw-offload=true
systemctl restart openvswitch

# 브릿지 생성
ovs-vsctl add-br br0
ovs-vsctl set bridge br0 datapath_type=netdev

# 브릿지에 포트 추가
ovs-vsctl add-port br0 enp4s0np0
ovs-vsctl add-port br0 enp4s0np1

# HW Offload 확인
ovs-vsctl get Open_vSwitch . other_config:hw-offload
```

##### 3.3.7.3 VF 할당 (Libvirt)

```xml
<!-- VM에 VF 할당 -->
<interface type='hostdev' managed='yes'>
  <source>
    <address type='pci' domain='0x0000' bus='0x03' slot='0x02' function='0x0'/>
  </source>
  <mac address='52:54:00:xx:xx:xx'/>
  <vlan>
    <tag id='100'/>
  </vlan>
</interface>
```

#### 3.3.8 네트워크 카드 종합 매트릭스

| 카드 | PCIe | 속도 | eswitch | switchdev | SR-IOV | OVS HW | RSS | TSO | GRO | VXLAN | IPsec | RDMA |
|------|------|------|---------|-----------|--------|--------|-----|-----|-----|-------|-------|------|
| Mellanox CX-7 | 4.0 | 200G/400G | Yes | Yes | 256 | ASAP² | Yes | Yes | Yes | Yes | Yes | Yes |
| BlueField-3 | 5.0 | 200G/400G | Yes | Yes | 128 | ASAP² | Yes | Yes | Yes | Yes | Yes | Yes |
| Intel E810-CQDA2T | 4.0 | 100G/200G | Yes | Yes | 64 | - | Yes | Yes | Yes | Yes | Yes | - |
| Broadcom BCM57504 | 4.0 | 100G/200G | Yes | Yes | 64 | switchdev | Yes | Yes | Yes | Yes | - | Yes |
| Pensando DSC-200 | 4.0 | 100G/200G | Yes | Yes | 32 | - | Yes | Yes | Yes | Yes | Yes | - |
| Solarflare EF100 | 4.0 | 100G | Yes | Yes | 64 | Onload | Yes | Yes | Yes | - | - | - |
| AMD Xilinx SN1022 | 4.0 | 100G | Yes | Yes | 16 | - | Yes | Yes | Yes | Yes | - | - |

#### 3.3.9 암호화 가속 하드웨어

암호화 가속 HW 지원 (선택):

| 가속기 | 유형 | 지원 알고리즘 | 요구사항 |
|--------|------|--------------|----------|
| **Intel AES-NI** | CPU 명령어 | AES-CBC, AES-GCM, AES-XTS | x86/x86_64 |
| **Intel AVX-512** | CPU 명령어 | Vectorized Crypto | x86_64 |
| **Intel QAT** | PCIe 카드 | RSA, DH, AES, SHA, Compression | 선택 |
...
| **AMD CCP** | PCIe 카드 | AES, SHA, RSA | 선택 |
| **ARM TrustZone** | Secure Element | Secure Storage, Key mgmt | 선택 |
| **TPM 2.0** | HW Security | Key Storage, Attestation | 선택 |
| **HSM** | External | All Crypto Operations | 선택 |

### 3.4 메모리 관리 및 오프로딩

#### 3.4.1 메모리 할당자

고성능 메모리 관리:

- Slab 할당자 (kmem_cache 기반)
- 메모리 풀 (Memory Pool)
- Huge page 지원 (2MB, 1GB)
- 대용량 페이지 할당 (mlock, mmap)
- 메모리 누수 탐지 기능

#### 3.4.2 NUMA 지원

NUMA 시스템 지원:

- NUMA-aware 메모리 할당
- 코어별 로컬 메모리 할당
-跨 NUMA 메모리 접근 최소화

#### 3.4.3 메모리 오프로딩

##### 3.4.3.1 Huge Pages 구성

| 페이지 크기 | 사용처 | 설정 방법 |
|------------|--------|----------|
| 2MB | 일반 패킷 버퍼 | echo 256 > /proc/sys/vm/nr_hugepages |
| 1GB | 대용량 캐시 | mmap with MAP_HUGETLB |
| THP | Transparent Huge Pages | /sys/kernel/mm/transparent_hugepage/enabled |

##### 3.4.3.2 IOMMU 및 DMA 오프로딩

| 기능 | 설명 | 요구사항 |
|------|------|----------|
| IOMMU | I/O 가상화 메모리 관리 | VT-d, AMD-Vi |
| DMA Engine | 직접 메모리 접근 가속 | 선택 |
| IOMMU Passthrough | VM 직접 HW 접근 | 선택 |
| PRU | Programmable Realtime Unit | TI Sitara 등 |

##### 3.4.3.3 리자브 메모리

| 유형 | 용도 | 크기 |
|------|------|------|
| Driver Reserved | 패킷 버퍼 | 64MB - 2GB |
| DMA Buffers | 네트워크 카드 통신 | 카드 의존 |
| Huge Pages | 대용량 버퍼 | 1GB+ |
| Fagment Reassembly | IP 재조립 | 256MB - 1GB |

##### 3.4.3.4 메모리 효율성

- 메모리 풀링 (연결별 할당 방지)
- 슬래빙 감소 (크기 클래스 최적화)
- 버퍼 재사용 (오브젝트 풀)
- 커널 버ypass 시 사용자 공간 메모리 직접 사용

---

## 4. MVC 아키텍처 구현 요구사항

### 4.1 모델 (Model) 레이어

#### 4.1.1 데이터 모델

핵심 데이터 구조:

**세션 테이블 (Session Table)**
```c
// 세션 테이블 엔트리 구조
typedef struct session_entry {
    uint32_t session_id;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  state;
    uint64_t created;
    uint64_t last_active;
    uint64_t timeout;
    uint32_t packets_in;
    uint32_t packets_out;
    uint64_t bytes_in;
    uint64_t bytes_out;
    void    *app_data;
    struct session_entry *next;
} session_entry_t;
```

**정책 (Policy)**
```c
// 방화벽 정책 구조
typedef struct policy_rule {
    uint32_t rule_id;
    uint32_t priority;
    uint8_t  action;         // ALLOW, DENY, DROP, REJECT
    uint8_t  direction;      // IN, OUT, BOTH
    uint32_t src_addr;
    uint32_t src_mask;
    uint32_t dst_addr;
    uint32_t dst_mask;
    uint16_t src_port_start;
    uint16_t src_port_end;
    uint16_t dst_port_start;
    uint16_t dst_port_end;
    uint8_t  protocol;
    uint8_t  app_id;
    uint32_t schedule_id;
    uint32_t user_id;
    uint32_t log_flag;
    uint32_t timeout;
} policy_rule_t;
```

**IPS 시그니처**
```c
// IPS 시그니처 구조
typedef struct ips_signature {
    uint32_t sig_id;
    char     name[128];
    char     description[512];
    uint8_t  severity;       // CRITICAL, HIGH, MEDIUM, LOW
    uint8_t  category;
    char     pattern[256];
    uint8_t  pattern_type;   // PCRE, SIMPLE, RAW
    char     protocol[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t flow_flag;
} ips_signature_t;
```

#### 4.1.2 데이터 저장소

**메모리 내 데이터:**
- 세션 테이블 (해시 테이블)
- 캐시 (LRU 캐시)
- 연결 리스트

**영구 저장소:**
- SQLite (선택적)
- 파일 기반 (JSON/XML)
- 설정 파일

#### 4.1.3 데이터 접근 계층 (DAO)

```c
// 데이터 접근 인터페이스
typedef struct session_dao {
    session_entry_t* (*create)(session_entry_t *entry);
    session_entry_t* (*find_by_id)(uint32_t id);
    session_entry_t* (*find_by_tuple)(uint32_t src_ip, uint32_t dst_ip, 
                                       uint16_t src_port, uint16_t dst_port, 
                                       uint8_t protocol);
    int (*update)(session_entry_t *entry);
    int (*delete)(uint32_t id);
    int (*foreach)(int (*callback)(session_entry_t *, void *), void *arg);
    uint32_t (*count)(void);
    void (*cleanup)(uint64_t timeout);
} session_dao_t;
```

### 4.2 뷰 (View) 레이어

#### 4.2.1 웹 UI 뷰

**대시보드 뷰:**
```c
// 대시보드 데이터 뷰
typedef struct dashboard_view {
    uint64_t uptime;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t active_sessions;
    uint32_t blocked_threats;
    uint32_t cpu_usage;
    uint32_t memory_usage;
    uint32_t bandwidth_in;
    uint32_t bandwidth_out;
    uint64_t timestamp;
} dashboard_view_t;
```

**로그 뷰:**
```c
// 로그 뷰 구조
typedef struct log_view {
    uint64_t timestamp;
    uint8_t  level;
    char     source[64];
    char     message[1024];
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    uint8_t  action;
} log_view_t;
```

#### 4.2.2 CLI 뷰

```c
// CLI 출력 뷰
typedef struct cli_view {
    char buffer[4096];
    uint32_t cursor_pos;
    uint32_t view_mode;    // NORMAL, INSERT, COMMAND
} cli_view_t;
```

#### 4.2.3 JSON/XML 뷰

```c
// 직렬화 인터페이스
typedef struct view_renderer {
    char* (*render_dashboard)(dashboard_view_t *data);
    char* (*render_log_list)(log_view_t *logs, uint32_t count);
    char* (*render_session_list)(session_entry_t *sessions, uint32_t count);
    char* (*render_policy_list)(policy_rule_t *rules, uint32_t count);
    char* (*render_error)(int error_code, const char *message);
} view_renderer_t;
```

### 4.3 컨트롤러 (Controller) 레이어

#### 4.3.1 요청 핸들러

```c
// HTTP 요청 핸들러
typedef struct http_controller {
    int (*handle_get)(http_request_t *req, http_response_t *res);
    int (*handle_post)(http_request_t *req, http_response_t *res);
    int (*handle_put)(http_request_t *req, http_response_t *res);
    int (*handle_delete)(http_request_t *req, http_response_t *res);
} http_controller_t;
```

#### 4.3.2 정책 컨트롤러

```c
// 정책 관리 컨트롤러
typedef struct policy_controller {
    int (*add_rule)(policy_rule_t *rule);
    int (*update_rule)(uint32_t id, policy_rule_t *rule);
    int (*delete_rule)(uint32_t id);
    policy_rule_t* (*get_rule)(uint32_t id);
    policy_rule_t* (*match_packet)(packet_info_t *packet);
    int (*reorder_rules)(uint32_t *order, uint32_t count);
} policy_controller_t;
```

#### 4.3.3 세션 컨트롤러

```c
// 세션 관리 컨트롤러
typedef struct session_controller {
    session_entry_t* (*create_session)(packet_info_t *packet);
    int (*update_session)(session_entry_t *session);
    int (*destroy_session)(uint32_t session_id);
    session_entry_t* (*lookup_session)(packet_info_t *packet);
    void (*cleanup_timeout)(void);
    uint32_t (*get_session_count)(void);
} session_controller_t;
```

#### 4.3.4 이벤트 디스패처

```c
// 이벤트 시스템
typedef enum event_type {
    EVENT_PACKET_RECEIVED,
    EVENT_SESSION_CREATED,
    EVENT_SESSION_DESTROYED,
    EVENT_THREAT_DETECTED,
    EVENT_POLICY_VIOLATION,
    EVENT_SYSTEM_ERROR,
    EVENT_CONFIG_CHANGED
} event_type_t;

typedef struct event {
    event_type_t type;
    uint64_t timestamp;
    void *data;
    void (*handler)(struct event *);
} event_t;

typedef struct event_dispatcher {
    int (*subscribe)(event_type_t type, void (*handler)(event_t *));
    int (*unsubscribe)(event_type_t type, void (*handler)(event_t *));
    int (*dispatch)(event_t *event);
    void (*process_events)(void);
} event_dispatcher_t;
```

---

## 5. 패킷 처리 요구사항

### 5.1 상태적 패킷 검사 (Stateful Packet Inspection)

#### 5.1.1 TCP 연결 추적

모든 TCP 세션의 연결 상태를 추적해야 한다. 연결 상태는 다음 단계를 포함한다:

- **NEW**: 새로운 연결 시작 (SYN 패킷 수신)
- **ESTABLISHED**: 연결 수립 완료 (3-way handshake 완료)
- **RELATED**: 기존 연결과 관련된 새로운 연결 (예: FTP 데이터 채널)
- **FIN_WAIT**: 연결 종료 과정
- **TIME_WAIT**: 연결 종료 후 대기 상태
- **CLOSED**: 연결 종료

#### 5.1.2 세션 테이블 관리

세션 테이블은 다음 요구사항을 충족해야 한다:

- 최대 100만 개 이상의 동시 세션 저장
- 세션 시간 초과 설정 가능 (기본값: TCP 3600초, UDP 60초)
- 세션 테이블 메모리 효율적 관리 (슬래빙 방지)
- 세션 검색 시간 복잡도 O(1) 달성
- 세션 만료 시 완전한 리소스 해제

#### 5.1.3 UDP 트래킹

UDP는 상태가 없는 프로토콜이지만, "연결과 유사한" 트래킹을 제공해야 한다:

- 5-tuple (Src IP, Dst IP, Src Port, Dst Port, Protocol) 기반 세션 생성
- UDP 세션 시간 초과 관리 (기본값: 60초)
- DNS, VoIP 등 UDP 기반 프로토콜의 세션 추적

#### 5.1.4 프래그먼트 처리 및 IP 재조립

분할된 IP 패킷을 올바르게 재조립하여 검사해야 한다:

- IPv4 프래그먼트 재조립
- IPv6 프래그먼트 재조립
- 프래그먼트 버퍼 관리 (메모리 제한)
- 프래그먼트 시간 초과 (기본값: 60초)
- overlapping 프래그먼트 탐지 및 처리
- 프래그먼트 기반 회피 기법 탐지

#### 5.1.5 NAT (Network Address Translation)

다음 NAT 모드를 지원해야 한다:

- **SNAT (Source NAT)**: 내부 네트워크에서 외부로 나가는 트래픽의 소스 IP 주소 변환
- **DNAT (Destination NAT)**: 외부에서 내부로 들어오는 트래픽의 대상 IP 주소 변환
- **PAT (Port Address Translation)**: 포트 기반 주소 변환 (Many-to-One NAT)
- **NAT Pool**: 여러 공인 IP를 풀(pool)로 관리
- **NAT Traversal**: VPN과 함께하는 NAT 환경 지원
- **NAT 환경에서의 IPS/IDS 동작**: NAT 환경에서도 정확한 위협 탐지

#### 5.1.6 ALG (Application Layer Gateway)

다음 프로토콜의 ALG를 지원해야 한다:

- FTP (PORT/PASV 명령 처리)
- SIP (VoIP 신호 분석)
- H.323 (화상 회의)
- DNS (동적 DNS 업데이트)
- PPTP
- TFTP

### 5.2 패킷 필터링

#### 5.2.1 계층별 필터링

각 OSI 모델 계층별로 필터링 기능을 제공해야 한다:

**Layer 2 (데이터 링크 계층)**:
- 소스/대상 MAC 주소 필터링
- 이더타입(EtherType) 기반 필터링
- VLAN 태그 기반 필터링

**Layer 3 (네트워크 계층)**:
- 소스/대상 IP 주소 필터링 (IPv4 및 IPv6)
- IP 프로토콜 번호 기반 필터링
- TTL (Time To Live) 검사
- IP 옵션 처리

**Layer 4 (전송 계층)**:
- 소스/대상 포트 필터링
- TCP 플래그 검사 (SYN, ACK, FIN, RST, PSH, URG)
- UDP 기반 필터링

**Layer 7 (애플리케이션 계층)**:
- HTTP/HTTPS 프로토콜 검사
- DNS 쿼리 분석
- SMTP 명령 분석
- FTP 명령 분석
- 自訂 프로토콜 지원

#### 5.2.2 ACL (접근 제어 목록)

다음과 같은 ACL 기능을 지원해야 한다:

- 명시적 Deny All 규칙 (기본 거부)
- 명시적 Permit/Deny 규칙
- 객체 기반 규칙 (IP 주소 객체, 포트 객체, 서비스 객체)
- 규칙 우선순위 관리
- 규칙 충돌 해결
- 규칙 활성화/비활성화
- 규칙 히스토리 및 변경 추적

#### 5.2.3 정책 충돌 해결

여러 규칙이 충돌할 경우 다음과 같은 해결 메커니즘이 필요한다:

- 명시적 규칙이 암시적 규칙보다 우선
- 상위 규칙이 하위 규칙보다 우선
- 더 구체적인 규칙이 일반적인 규칙보다 우선
- 정책 충돌 경고 및 로깅

### 5.3 네트워크 기능

#### 5.3.1 VLAN 지원

802.1Q VLAN 태깅을 지원해야 한다:

- VLAN ID 범위: 1-4094
- VLAN 태그 추가/제거
- VLAN 간 라우팅
- VLAN 태그 기반 정책 적용
- QinQ (VLAN Stacking) 지원
- Native VLAN 지원

#### 5.3.2 브릿지 및 라우터 모드

다양한 네트워크 구성 모드를 지원해야 한다:

- **라우터 모드 (Layer 3)**: IP 라우팅 기능 활성화, NAT, PAT 지원
- **트랜스parent 모드 (Layer 2)**: 브릿지로 동작, IP 주소 없음
- **혼합 모드**: 특정 인터페이스는 라우터, 다른 인터페이스는 브릿지로 동작
- **모드 간 전환**: 운영 중 모드 변경 지원

#### 5.3.3 IPv6 지원

IPv6 트래픽에 대해서도 모든 보안 기능을 지원해야 한다:

- IPv6 패킷 필터링
- IPv6 상태적 검사
- IPv6 NAT64/DNS64
- IPv6 IPS/IDS
- IPv6 ACL

---

## 6. 애플리케이션 컨트롤 요구사항

### 6.1 애플리케이션 식별

#### 6.1.1 심층 패킷 검사 (DPI)

패킷 페이로드까지 분석하여 애플리케이션 프로토콜을 식별해야 한다:

- 포트 독립적인 프로토콜 식별
- 암호화된 트래픽에서 메타데이터 분석
- HTTP/HTTPS 요청 분석 (User-Agent, Host, URL 패턴)
- DNS 쿼리 분석 (도메인 기반 애플리케이션 식별)
- SSL/TLS 인증서 분석 (SNI, 인증서 내용)

#### 6.1.2 애플리케이션 시그니처

1000개 이상의 애플리케이션 시그니처를 지원해야 한다:

- 알려진 프로토콜 (HTTP, HTTPS, FTP, SMTP, DNS 등)
- P2P 프로토BitTorrent, eDonkey, Gnutella 등)
- 메시징 (WhatsApp, Telegram, Slack, Discord 등)
- 소셜 미디어 (Facebook, Twitter, Instagram, LinkedIn 등)
- 스트리밍 (YouTube, Netflix, Spotify, Twitch 등)
- 클라우드 서비스 (Dropbox, Google Drive, OneDrive 등)
- 원격 액세스 (TeamViewer, AnyDesk, VNC, RDP 등)
- 게임 (Steam, Epic Games, Riot Games 등)
- 커맨드 앤 컨트롤 (C2) 프로토콜 탐지

#### 6.1.3 자체 구현 DPI 엔진

순수 C로 DPI 엔진을 직접 구현해야 한다:

```c
// DPI 엔진 구조
typedef struct dpi_engine {
    int (*init)(void);
    int (*add_signature)(dpi_signature_t *sig);
    int (*remove_signature)(uint32_t sig_id);
    int (*process_packet)(const uint8_t *payload, uint32_t len, dpi_result_t *result);
    int (*process_stream)(stream_t *stream, dpi_result_t *result);
    void (*cleanup)(void);
} dpi_engine_t;
```

### 6.2 애플리케이션 정책

#### 6.2.1 애플리케이션 제어

애플리케이션별 접근 제어를 지원해야 한다:

- 애플리케이션별 허용/차단
- 애플리케이션 카테고리별 허용/차단
- 특정 애플리케이션 기능 제한
- 사용자/그룹별 애플리케이션 정책
- 시간 기반 애플리케이션 정책

#### 6.2.2 대역폭 관리

애플리케이션별 대역폭 제어를 지원해야 한다:

- 애플리케이션별 带域 제한
- 애플리케이션 카테고리별帯域 제한
- 보장帯域 및 최대帯域 설정

---

## 7. 침입 방지 시스템 (IPS/IDS) 요구사항

### 7.1 탐지 기능

#### 7.1.1 시그니처 기반 위협 탐지

알려진 위협의 시그니처 데이터베이스를 유지해야 한다:

- CVE 번호로 매핑된 시그니처
- 공격 유형별 분류
- 최신 위협 시그니처 업데이트 (최소 일 1회)
- 自訂 시그니처 생성 지원
- 시그니처 심각도 등급

#### 7.1.2 자체 구현 정규 표현식 엔진

시그니처 매칭을 위한 정규 표현식 엔진을 C로 직접 구현해야 한다:

```c
// 정규 표현식 엔진 인터페이스
typedef struct regex_engine {
    regex_t* (*compile)(const char *pattern, int flags);
    int (*match)(regex_t *re, const char *text, regmatch_t *matches);
    int (*search)(regex_t *re, const char *text, regmatch_t *matches);
    void (*free)(regex_t *re);
} regex_engine_t;
```

#### 7.1.3 이상 기반 탐지

시그니처가 없는 새로운 공격을 탐지하기 위한 이상 탐지 기능:

- 네트워크 정상 행동 프로파일 생성
- 프로토콜 표준 준수 여부 검사
- 비정상적인 패킷 패턴 탐지

#### 7.1.4 웹 공격 탐지

웹 애플리케이션 공격을 탐지해야 한다:

- SQL 인젝션 (SQL Injection)
- 크로스사이트 스크립팅 (XSS)
- 크로스사이트 요청 위조 (CSRF)
- 디렉터리 트래버설 (Directory Traversal)
- 명령 주입 (Command Injection)
- 파일 포함 공격 (File Inclusion)

### 7.2 위협 데이터베이스

#### 7.2.1 시그니처 데이터베이스

시그니처 데이터베이스는 다음 요구사항을 충족해야 한다:

- 최소 10만 개 이상의 시그니처 지원
- 시그니처 카테고리 분류
- 시그니처 심각도 등급

#### 7.2.2 시그니처 관리

시그니처 업데이트 및 관리는 다음과 같이 지원해야 한다:

- 자동 시그니처 업데이트 (스케줄 설정 가능)
- 手動 시그니처 업데이트
- 시그니처 버전 관리
- 시그니처 활성화/비활성화

### 7.3 방지 조치

#### 7.3.1即时 조치

위협 탐지 시 即각적인 조치를 수행해야 한다:

- 악성 패킷 폐기 (Drop)
- TCP 연결 재설정 (Reset)
- 의심스러운 연결 차단
- IP 기반 자동 차단 (Reputation Blocking)

---

## 8. SSL/TLS 검사 요구사항

### 8.1 SSL/TLS 복호화

#### 8.1.1 프로토콜 지원

다음 SSL/TLS 프로토콜 버전을 지원해야 한다:

- TLS 1.3 (최종 권장)
- TLS 1.2
- TLS 1.1 (비권장)
- TLS 1.0 (비권장)

#### 8.1.2 암호화 스위트 지원

다음 암호화 스위트를 지원해야 한다:

- AES-GCM (128/256-bit)
- AES-CBC (128/256-bit)
- ChaCha20-Poly1305
- 3DES (레거시 호환)

### 8.2 자체 암호화 라이브러리

순수 C로 암호화 라이브러리를 직접 구현해야 한다:

#### 8.2.1 대칭 암호화

```c
// 대칭 암호화 인터페이스
typedef struct crypto_cipher {
    int (*init)(const uint8_t *key, size_t key_len, const uint8_t *iv);
    int (*encrypt)(const uint8_t *plaintext, size_t len, uint8_t *ciphertext);
    int (*decrypt)(const uint8_t *ciphertext, size_t len, uint8_t *plaintext);
    int (*set_iv)(const uint8_t *iv);
    void (*cleanup)(void);
} crypto_cipher_t;
```

#### 8.2.2 해시 함수

```c
// 해시 함수 인터페이스
typedef struct crypto_hash {
    int (*init)(void);
    int (*update)(const uint8_t *data, size_t len);
    int (*final)(uint8_t *digest);
    size_t (*digest_size)(void);
} crypto_hash_t;
```

#### 8.2.3 구현해야 할 암호화 알고리즘

| 알고리즘 | 용도 | 구현 필요 |
|---------|------|----------|
| AES-128/256-GCM | 암호화/복호화 | 필수 |
| AES-128/256-CBC | 암호화/복호화 | 필수 |
| ChaCha20-Poly1305 | 암호화/복호화 | 필수 |
| SHA-1 | 레거시 호환 | 권장 |
| SHA-256 | HMAC, 서명 | 필수 |
| SHA-384/512 | 고강도 HMAC | 필수 |
| MD5 | 레거시 호환 | 권장 |
| RSA | 키 교환, 서명 | 필수 |
| ECDH | 키 교환 | 필수 |
| ECDSA | 서명 | 필수 |
| HKDF | 키 파생 | 필수 |
| PBKDF2 | 비밀번호 기반 키 파생 | 필수 |

---

## 9. URL 필터링 요구사항

### 9.1 URL 데이터베이스

#### 9.1.1 카테고리 데이터베이스

100개 이상의 URL 카테고리를 지원해야 한다.

#### 9.1.2 자체 구현 URL 분류 엔진

순수 C로 URL 분류 엔진을 구현해야 한다:

```c
// URL 분류 엔진
typedef struct url_classifier {
    int (*init)(void);
    int (*load_database)(const char *path);
    int (*classify)(const char *url, uint32_t *category_id, float *confidence);
    int (*add_custom_rule)(const char *pattern, uint32_t category);
    int (*remove_custom_rule)(uint32_t rule_id);
} url_classifier_t;
```

### 9.2 필터링 조치

#### 9.2.1 카테고리 기반 차단

카테고리별 접근 제어:

- 카테고리별 허용/차단
- 시간별 카테고리 정책 변경
- 사용자/그룹별 카테고리 정책

---

## 10. 맬웨어 방지 요구사항

### 10.1 맬웨어 탐지

#### 10.1.1 실시간 검사

실시간으로 맬웨어를 탐지해야 한다:

- 파일 다운로드 시 即각 검사
- 파일 업로드 시 即각 검사
- 이메일 첨부파일 검사
- 웹 콘텐츠 검사

#### 10.1.2 탐지 유형

다양한 유형의 맬웨어 탐지 지원:

-바이러스 (Virus)
- 트로이목마 (Trojan)
- 웜 (Worm)
- 랜섬웨어 (Ransomware)
- 스파이웨어 (Spyware)
- 키로거 (Keylogger)
- 백도어 (Backdoor)

### 10.2 자체 구현 안티맬웨어 엔진

#### 10.2.1 시그니처 데이터베이스

```c
// 맬웨어 시그니처 구조
typedef struct malware_signature {
    uint32_t sig_id;
    char     name[256];
    uint8_t  malware_type;
    uint8_t  hash_type;      // MD5, SHA1, SHA256
    uint8_t  hash[64];       // 최대 SHA-512
    uint32_t pattern_offset;
    uint8_t  pattern[256];
    uint32_t severity;
} malware_signature_t;
```

#### 10.2.2 파일 스캐너

```c
// 파일 스캐너 인터페이스
typedef struct malware_scanner {
    int (*init)(void);
    int (*scan_file)(const char *path, malware_result_t *result);
    int (*scan_buffer)(const uint8_t *buffer, size_t len, malware_result_t *result);
    int (*add_signature)(malware_signature_t *sig);
    int (*remove_signature)(uint32_t sig_id);
    void (*cleanup)(void);
} malware_scanner_t;
```

---

## 11. 사용자 인증 및 정책 요구사항

### 11.1 자체 구현 인증 시스템

#### 11.1.1 사용자 데이터베이스

```c
// 사용자 구조
typedef struct user {
    uint32_t user_id;
    char     username[64];
    char     password_hash[128];
    char     salt[32];
    uint32_t group_id;
    uint32_t role;
    uint64_t created;
    uint64_t last_login;
    uint8_t  status;
} user_t;
```

#### 11.1.2 인증 방법

| 인증 방법 | 구현 요구사항 |
|----------|-------------|
| 로컬 비밀번호 | 필수 (bcrypt/scrypt/pbkdf2) |
| RADIUS 클라이언트 | 필수 |
| LDAP 클라이언트 | 필수 |
| TACACS+ 클라이언트 | 권장 |

### 11.2 RBAC (역할 기반 접근 제어)

역할 및 권한 관리:

| 역할 | 권한 |
|------|------|
| Admin | 전체 시스템 관리 |
| Security Admin | 보안 정책 관리 |
| Network Admin | 네트워크 설정 관리 |
| Monitor | 모니터링 및 보고서만 viewing |
| User | 자신의 프로필 관리 |

---

## 12. VPN 요구사항

### 12.1 IPsec VPN

#### 12.1.1 IKE (Internet Key Exchange)

IKE 프로토콜 지원:

- **IKEv1**: Aggressive Mode, Main Mode
- **IKEv2**: RFC 4306 기반 (권장)

#### 12.1.2 자체 구현 IKE 데몬

순수 C로 IKE 엔진을 구현해야 한다:

```c
// IKE 엔진 구조
typedef struct ike_engine {
    int (*init)(ike_config_t *config);
    int (*start)(void);
    int (*stop)(void);
    int (*add_sa)(ike_sa_t *sa);
    int (*delete_sa)(uint32_t spi);
    int (*process_packet)(const uint8_t *pkt, size_t len);
} ike_engine_t;
```

#### 12.1.3 암호화 및 인증

| 구분 | 지원 항목 | 구현 요구사항 |
|------|----------|--------------|
| 암호화 | AES-128, AES-256, ChaCha20 | 필수 |
| 해시 | SHA-256, SHA-384, SHA-512 | 필수 |
| DH 그룹 | DH Group 14, 19, 20, 21 | 필수 |
| PFS | 지원 | 필수 |

### 12.2 SSL VPN

#### 12.2.1 SSL VPN 서버

자체 구현 SSL VPN 서버:

```c
// SSL VPN 서버 구조
typedef struct ssl_vpn_server {
    int (*init)(ssl_vpn_config_t *config);
    int (*start)(void);
    int (*stop)(void);
    int (*connect)(ssl_vpn_session_t *session);
    int (*disconnect)(uint32_t session_id);
    int (*tunnel_data)(uint32_t session_id, const uint8_t *data, size_t len);
} ssl_vpn_server_t;
```

---

## 13. DDoS 완화 요구사항

### 13.1 공격 유형별 완화

#### 13.1.1 용량성 공격

다음 공격을 탐지하고 완화해야 한다:

- SYN Flood
- UDP Flood
- ICMP Flood
- DNS Amplification
- NTP Amplification
- HTTP/HTTPS Flood

#### 13.1.2 프로토콜 공격

- TCP 상태 소진
- 연결 제한
- 프로토콜 검증 실패

#### 13.1.3 애플리케이션 계층 공격

- Slowloris
- HTTP Flood
- Slow POST Attack

### 13.2 자체 구현 DDoS 완화 엔진

```c
// DDoS 완화 엔진
typedef struct ddos_mitigator {
    int (*init)(ddos_config_t *config);
    int (*update_config)(ddos_config_t *config);
    int (*process_packet)(packet_info_t *pkt, ddos_action_t *action);
    ddos_stats_t* (*get_stats)(void);
    int (*set_threshold)(ddos_threshold_t *threshold);
} ddos_mitigator_t;
```

---

## 14. 서비스 품질 (QoS) 요구사항

### 14.1 대역폭 관리

#### 14.1.1 자체 구현 큐잉 시스템

```c
// QoS 큐 구조
typedef struct qos_queue {
    uint32_t queue_id;
    uint32_t priority;
    uint32_t weight;
    uint32_t max_bandwidth;
    uint32_t min_bandwidth;
    uint32_t current_rate;
    uint32_t packet_count;
    uint32_t byte_count;
    struct qos_queue *next;
} qos_queue_t;
```

#### 14.1.2 큐잉 알고리즘

| 알고리즘 | 구현 요구사항 |
|----------|--------------|
| Priority Queuing (PQ) | 필수 |
| Weighted Fair Queuing (WFQ) | 필수 |
| Hierarchical Token Bucket (HTB) | 필수 |
| Class-Based Queuing (CBQ) | 권장 |

---

## 15. 로깅 및 모니터링 요구사항

### 15.1 자체 구현 로깅 시스템

#### 15.1.1 로그 포맷

자체 구현 로그 시스템은 다양한 출력 형식을 지원해야 한다:

**로그 레벨:**
| 레벨 | 값 | 설명 |
|------|-----|------|
| TRACE | 0 | 상세 추적 |
| DEBUG | 1 | 디버그 정보 |
| INFO | 2 | 일반 정보 |
| NOTICE | 3 | 중요한 일반 정보 |
| WARNING | 4 | 경고 |
| ERROR | 5 | 오류 |
| CRITICAL | 6 | 심각한 오류 |
| ALERT | 7 | 즉각 조치 필요 |
| EMERGENCY | 8 | 시스템 사용 불가 |

**로그 출력 형식:**
```c
// 로그 엔트리 구조
typedef struct log_entry {
    uint64_t timestamp;           // 마이크로초 단위 타임스탬프
    uint8_t  level;              // 로그 레벨
    uint8_t  module;             // 로그를 발생시킨 모듈
    uint32_t thread_id;           // 스레드 ID
    uint32_t process_id;         // 프로세스 ID
    char     source_file[64];    // 소스 파일명
    uint32_t source_line;        // 소스 라인
    char     message[1024];      // 로그 메시지
    uint32_t src_ip;             // 소스 IP
    uint32_t dst_ip;             // 대상 IP
    uint16_t src_port;           // 소스 포트
    uint16_t dst_port;           // 대상 포트
    uint8_t  protocol;           // 프로토콜
    uint32_t action;             // 수행된 조치
    char     user[64];           // 사용자
    char     session_id[32];      // 세션 ID
} log_entry_t;
```

**로그 출력 형식 (템플릿):**
| 형식 | 예시 |
|------|------|
| Plain | `2026-03-13 10:30:45.123456 [INFO] [core] Session created: 192.168.1.100:443 -> 10.0.0.1:80` |
| JSON | `{"time":"2026-03-13T10:30:45.123456Z","level":"INFO","module":"core","msg":"Session created","src_ip":"192.168.1.100","dst_ip":"10.0.0.1"}` |
| Syslog | `<134>Mar 13 10:30:45 ngfw core: Session created: 192.168.1.100 -> 10.0.0.1` |
| CEF | `CEF:0|NGFW|1.0|1001|Session Created|4|src=192.168.1.100 dst=10.0.0.1` |
| LEEF | `LEEF:1.0|NGFW|1.0|1001|Session Created|src=192.168.1.100 dst=10.0.0.1` |

#### 15.1.2 로그 저장소

**자체 구현 로그 저장 관리:**

| 저장소 유형 | 설명 | 용도 |
|------------|------|------|
| 순환 버퍼 (Ring Buffer) | 고정 크기 메모리 버퍼 | 고성능 실시간 로깅 |
| 파일 저장 | 순환 파일 쓰기 | 영구 저장 |
| 분산 저장 | 다중 파일 분산 | 대용량 로깅 |

**로그 순환 (Log Rotation):**
```c
// 로그 순환 설정
typedef struct log_rotation {
    uint64_t max_size;        // 최대 파일 크기 (MB)
    uint32_t max_files;       // 최대 파일 수
    uint32_t max_age;         // 최대 보관 기간 (일)
    char compress_cmd[128];    // 압축 명령어
    char pattern[64];         // 파일 패턴
    bool async_write;         // 비동기 쓰기
} log_rotation_t;
```

**로그 필터링:**
| 필터 유형 | 설명 |
|----------|------|
| 레벨 필터 | 특정 레벨 이상만 기록 |
| 모듈 필터 | 특정 모듈만 기록 |
| 소스 IP 필터 | 특정 IP만 기록 |
| 정규식 필터 | 메시지 패턴 필터링 |
| 샘플링 | 일정 비율만 기록 |

#### 15.1.3 로그 전송

**원격 로그 전송:**

| 프로토콜 | 설명 | 요구사항 |
|----------|------|----------|
| Syslog (UDP) | RFC 5424 | 필수 |
| Syslog (TCP) | RFC 5424 + TLS | 권장 |
| Kafka | 메시지 큐 | 선택 |
| Redis | 인메모리 저장 | 선택 |
| Elasticsearch | 검색엔진 | 선택 |

#### 15.1.4 로그 분석 기능

**자체 구현 로그 분석:**

```c
// 로그 쿼리 구조
typedef struct log_query {
    uint64_t start_time;
    uint64_t end_time;
    uint8_t  min_level;
    uint32_t module_filter;
    uint32_t ip_filter[2];      // 범위
    char     pattern[256];       // 정규식
    uint32_t limit;
    uint32_t offset;
} log_query_t;

// 로그ggregation
typedef struct log_aggregation {
    uint64_t time_window;       // 시간 창 (초)
    uint8_t  group_by;         // GROUP BY 필드
    uint8_t  aggregate_func;    // AVG, SUM, COUNT, MIN, MAX
} log_aggregation_t;
```

### 15.2 자체 구현 모니터링

#### 15.2.1 메트릭 수집

**시스템 메트릭:**

```c
// 상세 시스템 통계 구조
typedef struct system_stats {
    // 시스템
    uint64_t uptime;
    uint64_t boot_time;
    uint32_t load_average[3];  // 1분, 5분, 15분
    
    // CPU
    uint32_t cpu_usage_total;
    uint32_t cpu_usage_per_core[MAX_CORES];
    uint64_t cpu_context_switches;
    uint64_t cpu_interrupts;
    
    // 메모리
    uint64_t memory_total;
    uint64_t memory_used;
    uint64_t memory_free;
    uint64_t memory_cached;
    uint64_t memory_swap_total;
    uint64_t memory_swap_used;
    
    // 디스크
    uint64_t disk_total;
    uint64_t disk_used;
    uint64_t disk_read_bytes;
    uint64_t disk_write_bytes;
    
    // 네트워크
    uint64_t network_rx_bytes[MAX_INTERFACES];
    uint64_t network_tx_bytes[MAX_INTERFACES];
    uint64_t network_rx_packets[MAX_INTERFACES];
    uint64_t network_tx_packets[MAX_INTERFACES];
    uint64_t network_rx_errors[MAX_INTERFACES];
    uint64_t network_tx_errors[MAX_INTERFACES];
    
    // NGFW 특화
    uint64_t total_packets;
    uint64_t total_bytes;
    uint32_t active_sessions;
    uint32_t tcp_sessions;
    uint32_t udp_sessions;
    uint32_t blocked_threats;
    uint32_t ips_alerts;
    uint64_t bandwidth_in;
    uint64_t bandwidth_out;
    uint32_t connections_per_sec;
    uint32_t new_sessions_per_sec;
    uint32_t nat_translations;
    uint32_t rule_hits[Max_RULES];
} system_stats_t;
```

#### 15.2.2 프로메테우스/Prometheus 지원

**메트릭 형식 지원:**

```c
// Prometheus 형식 내보내기
typedef struct prometheus_metrics {
    // Counter (单向 증가)
    // #TYPE ngfw_packets_total counter
    // #HELP ngfw_packets_total Total packets processed
    // ngfw_packets_total{src="ingress"} 12345
    uint64_t packets_total;
    
    // Gauge (증감 가능)
    // #TYPE ngfw_active_sessions gauge
    // ngfw_active_sessions 10000
    uint32_t active_sessions;
    
    // Histogram
    // #TYPE ngfw_request_duration_seconds histogram
    uint64_t request_duration_ms;
    
    // Summary
    uint64_t response_size_bytes;
} prometheus_metrics_t;
```

#### 15.2.3 SNMP 모니터링

**SNMP 지원:**

| 버전 | 지원 | 용도 |
|------|------|------|
| SNMPv1 | 권장 | 레거시 장치 |
| SNMPv2c | 필수 | 일반 모니터링 |
| SNMPv3 | 권장 | 보안 강화 |

**MIB 지원:**
```c
// NGFW MIB 정의
#define NGFW_MIB_OID "1.3.6.1.4.1.XXXXX"

typedef struct snmp_mib {
    // 시스템 그룹
    { "sysDescr", STRING, "NGFW Next-Generation Firewall" },
    { "sysUpTime", TIMETICKS, uptime },
    { "sysContact", STRING, "admin@ngfw.local" },
    
    // NGFW 그룹
    { "ngfwActiveSessions", GAUGE, active_sessions },
    { "ngfwPacketsProcessed", COUNTER64, total_packets },
    { "ngfwBytesProcessed", COUNTER64, total_bytes },
    { "ngfwThreatsBlocked", COUNTER64, blocked_threats },
    { "ngfwCPUUsage", GAUGE, cpu_usage },
    { "ngfwMemoryUsage", GAUGE, memory_usage },
} snmp_mib_t;
```

#### 15.2.4 대시보드 및 시각화

**자체 구현 대시보드:**

| 대시보드 | 설명 |
|----------|------|
| 시스템 상태 | CPU, 메모리, 디스크, 네트워크 |
| 보안 위협 | 차폐된 위협, IPS 알림 |
| 세션 | 활성 세션, 연결 추이 |
| 대역폭 | 입출력 대역폭, 트래픽 추이 |
| 애플리케이션 | 앱 사용 통계 |
| VPN | VPN 연결 상태 |

### 15.3 알림 시스템

#### 15.3.1 알림 채널

| 채널 | 설명 | 요구사항 |
|------|------|----------|
| Email | SMTP 전송 | 필수 |
| SMS | SMS 게이트웨이 | 선택 |
| Slack | Webhook | 선택 |
| Teams | Webhook | 선택 |
| PagerDuty | Incident Management | 선택 |
| Webhook | HTTP POST | 필수 |
| Syslog | 원격 로깅 | 필수 |
| SNMP Trap | SNMP 알림 | 권장 |

#### 15.3.2 알림 규칙

```c
// 알림 규칙 구조
typedef struct alert_rule {
    uint32_t rule_id;
    char     name[128];
    bool     enabled;
    
    // 조건
    uint8_t  condition_type;   // THRESHOLD, RATE, PATTERN
    char     metric[64];        // 메트릭 이름
    uint32_t threshold;         // 임계값
    uint32_t duration;          // 지속 시간 (초)
    
    // 조치
    uint8_t  actions;          // OR combination
    #define ALERT_EMAIL    0x01
    #define ALERT_SMS      0x02
    #define ALERT_WEBHOOK 0x04
    #define ALERT_SNMP     0x08
    #define ALERT_SYSLOG   0x10
    
    char     email_recipients[512];
    char     webhook_url[256];
    char     severity[16];
} alert_rule_t;
```

---

## 16. 고가용성 (HA) 요구사항

### 16.1 HA 아키텍처

#### 16.1.1 HA 모드 유형

| 모드 | 설명 | 용도 |
|------|------|------|
| Active-Passive | 한 대가 활성, 다른 대가 대기 | 가장 일반적인 구성 |
| Active-Active | 양쪽 모두 활성, 부하 분산 | 고성능 요구 시 |
| Passive-Standby | 구성 동기화만, 페일오버 없음 | 설정 백업 |
| Cluster | 3대 이상集群 | 매우 높은 가용성 |

#### 16.1.2 자체 구현 HA 프로토콜

HA 시스템은 자체 구현해야 하며 외부 의존성을 최소화한다:

```c
// HA 상태 구조
typedef enum ha_state {
    HA_STATE_INIT,           // 초기화
    HA_STATE_ACTIVE,         // 활성 상태
    HA_STATE_STANDBY,      // 대기 상태
    HA_STATE_FAILED,         // 장애 상태
    HA_STATE_MAINTENANCE    // 유지보수 상태
} ha_state_t;

// HA 모드
typedef enum ha_mode {
    HA_MODE_AP,             // Active-Passive
    HA_MODE_AA,             // Active-Active
    HA_MODE_CLUSTER         // Cluster
} ha_mode_t;

// HA 메시지 유형
typedef enum ha_msg_type {
    HA_MSG_HEARTBEAT,       // 하트비트
    HA_MSG_STATE_CHANGE,   // 상태 변경
    HA_MSG_SESSION_SYNC,   // 세션 동기화
    HA_MSG_CONFIG_SYNC,    // 설정 동기화
    HA_MSG_NAT_SYNC,       // NAT 테이블 동기화
    HA_MSG_POLICY_SYNC,    // 정책 동기화
    HA_MSG_FAILOVER,       // 페일오버 요청
    HA_MSG_ACK,           // 확인 응답
    HA_MSG_CLUSTER_JOIN,   //集群 가입
    HA_MSG_CLUSTER_LEAVE  //集群 탈퇴
} ha_msg_type_t;

// HA 메시지 구조
typedef struct ha_message {
    uint16_t version;          // 프로토콜 버전
    uint8_t  type;             // 메시지 유형
    uint8_t  flags;            // 플래그
    uint32_t peer_id;          //peer ID
    uint32_t sequence;         // 시퀀스 번호
    uint64_t timestamp;        // 타임스탬프
    uint32_t session_count;    // 세션 수
    uint32_t checksum;         // 체크섬
    uint32_t data_len;        // 데이터 길이
    uint8_t  data[];          // 가변 데이터
} ha_message_t;

// HA 설정
typedef struct ha_config {
    char     peer_ip[64];      //peer IP 주소
    uint16_t peer_port;        //peer 포트
    char     local_ip[64];     // 로컬 IP 주소
    uint16_t local_port;      // 로컬 포트
    uint8_t  mode;             // HA 모드
    uint8_t  priority;         // 우선순위 (낮을수록 높음)
    uint32_t heartbeat_interval; // 하트비트 간격 (ms)
    uint32_t heartbeat_timeout; // 하트비트超时 (ms)
    uint32_t failover_delay;    // 페일오버 지연 (ms)
    uint32_t sync_interval;    // 동기화 간격 (ms)
    bool     auto_failback;    // 자동 페일백
    uint32_t failback_delay;  // 페일백 지연 (초)
} ha_config_t;
```

### 16.2 HA 프로토콜 구현

#### 16.2.1 하트비트 프로토콜

```c
// 하트비트 구현
typedef struct heartbeat_protocol {
    // 하트비트 송신
    int (*send_heartbeat)(ha_context_t *ctx);
    
    // 하트비트 수신 및 처리
    int (*recv_heartbeat)(ha_context_t *ctx, ha_message_t *msg);
    
    // 장애 감지
    int (*detect_failure)(ha_context_t *ctx);
    
    //peer 가용성 확인
    bool (*is_peer_alive)(ha_context_t *ctx);
} heartbeat_protocol_t;
```

#### 16.2.2 세션 동기화

| 동기화 유형 | 설명 | 방법 |
|------------|------|------|
| 실시간 동기화 | 세션 생성/변경시 즉시 동기화 | 변경 사항만 전송 |
| 주기적 동기화 | 정기적 전체 동기화 | 전체 세션 테이블 |
| 지연 동기화 | 배치为单位 동기화 | 배치 처리 |

**세션 동기화 메시지:**
```c
typedef struct session_sync {
    uint32_t session_id;
    uint8_t  protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  state;
    uint64_t created;
    uint64_t expire;
    uint32_t nat_src_ip;
    uint16_t nat_src_port;
    uint32_t bytes_in;
    uint32_t bytes_out;
} session_sync_t;
```

### 16.3 페일오버

#### 16.3.1 페일오버 조건

| 조건 | 임계값 | 동작 |
|------|--------|------|
| 하트비트丢失 | 3회 연속 | 페일오버 |
| 인터페이스 down | 즉시 | 페일오버 |
| 로컬 프로세스 crash | 즉시 | 페일오버 |
| CPU 과부하 | > 95% 60초 | 경고/페일오버 |
| 메모리 부족 | > 95% 60초 | 경고/페일오버 |

#### 16.3.2 페일오버 과정

```
[1] 장애 감지
    │
    ▼
[2] 확인 (2회 검증)
    │
    ▼
[3] Active 상태 전환 (Standby → Active)
    │
    ├── IP 주소 인계 (VRRP 또는 ARP)
    ├── MAC 주소 인계
    └── 로드 밸런서 업데이트
    │
    ▼
[4] 세션 테이블 동기화 (있다면)
    │
    ▼
[5] 서비스 재개
    │
    ▼
[6] 관리자 알림
```

### 16.4 클러스터 (3대 이상)

#### 16.4.1集群 프로토콜

```c
//集群 상태
typedef enum cluster_state {
    CLUSTER_STATE_INIT,
    CLUSTER_STATE_FORMING,
    CLUSTER_STATE_STABLE,
    CLUSTER_STATE_DEGRADED,
    CLUSTER_STATE_FAILED
} cluster_state_t;

//集群 구성원
typedef struct cluster_member {
    uint32_t member_id;
    char     name[64];
    char     ip[64];
    uint16_t port;
    uint8_t  state;
    uint8_t  role;           // MASTER, SLAVE, WITNESS
    uint32_t priority;
    uint64_t last_seen;
} cluster_member_t;

// Raft/Paxos 기반 consensus (자체 구현)
typedef struct consensus_protocol {
    int (*request_vote)(uint32_t candidate_id, uint64_t term);
    int (*append_entries)(uint32_t leader_id, uint64_t term, 
                         uint32_t prev_index, uint64_t prev_term);
    int (*commit_log)(uint32_t index);
} consensus_protocol_t;
```

### 16.5 설정 동기화

#### 16.5.1 동기화 대상

| 설정 항목 | 동기화 방법 | 우선순위 |
|----------|------------|---------|
| 보안 정책 | 실시간 | 높음 |
| NAT 규칙 | 실시간 | 높음 |
| 사용자 데이터 | 실시간 | 중간 |
| 인증서 | 주기적 | 낮음 |
| SSL 검사 설정 | 주기적 | 낮음 |
| IPS 시그니처 | 참조 (별도) | - |

### 16.6 자체 구현 HA의 장점

| 장점 | 설명 |
|------|------|
| 외부 의존성 제거 | 외부 HA 솔루션 의존 없음 |
| 최적화된 프로토콜 | NGFW에 특화된 효율적인 동기화 |
| 커스터마이징 | 요구에 맞는 기능 구현 가능 |
| 자원 효율 | 불필요한 기능 제거로 경량화 |

---

## 17. 관리 인터페이스 요구사항

### 17.1 자체 구현 웹 서버

NGFW는 외부 웹 서버(Apache, Nginx 등)에 의존하지 않고 자체 구현한 웹 서버를 사용해야 한다.

#### 17.1.1 HTTP/HTTPS 서버 아키텍처

순수 C로 HTTP/HTTPS 서버를 구현해야 한다:

```c
// HTTP 서버 구조
typedef struct http_server {
    char     bind_addr[64];
    uint16_t port;
    bool     ssl_enabled;
    char     cert_file[256];
    char     key_file[256];
    uint32_t max_connections;
    uint32_t worker_threads;
    uint32_t timeout;
    
    // 핸들러
    http_handler_t handlers[MAX_HANDLERS];
    
    // 세션 관리
    http_session_manager_t *session_mgr;
    
    // 정적 파일 서버
    bool     enable_static;
    char     document_root[256];
} http_server_t;
```

#### 17.1.2 HTTP 메서드 지원

| 메서드 | 지원 | 설명 |
|--------|------|------|
| GET | 필수 | 리소스 조회 |
| POST | 필수 | 리소스 생성 |
| PUT | 필수 | 리소스 수정 |
| DELETE | 필수 | 리소스 삭제 |
| PATCH | 권장 | 부분 수정 |
| HEAD | 권장 | 헤더만 조회 |
| OPTIONS | 권장 | 지원 메서드 조회 |

#### 17.1.3 REST API 엔드포인트

**API 버전 관리:**
```
/api/v1/...  (v1 - 현재)
/api/v2/...  (v2 - 개발 중)
```

**RESTful 리소스:**

| 리소스 | 메서드 | 설명 |
|--------|--------|------|
| /api/v1/system | GET, PUT | 시스템 설정 |
| /api/v1/network | GET, PUT | 네트워크 설정 |
| /api/v1/interfaces | GET, POST, PUT, DELETE | 인터페이스 관리 |
| /api/v1/policy | GET, POST, PUT, DELETE | 보안 정책 |
| /api/v1/rules | GET, POST, PUT, DELETE | 필터 규칙 |
| /api/v1/nat | GET, POST, PUT, DELETE | NAT 규칙 |
| /api/v1/routes | GET, POST, PUT, DELETE | 라우팅 |
| /api/v1/sessions | GET | 활성 세션 |
| /api/v1/stats | GET | 통계 정보 |
| /api/v1/logs | GET | 로그 조회 |
| /api/v1/users | GET, POST, PUT, DELETE | 사용자 관리 |
| /api/v1/groups | GET, POST, PUT, DELETE | 그룹 관리 |
| /api/v1/auth | POST | 인증 |
| /api/v1/vpn | GET, POST, PUT, DELETE | VPN 설정 |
| /api/v1/ips | GET, PUT | IPS 설정 |
| /api/v1/urlfilter | GET, PUT | URL 필터 설정 |
| /api/v1/ha | GET, PUT | HA 설정 |
| /api/v1/backup | POST | 백업/복원 |

#### 17.1.4 자체 구현 CLI

**CLI 모드:**

| 모드 | 프롬프트 | 설명 |
|------|---------|------|
| Privileged Exec | > | 시스템 정보, 작업 수행 |
| Global Config | (config)# | 전역 설정 |
| Interface Config | (config-if)# | 인터페이스 설정 |
| Policy Config | (config-policy)# | 정책 설정 |
| VPN Config | (config-vpn)# | VPN 설정 |
| Route Config | (config-route)# | 라우팅 설정 |

**CLI 명령어 구조:**

```c
// CLI 명령어 정의
typedef struct cli_command {
    const char *name;           // 명령어 이름
    const char *shortcut;      // 단축 명령
    const char *help;          // 도움말 텍스트
    enum cli_mode mode;        // 실행 가능한 모드
    enum cli_priv_level priv;  // 필요한 권한
    
    // 핸들러
    int (*handler)(cli_context_t *ctx, int argc, char **argv);
    
    // 서브 commands
    struct cli_command *subcommands;
    
    // 완료 핸들러 (Tab 자동완성)
    char** (*completer)(cli_context_t *ctx, const char *word, int pos);
} cli_command_t;
```

**주요 CLI 명령어:**

```bash
# 시스템
show system info
show version
show uptime
show license
reboot
shutdown
reload

# 네트워크
show interfaces
show interface <name>
set interface <name> ip <addr>
show ip routes
show arp table

# 정책
show policies
add policy <rule>
delete policy <id>
edit policy <id>
move policy <from> <to>

# 세션
show sessions
show sessions interface <name>
show sessions source-ip <addr>
show sessions destination-ip <addr>
clear sessions
clear sessions interface <name>

# 로그
show logs
show logs level <level>
show logs module <module>
show logs source-ip <addr>
export logs

# 통계
show statistics
show statistics interface <name>
show statistics protocol <proto>
clear statistics

# IPS
show ips rules
enable ips
disable ips

# HA
show ha status
show ha peers
set ha mode <ap|aa>
```

#### 17.1.5 원격 접근 프로토콜

| 프로토콜 | 포트 | 지원 | 설명 |
|----------|------|------|------|
| HTTP | 80 | 필수 | 로컬 관리 |
| HTTPS | 443 | 필수 | 암호화된 관리 |
| SSH | 22 | 필수 | CLI 원격 |
| Telnet | 23 | 비권장 | 레거시 CLI |
| SNMP | 161/162 | 권장 | 모니터링 |
| IPMI/Redfish | 623 | 선택 | BMC 관리 |

### 17.2 설정 관리

#### 17.2.1 설정 관리 기능

```c
// 설정 관리자
typedef struct config_manager {
    // 설정 로드/저장
    int (*load)(const char *path);
    int (*save)(const char *path);
    int (*export)(const char *path, enum config_format fmt);
    int (*import)(const char *path, enum config_format fmt);
    
    // 설정 검증
    int (*validate)(void);
    
    // 설정 비교
    int (*diff)(config_t *a, config_t *b, config_diff_t *diff);
    
    // 설정 롤백
    int (*rollback)(uint32_t version);
    int (*snapshot)(const char *comment);
} config_manager_t;
```

#### 17.2.2 설정 백업/복원

| 기능 | 설명 |
|------|------|
| 수동 백업 | 사용자가 수동 백업 |
| 스케줄 백업 |cron 기반 자동 백업 |
| 버전 관리 | 최대 N개 버전 유지 |
| 암호화 백업 | AES 암호화 지원 |
| 원격 백업 | FTP/SFTP/SCP로 전송 |

### 17.3 펌웨어 관리

#### 17.3.1 펌웨어 업데이트

```c
// 펌웨어 관리자
typedef struct fw_manager {
    // 펌웨어 정보
    int (*get_info)(fw_info_t *info);
    
    // 펌웨어 업데이트
    int (*update)(const char *image_path);
    int (*verify)(const char *image_path);
    
    // 롤백
    int (*rollback)(void);
    
    // 부트 관리
    int (*set_default_boot)(uint8_t slot);
} fw_manager_t;
```
    int (*add_route)(const char *path, http_handler_t handler);
    int (*set_tls)(tls_config_t *config);
} http_server_t;
```

#### 17.1.2 REST API 엔드포인트

| 엔드포인트 | 메서드 | 설명 |
|-----------|--------|------|
| /api/v1/system | GET, PUT | 시스템 설정 |
| /api/v1/network | GET, PUT | 네트워크 설정 |
| /api/v1/policy | GET, POST, PUT, DELETE | 보안 정책 |
| /api/v1/sessions | GET | 세션 목록 |
| /api/v1/stats | GET | 통계 정보 |
| /api/v1/logs | GET | 로그 조회 |

### 17.2 CLI (자체 구현)

#### 17.2.1 CLI 구조

```c
// CLI 엔진 구조
typedef struct cli_engine {
    int (*init)(void);
    int (*start)(void);
    int (*stop)(void);
    int (*add_command)(const char *name, cli_handler_t handler, const char *help);
    int (*execute)(const char *input);
} cli_engine_t;
```

#### 17.2.2 CLI 모드

| 모드 | 프롬프트 | 설명 |
|------|---------|------|
| Privileged Exec | > | 시스템 정보, 작업 수행 |
| Global Config | (config)# | 전역 설정 모드 |
| Interface Config | (config-if)# | 인터페이스 설정 |
| Policy Config | (config-policy)# | 정책 설정 |

---

## 18. 데이터 직렬화 요구사항

### 18.1 자체 구현 JSON 인코더/디코더

순수 C로 JSON 처리를 구현해야 한다:

```c
// JSON 값 유형
typedef enum json_type {
    JSON_NULL,
    JSON_BOOL,
    JSON_NUMBER,
    JSON_STRING,
    JSON_ARRAY,
    JSON_OBJECT
} json_type_t;

// JSON 값 구조
typedef struct json_value {
    json_type_t type;
    union {
        bool bool_value;
        double number_value;
        char *string_value;
        struct json_array *array;
        struct json_object *object;
    };
} json_value_t;

// JSON 파서
typedef struct json_parser {
    json_value_t* (*parse)(const char *json_str);
    char* (*stringify)(json_value_t *value);
    void (*free_value)(json_value_t *value);
} json_parser_t;
```

### 18.2 설정 파일 포맷

JSON 형식으로 설정 파일 관리:

- 설정 파일 읽기/쓰기
- 설정 유효성 검사
- 설정 백업/복원

---

## 19. 빌드 및 배포 요구사항

### 19.1 빌드 시스템

#### 19.1.1 빌드 시스템 개요

NGFW는 다음 빌드 시스템을 지원해야 한다:

| 빌드 시스템 | 설명 | 사용처 |
|------------|------|--------|
| **GNU Make** | 기본 Makefile | 기본 빌드 |
| **GNU Autotools** | autoconf/automake | 배포판 패키징 |
| **CMake** | 크로스 플랫폼 빌드 | IDE 통합 |
| **Meson** | 현대적 빌드 시스템 | 빠른 빌드 (선택) |

#### 19.1.2 GNU Makefile 빌드

기본 Makefile 기반 빌드:

```makefile
# NGFW Makefile (상세 구조)
# ============================================================

# 프로젝트 정보
PROJECT_NAME = ngfw
VERSION = 1.0.0
PACKAGE = $(PROJECT_NAME)-$(VERSION)
prefix = /usr/local
exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
includedir = $(prefix)/include
sysconfdir = /etc/$(PROJECT_NAME)
localstatedir = /var

# 대상 아키텍처
ARCH ?= $(shell uname -m)
CROSS_COMPILE ?=
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
AR = $(CROSS_COMPILE)ar
RANLIB = $(CROSS_COMPILE)ranlib
STRIP = $(CROSS_COMPILE)strip

# 컴파일러 플래그
WARNINGS = -Wall -Wextra -Wpedantic -Werror
CSTD = -std=c99
OPTIMIZATION = -O2 -march=native
PROFILING = -pg
DEBUG = -g -ggdb
PIC = -fPIC
LTO = -flto

# 기본 CFLAGS
CFLAGS = $(WARNINGS) $(CSTD) $(OPTIMIZATION) $(PIC) -I./include -I./include/$(ARCH)
CFLAGS += -DVERSION=\"$(VERSION)\" -DPACKAGE=\"$(PACKAGE)\"

# 디렉토리
SRC_DIR = src
BUILD_DIR = build/$(ARCH)
BIN_DIR = bin/$(ARCH)
LIB_DIR = lib/$(ARCH)
DOC_DIR = doc
TEST_DIR = tests

# 소스 디렉토리 구조
SRC_SUBDIRS = core network security crypto web cli platform
CORE_SRCS = $(SRC_DIR)/core/main.c $(SRC_DIR)/core/init.c
NETWORK_SRCS = $(SRC_DIR)/network/packet.c $(SRC_DIR)/network/session.c
SECURITY_SRCS = $(SRC_DIR)/security/ips.c $(SRC_DIR)/security/firewall.c
CRYPTO_SRCS = $(SRC_DIR)/crypto/aes.c $(SRC_DIR)/crypto/sha.c

# 오브젝트 파일
OBJS = $(patsubst $(SRC_DIR)/%.c,$(BUILD_DIR)/%.o,$(wildcard $(SRC_DIR)/*.c $(SRC_DIR)/*/*.c))

# 모듈
MODULES = core network packet filter ips url malware vpn qos log web cli
ENABLE_IPS = 1
ENABLE_URLFILTER = 1
ENABLE_ANTIVIRUS = 1
ENABLE_VPN = 1

# 모듈별 CFLAGS
ifeq ($(ENABLE_IPS),1)
    CFLAGS += -DENABLE_IPS
    MODULES += ips
endif

ifeq ($(ENABLE_VPN),1)
    CFLAGS += -DENABLE_VPN
    MODULES += vpn
endif

# 의존성
LIBS = -lm -lpthread -lrt -ldl
ifeq ($(ENABLE_OPENSSL),1)
    LIBS += -lssl -lcrypto
endif

# 빌드 타겟
.PHONY: all clean install uninstall distcheck config profile

all: config $(BUILD_DIR) $(BIN_DIR) $(LIB_DIR) nsfw

config:
	@echo "Configuring NGFW $(VERSION) for $(ARCH)..."
	@mkdir -p $(BUILD_DIR)
	@mkdir -p $(BIN_DIR)
	@mkdir -p $(LIB_DIR)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)
	$(foreach dir,$(SRC_SUBDIRS),mkdir -p $(BUILD_DIR)/$(dir);)

# 패턴 규칙
$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.S
	$(CC) $(CFLAGS) -c $< -o $@

# 메인 타겟
ngfw: $(OBJS)
	$(CC) $(LDFLAGS) $^ $(LIBS) -o $@
	@echo "Build complete: $@"

# 설치
install: nsfw
	install -d $(DESTDIR)$(bindir)
	install -d $(DESTDIR)$(libdir)
	install -d $(DESTDIR)$(sysconfdir)
	install -m 755 nsfw $(DESTDIR)$(bindir)/
	install -m 644 lib/*.a $(DESTDIR)$(libdir)/
	install -m 644 etc/*.conf $(DESTDIR)$(sysconfdir)/

uninstall:
	rm -f $(DESTDIR)$(bindir)/ngfw
	rm -rf $(DESTDIR)$(libdir)/libngfw*
	rm -rf $(DESTDIR)$(sysconfdir)

# 클린
clean:
	rm -rf $(BUILD_DIR) $(BIN_DIR) $(LIB_DIR)
	rm -f nsfw *.o *~ core core.*

distclean: clean
	rm -rf config.status config.log config.h

# 도움말
help:
	@echo "NGFW Build System"
	@echo "=================="
	@echo "Targets:"
	@echo "  all         - Build everything"
	@echo "  clean       - Remove build files"
	@echo "  install     - Install binaries"
	@echo "  uninstall   - Uninstall"
	@echo "  config      - Run configuration"
	@echo ""
	@echo "Options:"
	@echo "  ARCH=$(ARCH)            - Target architecture"
	@echo "  CROSS_COMPILE=prefix    - Cross compile"
	@echo "  ENABLE_IPS=0|1          - Enable/disable IPS"
	@echo "  ENABLE_VPN=0|1          - Enable/disable VPN"
	@echo "  ENABLE_OPENSSL=0|1       - Use OpenSSL"
	@echo ""
	@echo "Examples:"
	@echo "  make                        # Native build"
	@echo "  make ARCH=arm64            # ARM64 build"
	@echo "  make CROSS_COMPILE=aarch64-linux-gnu- ARCH=arm64"
```

#### 19.1.3 GNU Autotools (autoconf/automake) 빌드

Autotools 기반의 표준 Unix 빌드 시스템:

**디렉토리 구조:**
```
ngfw/
├── configure.ac          # autoconf 설정
├── Makefile.am           # automake 설정
├── configure             # 생성된 설정 스크립트
├── Makefile.in          # 생성된 Makefile 템플릿
├── src/
│   ├── Makefile.am
│   ├── core/
│   │   ├── Makefile.am
│   │   └── ...
│   ├── network/
│   │   ├── Makefile.am
│   │   └── ...
│   └── ...
├── include/
│   └── Makefile.am
├── lib/
│   └── Makefile.am
├── tests/
│   └── Makefile.am
└── scripts/
    └── Makefile.am
```

**configure.ac 예시:**
```m4
#                                               -*- Autoconf -*-
# Process this file with autoconf to produce configure script.

AC_PREREQ([2.71])
AC_INIT([ngfw], [1.0.0], [ngfw@example.com])
AC_CONFIG_SRCDIR([src/core/main.c])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_AUX_DIR([build-aux])
AM_INIT_AUTOMAKE([-Wall foreign subdir-objects])
AC_PROG_CC
AM_PROG_AR
LT_INIT([dlopen win32-dll static disable-shared])
AC_PROG_INSTALL
AC_CONFIG_FILES([Makefile src/Makefile lib/Makefile tests/Makefile])

# Checks for libraries.
AC_CHECK_LIB([pthread], [pthread_create])
AC_CHECK_LIB([m], [cos])
AC_CHECK_FUNCS([strdup strerror memset])

# Check for OpenSSL (optional)
AC_ARG_WITH([openssl],
    [AS_HELP_STRING([--without-openssl],
        [Build without OpenSSL, use internal crypto])],
    [],
    [with_openssl=yes])
AM_CONDITIONAL([USE_OPENSSL], [test "x$with_openssl" != xno])

# Check for features
AC_ARG_ENABLE([ips],
    [AS_HELP_STRING([--disable-ips],
        [Disable Intrusion Prevention System])],
    [enable_ips=$enableval],
    [enable_ips=yes])
AM_CONDITIONAL([ENABLE_IPS], [test "x$enable_ips" != xno])

# Check for architecture-specific features
AC_CANONICAL_HOST
AC_MSG_CHECKING([for host system type])
AC_MSG_RESULT([$host_os-$host_cpu])
AM_CONDITIONAL([ARCH_X86_64], [test "$host_cpu" = x86_64])
AM_CONDITIONAL([ARCH_ARM64], [test "$host_cpu" = aarch64])

# Check for compiler flags
AC_C_BIGENDIAN

AC_OUTPUT
```

**Makefile.am 예시:**
```makefile
# Top level Makefile.am

SUBDIRS = src lib include tests
dist_doc_DATA = README.md AUTHORS NEWS ChangeLog

# Global CFLAGS
AM_CFLAGS = -Wall -Wextra -std=c99 -fPIC

if USE_OPENSSL
    AM_CFLAGS += -DUSE_OPENSSL
    LIBS += -lssl -lcrypto
endif

if ENABLE_IPS
    AM_CFLAGS += -DENABLE_IPS
endif

# Binary
bin_PROGRAMS = nsfw
nsfw_SOURCES = src/core/main.c src/core/init.c
nsfw_CFLAGS = $(AM_CFLAGS)
nsfw_LDADD = lib/libngfw_core.la lib/libngfw_network.la
```

**src/Makefile.am 예시:**
```makefile
# src/Makefile.am

SUBDIRS = core network security crypto web cli

# Build order
lib_LTLIBRARIES =
noinst_LTLIBRARIES =

if ENABLE_IPS
    SUBDIRS += security/ips
endif

if ENABLE_VPN
    SUBDIRS += security/vpn
endif

# Common sources
ngfw_core_sources = core/main.c core/config.c core/log.c
ngfw_network_sources = network/packet.c network/session.c network/nat.c

# Install headers
pkgincludedir = $(includedir)/ngfw
pkginclude_HEADERS = ../include/ngfw.h ../include/ngfw_core.h
```

**Autotools 빌드 명령어:**
```bash
# Autotools 빌드流程
autoreconf -i                          # autoconf 실행
./configure                            # 설정
    --prefix=/usr/local                # 설치 디렉토리
    --enable-ips                       # IPS 활성화
    --disable-openssl                  # 자체 암호화 사용
    --host=aarch64-linux-gnu          # 크로스 컴파일
    --with-crosstool=/opt/ct-ng        # 크로스 툴체인
make                                   # 빌드
make check                             # 테스트
make install DESTDIR=/tmp/ngfw-pkg     # 설치 (패키징용)
make distcheck                         # 배포 패키지 생성
```

#### 19.1.4 CMake 빌드

CMake 기반의 크로스 플랫폼 빌드:

**CMakeLists.txt 예시:**
```cmake
# CMakeLists.txt (최상위)
cmake_minimum_required(VERSION 3.16)
project(ngfw VERSION 1.0.0 LANGUAGES C)

# 옵션
option(ENABLE_IPS "Enable Intrusion Prevention System" ON)
option(ENABLE_VPN "Enable VPN support" ON)
option(ENABLE_OPENSSL "Use OpenSSL for crypto" OFF)
option(ENABLE_TESTS "Build tests" ON)
option(ENABLE_DOCS "Build documentation" ON)

# 버전 정보
set(PROJECT_VERSION_MAJOR 1)
set(PROJECT_VERSION_MINOR 0)
set(PROJECT_VERSION_PATCH 0)
set(PROJECT_VERSION "${PROJECT_VERSION_MAJOR}.${PROJECT_VERSION_MINOR}.${PROJECT_VERSION_PATCH}")

# C 표준
set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# 컴파일러 최적화
set(CMAKE_C_FLAGS_INIT "-Wall -Wextra -fPIC")
set(CMAKE_C_FLAGS_DEBUG_INIT "-g -O0")
set(CMAKE_C_FLAGS_RELEASE_INIT "-O3 -DNDEBUG")

# 아키텍처 감지
if(CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    set(TARGET_ARCH "x86_64")
    set(HAVE_X86_64 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "aarch64|arm64")
    set(TARGET_ARCH "arm64")
    set(HAVE_ARM64 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "arm")
    set(TARGET_ARCH "arm")
    set(HAVE_ARM 1)
elseif(CMAKE_SYSTEM_PROCESSOR MATCHES "riscv64")
    set(TARGET_ARCH "riscv64")
    set(HAVE_RISCV64 1)
endif()

# 출력 디렉토리
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)
set(CMAKE_ARCHIVE_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/lib)

# 찾아보기 디렉토리
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/include/${TARGET_ARCH}
    ${PROJECT_BINARY_DIR}/include
)

# 서브 디렉토리
add_subdirectory(src)
add_subdirectory(lib)
add_subdirectory(include)
if(ENABLE_TESTS)
    enable_testing()
    add_subdirectory(tests)
endif()
if(ENABLE_DOCS)
    add_subdirectory(docs)
endif()

# 설치
install(TARGETS nsfw
    RUNTIME DESTINATION bin
    LIBRARY DESTINATION lib
    ARCHIVE DESTINATION lib)
install(DIRECTORY etc/
    DESTINATION etc/ngfw
    FILES_MATCHING PATTERN "*.conf")
install(DIRECTORY var/
    DESTINATION var/ngfw
    FILES_MATCHING PATTERN "*")
```

**src/CMakeLists.txt 예시:**
```cmake
# src/CMakeLists.txt

# 서브디렉토리
add_subdirectory(core)
add_subdirectory(network)
add_subdirectory(security)
add_subdirectory(crypto)
add_subdirectory(web)
add_subdirectory(cli)

# 메인 실행 파일
add_executable(ngfw
    core/main.c
)

target_link_libraries(ngfw
    PRIVATE
        ngfw_core
        ngfw_network
        ngfw_security
        ngfw_crypto
        ngfw_web
        ngfw_cli
)

# 컴파일 옵션
if(ENABLE_IPS)
    target_compile_definitions(ngfw PRIVATE ENABLE_IPS)
    target_link_libraries(ngfw PRIVATE ngfw_ips)
endif()

if(ENABLE_VPN)
    target_compile_definitions(ngfw PRIVATE ENABLE_VPN)
    target_link_libraries(ngfw PRIVATE ngfw_vpn)
endif()

# 시스템 기능 감지
include(CheckFunctionExists)
check_function_exists(strdup HAVE_STRDUP)
check_function_exists(daemon HAVE_DAEMON)
```

**CMake 빌드 명령어:**
```bash
# CMake 빌드流程
mkdir build && cd build           # 빌드 디렉토리 생성
cmake ..                          # 설정
    -DCMAKE_BUILD_TYPE=Release    # 빌드 타입
    -DENABLE_IPS=ON              # IPS 활성화
    -DENABLE_VPN=ON              # VPN 활성화
    -DCMAKE_INSTALL_PREFIX=/usr/local
    -DCMAKE_TOOLCHAIN_FILE=../cmake/arm64-linux-gnu.cmake  # 크로스 컴파일

cmake --build .                   # 빌드
cmake --build . --target test     # 테스트
cmake --install .                 # 설치
cmake --install . --prefix /tmp/ngfw-pkg  # 패키징용 설치
```

#### 19.1.5 크로스 컴파일 (Cross Compilation)

다양한 아키텍처를 위한 크로스 컴파일 지원:

**크로스 컴파일 도구체인:**
| 아키텍처 | 도구체인 | Trin/저 |
|----------|----------|---------|
| ARM64 (aarch64) | aarch64-linux-gnu-* | GCC, Clang |
| ARM32 (armhf) | arm-linux-gnueabihf-* | GCC |
| RISC-V 64-bit | riscv64-linux-gnu-* | GCC, Clang |
| x86 | i686-linux-gnu-* | GCC |
| x86-64 (32-bit) | i386-linux-gnu-* | GCC |
| PowerPC64 | powerpc64le-linux-gnu-* | GCC |
| s390x | s390x-linux-gnu-* | GCC |

**크로스 컴파일 도구체인 파일 (cmake/aarch64-linux-gnu.cmake):**
```cmake
# CMake toolchain file for ARM64 (aarch64) cross compilation

set(CMAKE_SYSTEM_NAME Linux)
set(CMAKE_SYSTEM_PROCESSOR aarch64)

# 도구체인 경로
set(TOOLCHAIN_ROOT /opt/aarch64-linux-gnu)

set(CMAKE_C_COMPILER ${TOOLCHAIN_ROOT}/bin/aarch64-linux-gnu-gcc)
set(CMAKE_CXX_COMPILER ${TOOLCHAIN_ROOT}/bin/aarch64-linux-gnu-g++)
set(CMAKE_AR ${TOOLCHAIN_ROOT}/bin/aarch64-linux-gnu-ar)
set(CMAKE_RANLIB ${TOOLCHAIN_ROOT}/bin/aarch64-linux-gnu-ranlib)
set(CMAKE_STRIP ${TOOLCHAIN_ROOT}/bin/aarch64-linux-gnu-strip)

# sysroot
set(CMAKE_SYSROOT /opt/aarch64-linux-gnu/aarch64-linux-gnu)

# 플래그
set(CMAKE_C_FLAGS_INIT "-march=armv8-a -fPIC")
set(CMAKE_C_FLAGS_DEBUG_INIT "-g")
set(CMAKE_C_FLAGS_RELEASE_INIT "-O3")

# 찾기 모드
set(CMAKE_FIND_ROOT_PATH_MODE_PROGRAM NEVER)
set(CMAKE_FIND_ROOT_PATH_MODE_LIBRARY ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_INCLUDE ONLY)
set(CMAKE_FIND_ROOT_PATH_MODE_PACKAGE ONLY)
```

**GNU Make 크로스 컴파일:**
```bash
# ARM64 크로스 컴파일
make ARCH=arm64 \
    CROSS_COMPILE=aarch64-linux-gnu- \
    CC=aarch64-linux-gnu-gcc \
    AR=aarch64-linux-gnu-ar \
    STRIP=aarch64-linux-gnu-strip

# RISC-V 크로스 컴파일
make ARCH=riscv64 \
    CROSS_COMPILE=riscv64-linux-gnu- \
    CC=riscv64-linux-gnu-gcc \
    CFLAGS="-march=rv64gc -mabi=lp64d"

# ARM32 (ARMv7) 크로스 컴파일
make ARCH=arm \
    CROSS_COMPILE=arm-linux-gnueabihf- \
    CC=arm-linux-gnueabihf-gcc \
    CFLAGS="-march=armv7-a -mfpu=neon-vfpv4 -mfloat-abi=hard"
```

**Autotools 크로스 컴파일:**
```bash
# Autotools 크로스 컴파일
./configure --host=aarch64-linux-gnu \
    --build=x86_64-linux-gnu \
    CC=aarch64-linux-gnu-gcc \
    AR=aarch64-linux-gnu-ar \
    RANLIB=aarch64-linux-gnu-ranlib \
    --with-sysroot=/opt/aarch64-linux-gnu/sysroot

make
```

#### 19.1.6 모듈식 빌드

**모듈 활성화/비활성화:**

```makefile
# 모듈식 빌드 Makefile 예시

# 모듈 목록
MODULES = core network security/crypto security/ips security/urlfilter \
          security/antivirus network/nat network/qos web cli

# 기본 활성화
ENABLE_CORE = 1
ENABLE_NETWORK = 1
ENABLE_CRYPTO = 1
ENABLE_IPS = 1
ENABLE_URLFILTER = 1
ENABLE_ANTIVIRUS = 0
ENABLE_VPN = 0
ENABLE_QOS = 1
ENABLE_WEB = 1
ENABLE_CLI = 1

# 모듈별 빌드
define MODULE_template
$(1)_SRCS = $(SRC_DIR)/$(1).c
$(1)_OBJS = $$(patsubst %.c,$(BUILD_DIR)/%.o,$$($(1)_SRCS))

$(BUILD_DIR)/$(1).o: $(SRC_DIR)/$(1).c | $(BUILD_DIR)
	$$(CC) $$(CFLAGS) -c $$< -o $$@

.PHONY: $(1)
$(1): $$($(1)_OBJS)
endef

$(foreach module,$(MODULES),$(eval $(call MODULE_template,$(module))))
```

**CMake 모듈 빌드:**
```cmake
# CMake 모듈식 빌드

# 모듈 옵션
option(ENABLE_CORE "Build core module" ON)
option(ENABLE_NETWORK "Build network module" ON)
option(ENABLE_IPS "Build IPS module" ON)
option(ENABLE_VPN "Build VPN module" OFF)
option(ENABLE_URLFILTER "Build URL filter module" ON)
option(ENABLE_ANTIVIRUS "Build antivirus module" OFF)

# 조건부 서브디렉토리
if(ENABLE_CORE)
    add_subdirectory(src/core)
endif()

if(ENABLE_NETWORK)
    add_subdirectory(src/network)
endif()

if(ENABLE_IPS)
    add_subdirectory(src/security/ips)
endif()

# 메인 실행 파일에 조건부 링크
if(ENABLE_IPS)
    target_link_libraries(ngfw PRIVATE ngfw_ips)
endif()
```

#### 19.1.7 빌드 변수 및 옵션

| 변수 | 설명 | 기본값 |
|------|------|--------|
| ARCH | 대상 아키텍처 | $(shell uname -m) |
| CROSS_COMPILE | 크로스 컴파일러 접두사 | (empty) |
| CC | C 컴파일러 | gcc |
| CFLAGS | C 컴파일러 플래그 | -Wall -O2 |
| LDFLAGS | 링크더 플래그 | (empty) |
| LIBS | 추가 라이브러리 | -lm -lpthread |
| prefix | 설치 디렉토리 | /usr/local |
| ENABLE_IPS | IPS 모듈 활성화 | 1 |
| ENABLE_VPN | VPN 모듈 활성화 | 1 |
| ENABLE_OPENSSL | OpenSSL 사용 | 0 |

#### 19.1.8 빌드 타겟

| 타겟 | 설명 |
|------|------|
| all | 기본 빌드 |
| clean | 빌드 파일 삭제 |
| distclean | 모든 생성 파일 삭제 |
| install | 설치 |
| uninstall | 설치 삭제 |
| check | 테스트 빌드 및 실행 |
| test | 단위 테스트 실행 |
| benchmark | 성능 벤치마크 실행 |
| doc | 문서 생성 |
| dist | 배포.tar.gz 생성 |
| distcheck | 배포 및 테스트 |

### 19.2 의존성 관리

#### 19.2.1 최소 의존성

| 의존성 | 최소 버전 | 용도 |
|--------|----------|------|
| Linux Kernel | 6.0+ | 시스템 콜, 네트워크 |
| GLibC | 2.31+ | 표준 라이브러리 |
| OpenSSL (선택) | 3.0+ | TLS 1.3 (자체 구현 우선) |

### 19.3 설치 및 배포

#### 19.3.1 설치 디렉토리 구조

```
/opt/ngfw/
├── bin/              # 실행 파일
├── lib/              # 라이브러리
├── etc/              # 설정 파일
│   ├── policy/       # 정책 파일
│   ├── certs/        # 인증서
│   └── ips/          # IPS 시그니처
├── var/
│   ├── log/          # 로그 파일
│   ├── session/      # 세션 데이터
│   └── cache/        # 캐시 데이터
├── doc/              # 문서
└── scripts/          # 유틸리티 스크립트
```

### 19.4 빌드 결과물 (Build Outputs)

#### 19.4.1 빌드 결과물 개요

NGFW 빌드 시스템은 다양한 형태의 배포 이미지를 생성해야 한다:

| 결과물 | 형식 | 용도 | 생성 타겟 |
|--------|------|------|----------|
| 실행 바이너리 | ELF ( statically linked) | 직접 실행 | `make binary` |
| Root Filesystem | tar.gz, ext4, squashfs | 임베디드/베어메탈 | `make rootfs` |
| 설치 ISO | ISO 9660 | 부팅 및 설치 | `make iso` |
| RAW 디스크 이미지 | raw, img | 베어메탈 배포 | `make disk-image` |
| VM 이미지 | QCOW2, VMDK, VHDX | 가상화 배포 | `make vm-image` |
| 컨테이너 이미지 | Docker/OCI | 컨테이너 런타임 | `make container` |
| DEB/RPM 패키지 | .deb, .rpm | 리눅스 배포판 | `make package` |
| SDK | tar.gz | 개발자용 | `make sdk` |

#### 19.4.2 실행 바이너리 (Standalone Binary)

** Standalone ELF 바이너리 생성:**

```makefile
# Standalone 바이너리 빌드 타겟
.PHONY: binary
binary: $(OBJS)
	$(CC) $(LDFLAGS) -static -nostdlib \
		-e _start -Wl,--gc-sections \
		$^ $(STATIC_LIBS) -o $(BIN_DIR)/ngfw

# 정적 링크 확인
$(BIN_DIR)/ngfw: file $< | grep -q "statically linked"
```

**특징:**
- 정적 링크 (static linking)
- 심볼 제거 (strip)
- UPX 압축 (선택)
- 단일 파일 배포 가능

#### 19.4.3 Root Filesystem (Rootfs)

** Rootfs 구조:**

```
ngfw-rootfs/
├── bin/
│   ├── nsfw                    # 메인 실행 파일
│   ├── init                    # init 시스템
│   ├── sh                      # 쉘
│   └── utilities/              # 유틸리티
├── sbin/
│   ├── ngfw-ctl               # 제어 프로그램
│   └── ngfw-setup             # 설정 프로그램
├── etc/
│   ├── ngfw/
│   │   ├── ngfw.conf          # 메인 설정
│   │   ├── policy/            # 정책 파일
│   │   ├── ips/               # IPS 시그니처
│   │   ├── certs/             # 인증서
│   │   └── modules/           # 모듈 설정
│   ├── init.d/                # 부트 스크립트
│   ├── rc.d/                  # 런레벨 스크립트
│   ├── network/               # 네트워크 설정
│   ├── sysctl.d/             # 커널 파라미터
│   └── modprobe.d/            # 커널 모듈
├── lib/
│   ├── modules/               # 커널 모듈
│   └── firmware/              # 펌웨어
├── usr/
│   ├── lib/                  # 추가 라이브러리
│   ├── share/
│   │   ├── ngfw/             # 데이터 파일
│   │   ├── man/              # 매뉴얼
│   │   └── doc/              # 문서
│   └── local/                # 사용자 공간
├── var/
│   ├── ngfw/
│   │   ├── log/              # 로그
│   │   ├── session/          # 세션 데이터
│   │   ├── cache/            # 캐시
│   │   └── data/             # 동적 데이터
│   ├── run/                  # 런타임 파일
│   └── tmp/                  # 임시 파일
├── proc/                     # proc 파일시스템 (마운트)
├── sys/                      # sys 파일시스템 (마운트)
├── dev/                      # 디바이스 파일
├── tmp/                      # 임시 디렉토리
├── root/                     # 루트 디렉토리
└── home/                     # 홈 디렉토리
```

** Rootfs 생성 타겟:**

```makefile
# Rootfs 빌드 타겟
.PHONY: rootfs
rootfs: binary
	@echo "Building rootfs..."
	rm -rf $(BUILD_DIR)/rootfs
	mkdir -p $(BUILD_DIR)/rootfs
	# 기본 디렉토리 생성
	$(MAKE) -C scripts/initramfs tree DIR=$(BUILD_DIR)/rootfs
	# 바이너리 복사
	install -m 755 $(BIN_DIR)/ngfw $(BUILD_DIR)/rootfs/bin/
	# 라이브러리 복사
	$(MAKE) -C scripts/rootfs install-libs DIR=$(BUILD_DIR)/rootfs
	# 설정 파일 복사
	cp -r $(SRC_DIR)/etc/* $(BUILD_DIR)/rootfs/etc/
	# 스크립트 복사
	install -m 755 $(SRC_DIR)/scripts/*.sh $(BUILD_DIR)/rootfs/sbin/

# 다양한 형식으로 압축
rootfs-tarball: rootfs
	tar -czvf $(DIST_DIR)/ngfw-rootfs-$(VERSION).tar.gz \
		-C $(BUILD_DIR)/rootfs .

rootfs-squashfs: rootfs
	mksquashfs $(BUILD_DIR)/rootfs \
		$(DIST_DIR)/ngfw-rootfs-$(VERSION).squashfs \
		-comp xz -no-progress

rootfs-cpio: rootfs
	find $(BUILD_DIR)/rootfs -print | \
		cpio -o -H newc | \
		gzip > $(DIST_DIR)/ngfw-initramfs-$(VERSION).img
```

** Rootfs 빌드 스크립트:**

```bash
#!/bin/bash
# scripts/build-rootfs.sh

set -e

ROOTFS_DIR=${1:-./rootfs}
VERSION=${2:-1.0.0}

echo "Building NGFW Rootfs ${VERSION}..."

# 디렉토리 생성
mkdir -p "${ROOTFS_DIR}"/{bin,sbin,etc,proc,sys,dev,tmp,var,run,root,home,lib,lib64,usr/{bin,sbin,lib,share}}

# 필수 디렉토리 생성
install -d -m 755 "${ROOTFS_DIR}"/var/{log,ngfw/{log,session,cache,data},run,tmp}
install -d -m 750 "${ROOTFS_DIR}"/etc/ngfw

# 정적 바이너리 복사
if [ -f "./bin/ngfw" ]; then
    install -m 755 ./bin/ngfw "${ROOTFS_DIR}/bin/"
fi

# 동적 바이너리 의존성 복사
copy_libs() {
    local binary=$1
    local lib
    ldd "$binary" 2>/dev/null | while read -r line; do
        lib=$(echo "$line" | awk '{print $3}')
        if [ -f "$lib" ]; then
            mkdir -p "${ROOTFS_DIR}/lib/$(basename $(dirname $lib))"
            install -m 755 "$lib" "${ROOTFS_DIR}/lib/$(dirname $lib)/"
        fi
    done
}

# init 스크립트 생성
cat > "${ROOTFS_DIR}/init" << 'EOF'
#!/bin/sh
mount -t proc none /proc
mount -t sysfs none /sys
mount -t devtmpfs none /dev
echo "NGFW Starting..."
exec /bin/ngfw
EOF
chmod +x "${ROOTFS_DIR}/init"

echo "Rootfs created at: ${ROOTFS_DIR}"
```

#### 19.4.4 부팅 설치용 ISO 이미지

** ISO 이미지 생성:**

```makefile
# ISO 이미지 빌드 타겟
.PHONY: iso
iso: rootfs
	@echo "Building ISO image..."
	# ISO 빌드 디렉토리 준비
	rm -rf $(BUILD_DIR)/iso
	mkdir -p $(BUILD_DIR)/iso/{boot,isolinux,ngfw}
	# 부트 로더 설치
	install -m 644 $(SRC_DIR)/boot/isolinux/isolinux.bin \
		$(BUILD_DIR)/iso/boot/
	install -m 644 $(SRC_DIR)/boot/isolinux/vesamenu.c32 \
		$(BUILD_DIR)/iso/boot/
	# 커널 설치
	install -m 644 $(BUILD_DIR)/vmlinuz \
		$(BUILD_DIR)/iso/boot/
	install -m 644 $(BUILD_DIR)/initrd.img \
		$(BUILD_DIR)/iso/boot/
	# Rootfs 복사
	cp $(DIST_DIR)/ngfw-rootfs-$(VERSION).squashfs \
		$(BUILD_DIR)/iso/ngfw/
	# isolinux.cfg 생성
	cat > $(BUILD_DIR)/iso/isolinux/isolinux.cfg << 'EOF'
UI vesamenu.c32
MENU TITLE NGFW Installer
MENU TITLE Next-Generation Firewall

LABEL ngfw
    MENU LABEL Install NGFW
    KERNEL /boot/vmlinuz
    APPEND initrd=/boot/initrd.img squashash=/ngfw/ngfw-rootfs.squashfs quiet

LABEL ngfw-rescue
    MENU LABEL NGFW Rescue Mode
    KERNEL /boot/vmlinuz
    APPEND initrd=/boot/initrd.img rescue quiet

LABEL harddisk
    MENU LABEL Boot from Hard Disk
    LOCALBOOT 0x80
EOF
	# ISO 이미지 생성
	xorriso -as mkisofs \
		-iso-level 3 \
		-o $(DIST_DIR)/ngfw-$(VERSION)-amd64.iso \
		$(BUILD_DIR)/iso \
		-boot-info-table \
		-boot-load-size 4 \
		-eltorito-alt-boot \
		-e boot/efiboot.img \
		-no-emul-boot
```

** isolinux 설정 예시:**

```
# isolinux/isolinux.cfg
UI vesamenu.c32
MENU BACKGROUND splash.png
MENU TITLE NGFW (Next-Generation Firewall) Installer

TIMEOUT 300
ONTIMEOUT ngfw
PROMPT 0

MENU BEGIN NGFW Installer
MENU TITLE NGFW Installation

LABEL main
    MENU LABEL ^Install NGFW
    KERNEL /boot/vmlinuz
    APPEND initrd=/boot/initrd.img inst.stage2=hd:LABEL=NGFW quiet

LABEL auto
    MENU LABEL ^Automated Install
    KERNEL /boot/vmlinuz
    APPEND initrd=/boot/initrd.img inst.ks=hd:LABEL=NGFW:/ks.cfg quiet

LABEL rescue
    MENU LABEL ^Rescue Mode
    KERNEL /boot/vmlinuz
    APPEND initrd=/boot/initrd.img inst.rescue quiet

LABEL memtest
    MENU LABEL ^Memory Test
    KERNEL /boot/memtest
EOF
```

** EFI 부팅 지원:**

```makefile
# EFI 파티션 포함 ISO
iso-efi: rootfs
	# EFI 부트 이미지 생성
	mmd -i $(BUILD_DIR)/efiboot.img efi
	mmd -i $(BUILD_DIR)/efiboot.img efi/boot
	mcopy -i $(BUILD_DIR)/efiboot.img \
		$(SRC_DIR)/boot/efi/shellx64.efi ::efi/boot/
	# ISO에 EFI 부트 포함
	xorriso -as mkisofs \
		-iso-level 3 \
		-append_partition 2 0xef $(BUILD_DIR)/efiboot.img \
		-eltorito-alt-boot \
		-e boot/efiboot.img \
		-no-emul-boot \
		-o $(DIST_DIR)/ngfw-$(VERSION)-amd64-efi.iso \
		$(BUILD_DIR)/iso
```

#### 19.4.5 RAW 디스크 이미지

** RAW 디스크 이미지 생성:**

```makefile
# RAW 디스크 이미지 빌드 타겟
.PHONY: disk-image
disk-image: rootfs
	@echo "Building RAW disk image..."
	# 디스크 크기 설정 (단위: MB)
	DISK_SIZE=2048
	IMG_FILE=$(DIST_DIR)/ngfw-$(VERSION)-amd64.img
	
	# 디스크 이미지 생성
	dd if=/dev/zero of=$(IMG_FILE) bs=1M count=$(DISK_SIZE) status=progress
	
	# 파티션 설정
	parted -s $(IMG_FILE) mklabel msdos
	parted -s $(IMG_FILE) mkpart primary ext4 1MiB 100%
	parted -s $(IMG_FILE) set 1 boot on
	
	# 루프백 디바이스 설정
	LOOP_DEV=$(shell losetup -f --show -P $(IMG_FILE))
	
	# 파일시스템 생성
	mkfs.ext4 -F -L NGFW /dev/$(LOOP_DEV)p1
	
	# 마운트 및 파일 복사
	mkdir -p $(BUILD_DIR)/mnt
	mount /dev/$(LOOP_DEV)p1 $(BUILD_DIR)/mnt
	cp -a $(BUILD_DIR)/rootfs/* $(BUILD_DIR)/mnt/
	
	# 마운트 해제
	umount $(BUILD_DIR)/mnt
	losetup -d $(LOOP_DEV)
	rmdir $(BUILD_DIR)/mnt
	
	# 압축 (선택)
	pigz -k $(IMG_FILE)
```

** 디스크 이미지 파티션 레이아웃:**

| 파티션 | 크기 | 유형 | 용도 |
|--------|------|------|------|
| /dev/sda1 | 100MB | ext4/boot | 부트 파티션 |
| /dev/sda2 | Remaining | ext4 | 루트 파일시스템 |
| /dev/sda3 | 512MB-1GB | swap | 스왑 (선택) |

** 디스크 이미지 생성 스크립트:**

```bash
#!/bin/bash
# scripts/build-disk-image.sh

set -e

IMAGE_FILE=${1:-ngfw.img}
DISK_SIZE=${2:-2048}  # MB
BOOT_SIZE=${3:-256}   # MB

echo "Creating NGFW disk image: ${IMAGE_FILE}"
echo "Disk size: ${DISK_SIZE}MB"

# 빈 이미지 생성
dd if=/dev/zero of=${IMAGE_FILE} bs=1M count=${DISK_SIZE} status=progress

# 파티션 테이블 생성
cat << EOF | fdisk ${IMAGE_FILE}
o
n
p
1
${BOOT_SIZE}
n
p
2


t
1
83
w
EOF

# 루프백 마운트
LOOP=$(losetup -f --show -P ${IMAGE_FILE})

# 파일시스템 생성
mkfs.ext4 -F -L BOOT /dev/${LOOP}p1
mkfs.ext4 -F -L NGFW /dev/${LOOP}p2

# 부트 파티션 마운트
mkdir -p mnt/boot
mount /dev/${LOOP}p1 mnt/boot

# 커널//initrd 복사 (준비된 경우)
if [ -f vmlinuz ]; then
    cp vmlinuz mnt/boot/
fi
if [ -f initrd.img ]; then
    cp initrd.img mnt/boot/
fi

# 부트 로더 설치
install -m 644 boot/*.bin mnt/boot/ 2>/dev/null || true

umount mnt/boot
rmdir mnt/boot

# 루트 파티션 마운트
mkdir -p mnt/root
mount /dev/${LOOP}p2 mnt/root

# Rootfs 복사
if [ -d rootfs ]; then
    cp -a rootfs/* mnt/root/
fi

umount mnt/root
rmdir mnt/root

# 루프백 해제
losetup -d ${LOOP}

# 압축
gzip -k ${IMAGE_FILE}

echo "Done: ${IMAGE_FILE}.gz"
```

#### 19.4.6 가상 머신 이미지

** QCOW2 이미지 생성:**

```makefile
# QCOW2 이미지 빌드 타겟
.PHONY: vm-image-qcow2
vm-image-qcow2: rootfs
	@echo "Building QCOW2 VM image..."
	
	# RAW 이미지 먼저 생성
	$(MAKE) disk-image RAW_FILE=$(BUILD_DIR)/ngfw.raw
	
	# QCOW2로 변환
	qemu-img convert -f raw -O qcow2 \
		$(BUILD_DIR)/ngfw.raw \
		$(DIST_DIR)/ngfw-$(VERSION)-amd64.qcow2
	
	# QCOW2 옵션 설정
	qemu-img rebase -b "" $(DIST_DIR)/ngfw-$(VERSION)-amd64.qcow2
	qemu-img snapshot -c base $(DIST_DIR)/ngfw-$(VERSION)-amd64.qcow2
```

** VMDK 이미지 생성:**

```makefile
# VMDK 이미지 빌드 타겟
.PHONY: vm-image-vmdk
vm-image-vmdk: rootfs
	@echo "Building VMDK VM image..."
	
	qemu-img convert -f raw -O vmdk \
		$(BUILD_DIR)/ngfw.raw \
		$(DIST_DIR)/ngfw-$(VERSION)-amd64.vmdk
	
	# VMDK 옵션 (VMware 호환)
	qemu-img convert -f raw -O vmdk \
		-o subformat=monolithicSparse \
		$(BUILD_DIR)/ngfw.raw \
		$(DIST_DIR)/ngfw-$(VERSION)-amd64.vmdk
```

** VHDX 이미지 생성:**

```makefile
# VHDX 이미지 빌드 타겟
.PHONY: vm-image-vhdx
vm-image-vhdx: rootfs
	@echo "Building VHDX VM image..."
	
	qemu-img convert -f raw -O vhdx \
		$(BUILD_DIR)/ngfw.raw \
		$(DIST_DIR)/ngfw-$(VERSION)-amd64.vhdx
```

** VM 이미지 메타데이터:**

```yaml
# vm-images/metadata.yaml
vm_images:
  - name: ngfw-1.0.0-amd64.qcow2
    format: qcow2
    size: 2048
    os: linux
    os_version: "6.x"
    arch: x86_64
    virtio: true
    requirements:
      min_ram: 4096
      min_cpu: 4
      min_disk: 8
  
  - name: ngfw-1.0.0-amd64.vmdk
    format: vmdk
    size: 2048
    os: linux
    os_version: "6.x"
    arch: x86_64
    vmware_tools: required
    requirements:
      min_ram: 4096
      min_cpu: 4
      min_disk: 8
```

#### 19.4.7 컨테이너 이미지 (Docker/OCI)

** Dockerfile 생성:**

```dockerfile
# Dockerfile
FROM scratch AS base

# 메타데이터
LABEL maintainer="ngfw@example.com"
LABEL version="1.0.0"
LABEL description="Next-Generation Firewall"

# Rootfs 복사
ADD rootfs.tar.gz /

# 포트 노출
EXPOSE 22 80 443 4433 5000/udp 4500/udp

# 환경 변수
ENV NGFW_HOME=/opt/ngfw \
    NGFW_CONFIG=/etc/ngfw \
    NGFW_LOG=/var/log/ngfw

# 볼륨
VOLUME ["/etc/ngfw", "/var/log/ngfw", "/var/ngfw"]

# Entrypoint
ENTRYPOINT ["/bin/ngfw"]
CMD ["--help"]
```

** 컨테이너 이미지 빌드:**

```makefile
# Docker 이미지 빌드 타겟
.PHONY: container
container: rootfs
	@echo "Building Docker container image..."
	
	# Rootfs tarball 생성
	tar -C $(BUILD_DIR)/rootfs -cvf - . | \
		docker import - ngfw:latest
	
	# 레이어 추가
	docker build -t ngfw:$(VERSION) -t ngfw:latest .
	
	# 태그
	docker tag ngfw:latest ngfw:$(VERSION)-amd64
	
	# 저장소推送 (설정된 경우)
	if [ -n "$(REGISTRY)" ]; then \
		docker push $(REGISTRY)/ngfw:$(VERSION); \
	fi
```

#### 19.4.8 패키지 (DEB/RPM)

** DEB 패키지 생성:**

```makefile
# DEB 패키지 빌드 타겟
.PHONY: package-deb
package-deb: binary
	@echo "Building DEB package..."
	
	# DEB 빌드 디렉토리
	rm -rf $(BUILD_DIR)/deb
	mkdir -p $(BUILD_DIR)/deb/DEBIAN
	mkdir -p $(BUILD_DIR)/deb/etc/ngfw
	mkdir -p $(BUILD_DIR)/deb/usr/bin
	mkdir -p $(BUILD_DIR)/deb/usr/lib/ngfw
	mkdir -p $(BUILD_DIR)/deb/usr/share/doc/ngfw
	
	# 파일 복사
	install -m 755 $(BIN_DIR)/ngfw $(BUILD_DIR)/deb/usr/bin/
	install -m 644 $(SRC_DIR)/etc/*.conf $(BUILD_DIR)/deb/etc/ngfw/
	
	# control 파일 생성
	cat > $(BUILD_DIR)/deb/DEBIAN/control << 'EOF'
Package: ngfw
Version: 1.0.0
Section: net
Priority: optional
Architecture: amd64
Depends: libc6 (>= 2.31)
Maintainer: NGFW Team <ngfw@example.com>
Description: Next-Generation Firewall
 A comprehensive network security solution providing firewall,
 intrusion prevention, VPN, and content filtering capabilities.
EOF
	
	# copyright 파일
	cat > $(BUILD_DIR)/deb/DEBIAN/copyright << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
License: GPL-2.0+
EOF
	
	# postinst 스크립트
	cat > $(BUILD_DIR)/deb/DEBIAN/postinst << 'EOF'
#!/bin/sh
case "$1" in
    configure)
        systemctl daemon-reload || true
        ;;
esac
exit 0
EOF
	chmod +x $(BUILD_DIR)/deb/DEBIAN/postinst
	
	# DEB 패키징
	dpkg-deb --build $(BUILD_DIR)/deb $(DIST_DIR)/ngfw_$(VERSION)_amd64.deb
```

** RPM 패키지 생성:**

```makefile
# RPM 패키지 빌드 타겟
.PHONY: package-rpm
package-rpm: binary
	@echo "Building RPM package..."
	
	# SPEC 파일 생성
	cat > $(BUILD_DIR)/ngfw.spec << 'EOF'
Name:           ngfw
Version:        1.0.0
Release:        1%{?dist}
Summary:        Next-Generation Firewall
License:        GPL-2.0+
URL:            https://ngfw.example.com
BuildArch:      x86_64

Requires:       glibc >= 2.31
Requires:       systemd

%description
NGFW is a comprehensive network security solution providing firewall,
intrusion prevention, VPN, and content filtering capabilities.

%prep
%build

%install
install -Dm755 %{_builddir}/ngfw %{buildroot}%{_bindir}/ngfw
install -Dm644 %{_src}/ngfw.conf %{buildroot}%{_sysconfdir}/ngfw/ngfw.conf

%files
%{_bindir}/ngfw
%config(noreplace) %{_sysconfdir}/ngfw/

%post
systemctl daemon-reload || true

%changelog
* $(date '+%a %b %d %Y') NGFW Team <ngfw@example.com> - 1.0.0-1
- Initial release
EOF
	
	# RPM 빌드
	rpmbuild -bb $(BUILD_DIR)/ngfw.spec \
		--define "_topdir $(BUILD_DIR)/rpm" \
		--define "_rpmdir $(DIST_DIR)"
```

#### 19.4.9 SDK 생성

** SDK 패키지 생성:**

```makefile
# SDK 빌드 타겟
.PHONY: sdk
sdk: binary
	@echo "Building SDK..."
	
	rm -rf $(BUILD_DIR)/sdk
	mkdir -p $(BUILD_DIR)/sdk/{sysroots,scripts,toolchain}
	
	# 타겟 sysroot 복사
	cp -a $(SYSROOT) $(BUILD_DIR)/sdk/sysroots/ngfw-target
	
	# 컴파일러 및 도구 체인
	install -m 755 $(TOOLCHAIN)/bin/* $(BUILD_DIR)/sdk/toolchain/
	
	# 빌드 스크립트
	install -m 755 $(SRC_DIR)/scripts/*.sh $(BUILD_DIR)/sdk/scripts/
	
	# 헤더 파일
	install -m 644 $(INCLUDE_DIR)/*.h $(BUILD_DIR)/sdk/include/
	
	# 라이브러리
	install -m 644 $(LIB_DIR)/*.a $(BUILD_DIR)/sdk/lib/
	
	# SDK tarball 생성
	tar -czvf $(DIST_DIR)/ngfw-sdk-$(VERSION)-amd64.tar.gz \
		-C $(BUILD_DIR)/sdk .
```

#### 19.4.10 전체 빌드 타겟

```makefile
# 모든 결과물 빌드 타겟
.PHONY: all-outputs
all-outputs: binary rootfs iso disk-image vm-image-qcow2 vm-image-vmdk vm-image-vhdx container

# 정리 타겟
.PHONY: clean-outputs
clean-outputs:
	rm -rf $(BUILD_DIR)/{rootfs,iso,efiboot.img,mnt}
	rm -f $(DIST_DIR)/ngfw-*.{img,qcow2,vmdk,vhdx,iso,tar.gz,deb,rpm,docker}

# 배포 타겟
.PHONY: dist
dist: all-outputs
	# 체크섬 생성
	cd $(DIST_DIR) && \
		md5sum ngfw-*.img ngfw-*.iso ngfw-*.qcow2 ngfw-*.tar.gz > MD5SUMS && \
		sha256sum ngfw-*.img ngfw-*.iso ngfw-*.qcow2 ngfw-*.tar.gz > SHA256SUMS
```

#### 19.4.11 SDK/Library/Application/Kernel 모듈 역할 분리

##### 19.4.11.1 모듈식 아키텍처 개요

NGFW는 다음과 같이 명확하게 분리된 계층 구조를 가져야 한다:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        NGFW Component Architecture                       │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                    Application Layer (응용 계층)                     │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐   │    │
│  │  │  nsfw CLI     │  │  Web UI Server │  │  REST API Server │   │    │
│  │  └────────────────┘  └────────────────┘  └──────────────────┘   │    │
│  │  - 사용자 인터페이스 제공                                           │    │
│  │  - 명령어 해석 및 실행                                            │    │
│  │  - 설정 관리                                                      │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                   Library Layer (라이브러리 계층)                    │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐   │    │
│  │  │  libngfw-core │  │ libngfw-sec    │  │  libngfw-net    │   │    │
│  │  │  - Core API   │  │ - IPS Engine  │  │  - Packet I/O  │   │    │
│  │  │  - Config    │  │ - VPN Engine  │  │  - Session     │   │    │
│  │  │  - Logging   │  │ - SSL Proxy  │  │  - NAT         │   │    │
│  │  └────────────────┘  └────────────────┘  └──────────────────┘   │    │
│  │  - 재사용 가능한 비즈니스 로직                                       │    │
│  │  - 모듈 간 통신桥梁                                              │    │
│  │  - 공개 API 제공                                                 │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                    │                                     │
│                                    ▼                                     │
│  ┌─────────────────────────────────────────────────────────────────┐    │
│  │                   Kernel/Module Layer (커널/모듈 계층)               │    │
│  │  ┌────────────────┐  ┌────────────────┐  ┌──────────────────┐   │    │
│  │  │  netfilter    │  │  eBPF/XDP     │  │  Kernel Module  │   │    │
│  │  │  (iptables)   │  │  (kernel)     │  │  (kernel .ko)  │   │    │
│  │  └────────────────┘  └────────────────┘  └──────────────────┘   │    │
│  │  - 커널 레벨 패킷 처리                                            │    │
│  │  - 하드웨어 상호작용                                               │    │
│  │  - 높은 성능 요구 기능                                             │    │
│  └─────────────────────────────────────────────────────────────────┘    │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

##### 19.4.11.2 각 계층의 역할 및 책임

**Application Layer (응용 계층):**

| 구성요소 | 역할 | 책임 |
|---------|------|------|
| nsfw CLI | 명령줄 인터페이스 | 사용자 명령 해석, 실행, 결과 출력 |
| Web UI Server | 웹 기반 관리 | 웹 인터페이스 제공, 세션 관리 |
| REST API Server | API 서비스 | JSON/XML API 제공, 인증, 레이트 리밋 |
| Daemon | 백그라운드 서비스 | 정책 스케줄링, 로그 수집, 모니터링 |

**Library Layer (라이브러리 계층):**

| 라이브러리 | 역할 | 책임 |
|-----------|------|------|
| libngfw-core | 핵심 기능 | 초기화, 설정 관리, 로깅, 공통 유틸리티 |
| libngfw-sec | 보안 엔진 | IPS, URL 필터, 안티맬웨어, SSL 검사 |
| libngfw-net | 네트워크 | 패킷 처리, 세션 관리, NAT, QoS |
| libngfw-crypto | 암호화 | 대칭/비대칭 암호화, 해시, RNG |
| libngfw-vpn | VPN | IPsec, SSL VPN, 키 관리 |
| libngfw-cli | CLI 프레임워크 | 명령 파서, 자동완성, 히스토리 |
| libngfw-http | HTTP 서버 | 웹/클라이언트, 세션, 인증 |

**Kernel/Module Layer (커널/모듈 계층):**

| 모듈 | 역할 | 책임 |
|------|------|------|
| nftables/iptables | 패킷 필터링 | 커널 레벨 필터링 규칙 적용 |
| eBPF/XDP | 고속 패킷 처리 |Early Drop, 로드 밸런싱 |
| 커널 모듈 (.ko) | 커널 확장 | 커널과의 통합, 시스템 콜 후크 |
| netfilter 후크 | 패킷 개입 | PRE_ROUTING, LOCAL_IN, FORWARD, LOCAL_OUT, POST_ROUTING |

##### 19.4.11.3 심볼 충돌 방지를 위한 고유 Namespace

**Namespace 명명 규칙:**

| 접두사 | 사용처 | 예시 |
|--------|--------|------|
| `ngfw_` | 공개 API (Application용) | `ngfw_init()`, `ngfw_start()` |
| `__ngfw_` | 내부 함수 | `__ngfw_session_alloc()` |
| `_ngfw_` | 라이브러리 내부 | `_ngfw_hash_create()` |
| `nf_` | Netfilter 후크 | `nf_nfhook()` |
| `xdp_` | XDP 프로그램 | `xdp_packet_process()` |
| `ebpf_` | eBPF 맵/프로그램 | `ebpf_session_map` |

** 심볼 버전 관리 (Symbol Versioning):**

```c
/* libngfw-core Symbols (버전 관리) */
NGFW_VERSION_1.0 {
    global:
        ngfw_init;
        ngfw_fini;
        ngfw_config_load;
        ngfw_config_save;
        ngfw_log_write;
    local:
        *;
};

/* libngfw-net Symbols */
NGFW_VERSION_1.0_NET {
    global:
        ngfw_net_session_create;
        ngfw_net_session_destroy;
        ngfw_net_packet_process;
        ngfw_net_nat_apply;
    local:
        *;
};
```

**커널 모듈 심볼 내보내기:**

```c
/* 커널 모듈 심볼 내보내기 (GPL 라이선스) */
#include <linux/module.h>
#include <linux/export.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("NGFW Team");
MODULE_DESCRIPTION("NGFW Kernel Module");

/* 공개 심볼 (다른 모듈에서 사용 가능) */
EXPORT_SYMBOL_GPL(ngfw_register_hook);
EXPORT_SYMBOL_GPL(ngfw_unregister_hook);
EXPORT_SYMBOL_GPL(ngfw_session_lookup);

/* 비공개 심볼 (내부 사용만) */
static int __ngfw_packet_handler(struct sk_buff *skb);
static void __ngfw_state_sync(struct nf_conn *ct);

/* XDP 심볼 */
EXPORT_SYMBOL_GPL(ngfw_xdp_register_prog);
EXPORT_SYMBOL_GPL(ngfw_xdp_unregister_prog);
```

##### 19.4.11.4 빌드 시스템에서 모듈 분리

**모듈별 Makefile:**

```makefile
# ====================
# Library Makefile
# ====================

# 라이브러리 빌드
lib/%.o: src/%.c
	$(CC) $(CFLAGS) -fPIC -c $< -o $@

# 정적 라이브러리
$(LIB_DIR)/libngfw-core.a: $(CORE_OBJS)
	$(AR) rcs $@ $^

# 공유 라이브러리 (Symbol Versioning)
$(LIB_DIR)/libngfw-core.so.$(VERSION): $(CORE_OBJS)
	$(CC) -shared -Wl,-soname,libngfw-core.so.1 \
		-Wl,--version-script=libngfw-core.map $^ -o $@

# ====================
# Kernel Module Makefile
# ====================

# 커널 모듈 빌드 (별도 디렉토리)
KMOD_DIR = kernel
obj-m += nsfw_core.o
nsfw_core-objs := main.o hook.o session.o

# 커널 빌드
modules:
	$(MAKE) -C $(KERNELDIR) M=$(PWD) modules

# ====================
# Application Makefile
# ====================

# 애플리케이션 빌드 (정적 링크 권장)
$(BIN_DIR)/nsfw: $(APP_OBJS) $(LIB_DIR)/libngfw-core.a
	$(CC) $(LDFLAGS) -static -nostdlib $^ -o $@
```

**CMake에서의 모듈 분리:**

```cmake
# ====================
# CMakeLists.txt (Library)
# ====================

# 라이브러리 targets
add_library(ngfw_core STATIC
    src/core/init.c
    src/core/config.c
    src/core/log.c
)

add_library(ngfw_net SHARED
    src/net/packet.c
    src/net/session.c
    src/net/nat.c
)
set_target_properties(ngfw_net PROPERTIES
    VERSION ${PROJECT_VERSION}
    SOVERSION 1
    OUTPUT_NAME "ngfw-net"
    OUTPUT_NAME_DEBUG "ngfw-net-dbg"
)

# Symbol Visibility
set_target_properties(ngfw_core PROPERTIES
    C_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
)

# ====================
# CMakeLists.txt (Kernel Module)
# ====================

# 커널 모듈 (별도 CMakeLists.txt 권장)
add_custom_target(kmodule ALL
    COMMAND make -C $(KERNEL_DIR) M=${CMAKE_CURRENT_SOURCE_DIR}
    DEPENDS ${CMAKE_SOURCE_DIR}/kernel/*.c
)

# ====================
# CMakeLists.txt (Application)
# ====================

add_executable(ngfw
    src/app/main.c
    src/app/cli.c
)

target_link_libraries(ngfw
    PRIVATE
        ngfw_core
        ngfw_net
        ngfw_sec
        ngfw_crypto
)

# 정적 링크 (권장)
set_target_properties(ngfw PROPERTIES
    LINK_SEARCH_START_STATIC ON
    STATIC_LINK_FLAGS "-static"
)
```

##### 19.4.11.5 Symbol Export Control

**내보내기 매크로 정의:**

```c
/* 공개 API 매크로 */
#define NGFW_API __attribute__((visibility("default")))
#define NGFW_PRIVATE __attribute__((visibility("hidden")))

/* 함수 선언 */
NGFW_API int ngfw_init(int argc, char *argv[]);
NGFW_API int ngfw_config_load(const char *path);
NGFW_PRIVATE int __ngfw_config_parse(const char *file);

/* 커널 모듈용 */
#ifdef __KERNEL__
#define NGFW_KMODULE EXPORT_SYMBOL_GPL
#else
#define NGFW_KMODULE
#endif
```

**LD Scripts (링커 스크립트):**

```ld
/* libngfw-core.ld - 심볼 내보내기 제어 */
{
    global:
        ngfw_init;
        ngfw_fini;
        ngfw_config_*;
        ngfw_log_*;
    local:
        *;
};

/* libngfw-net.ld */
{
    global:
        ngfw_net_session_*;
        ngfw_net_packet_*;
        ngfw_net_nat_*;
    local:
        *;
};
```

##### 19.4.11.6ABI 호환성 관리

**버전 관리 전략:**

| 버전 유형 | 의미 | 변경 사항 |
|----------|------|----------|
| Major (x.0.0) | 주요 변경 | ABI 호환성 깨짐 |
| Minor (1.x.0) | 기능 추가 | ABI 호환성 유지 |
| Patch (1.0.x) | 버그 수정 | ABI 호환성 유지 |

**ABI 호환성 체크:**

```bash
#!/bin/bash
# scripts/check-abi.sh

OLD_SO=libngfw-core.so.1.0.0
NEW_SO=libngfw-core.so.1.1.0

# 심볼 비교
nm -D ${OLD_SO} | cut -d' ' -f3 | sort > old_symbols.txt
nm -D ${NEW_SO} | cut -d' ' -f3 | sort > new_symbols.txt

# 제거된 심볼
REMOVED=$(comm -23 old_symbols.txt new_symbols.txt)
if [ -n "$REMOVED" ]; then
    echo "ERROR: Removed symbols: $REMOVED"
    exit 1
fi

# 추가된 심볼 (경고)
ADDED=$(comm -13 old_symbols.txt new_symbols.txt)
if [ -n "$ADDED" ]; then
    echo "WARNING: Added symbols: $ADDED"
fi

echo "ABI check passed"
```

##### 19.4.11.7 라이브러리 의존성 그래프

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     NGFW Library Dependency Graph                     │
├─────────────────────────────────────────────────────────────────────────┤
│                                                                          │
│  ┌──────────────────────────────────────────────────────────────────┐   │
│  │                     Application (ngfw)                            │   │
│  └──────────────────────────┬───────────────────────────────────────┘   │
│                               │                                             │
│          ┌───────────────────┼───────────────────┐                      │
│          ▼                   ▼                   ▼                      │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                │
│  │ libngfw-core │  │ libngfw-cli  │  │  libngfw-http│                │
│  │ (필수)        │  │               │  │               │                │
│  └───────┬───────┘  └───────┬───────┘  └───────┬───────┘                │
│          │                   │                   │                      │
│          ▼                   ▼                   ▼                      │
│  ┌───────────────┐  ┌───────────────┐  ┌───────────────┐                │
│  │ libngfw-net  │  │ libngfw-crypto│  │  libngfw-util│                │
│  │               │  │  (필수)       │  │               │                │
│  └───────┬───────┘  └───────┬───────┘  └───────────────┘                │
│          │                   │                                             │
│          └─────────────┬─────┘                                            │
│                        ▼                                                  │
│          ┌───────────────────────────────────────┐                       │
│          │       Kernel Layer (선택적)             │                       │
│          │  - netfilter hooks (via libnetfilter)  │                       │
│          │  - eBPF maps (via libbpf)             │                       │
│          │  - Kernel module (.ko)                 │                       │
│          └───────────────────────────────────────┘                       │
│                                                                          │
└─────────────────────────────────────────────────────────────────────────┘
```

##### 19.4.11.8 모듈식 배포 단위

| 배포 형태 | 포함 요소 | 용도 |
|-----------|----------|------|
| Base | libngfw-core + libngfw-util | 최소 배포 |
| Network | + libngfw-net | 방화벽 기능만 |
| Security | + libngfw-sec | IPS/VPN 포함 |
| Full | 전체 라이브러리 | 전체 기능 |
| SDK | 헤더 + 정적 라이브러리 | 개발용 |

##### 19.4.11.9 인터페이스 분리 원칙

**Application ↔ Library 인터페이스:**

```c
/* public/api/ngfw.h - 공개 API */
#include <ngfw/types.h>

/* 버전 호환성 */
#if NGFW_API_VERSION >= 100
/* 새 API */
#endif

/* 핵심 함수 */
NGFW_API int ngfw_init(const ngfw_config_t *config);
NGFW_API void ngfw_fini(void);
NGFW_API int ngfw_start(void);
NGFW_API int ngfw_stop(void);

/* 설정 */
NGFW_API int ngfw_config_load(const char *path);
NGFW_API int ngfw_config_save(const char *path);
NGFW_API const char* ngfw_get_version(void);
```

**Library ↔ Kernel 인터페이스:**

```c
/* internal/kernel_iface.h - 커널 인터페이스 */

/* Netfilter 후크 등록 */
struct nf_hook_ops *ngfw_netfilter_register(
    enum nf_inet_hooks hooknum,
    int (*handler)(void *priv, struct sk_buff *skb,
                   const struct nf_hook_state *state)
);

/* 세션 테이블 접근 (공유 메모리 via map) */
int ngfw_session_get(uint32_t session_id, ngfw_session_t *session);
int ngfw_session_set(uint32_t session_id, const ngfw_session_t *session);

/* XDP 프로그램 등록 */
int ngfw_xdp_attach(int ifindex, struct bpf_prog *prog);
int ngfw_xdp_detach(int ifindex);
```

### 19.5 가상화 환경 지원

#### 19.4.1 가상화 플랫폼 지원 개요

NGFW는 다양한 가상화 플랫폼에서 동작할 수 있어야 한다:

| 플랫폼 | 지원 유형 | 요구사항 |
|--------|----------|----------|
| KVM/QEMU | 가상 어플라이언스 | 필수 |
| VMware ESXi | 가상 어플라이언스 | 권장 |
| Microsoft Hyper-V | 가상 어플라이언스 | 권장 |
| Xen | 가상 어플라이언스 | 권장 |
| Proxmox VE | 가상 어플라이언스 | 권장 |

#### 19.4.2 KVM/QEMU 가상화

##### 19.4.2.1 KVM 지원

KVM (Kernel-based Virtual Machine) 기반 배포:

**요구사항:**
| 항목 | 최소 | 권장 |
|------|------|------|
| vCPU | 4 cores | 8+ cores |
| Memory | 8 GB | 16+ GB |
| Disk | 100 GB | 256+ GB SSD |
| Network | VirtIO | VirtIO + vhost-net |

**VirtIO 드라이버:**
| 드라이버 | 설명 | 요구사항 |
|----------|------|----------|
| virtio-net | 가상 네트워크 카드 | 필수 |
| virtio-blk | 가상 디스크 | 필수 |
| virtio-scsi | SCSI 컨트롤러 | 권장 |
| virtio-fs | 공유 파일시스템 | 선택 |
| vhost-user | vhost 사용자 공간 | 권장 |
| vhost-net | vhost 커널 네트워킹 | 권장 |

```xml
<!-- KVM VM 정의 예시 -->
<domain type='kvm'>
  <name>ngfw-vm</name>
  <memory unit='GiB'>16</memory>
  <vcpu placement='static'>8</vcpu>
  <os>
    <type arch='x86_64' machine='pc-q35-8.0'>hvm</type>
    <boot dev='hd'/>
  </os>
  <cpu mode='host-passthrough'/>
  <devices>
    <interface type='network'>
      <source network='default'/>
      <model type='virtio'/>
    </interface>
    <interface type='network'>
      <source network='wan'/>
      <model type='virtio'/>
    </interface>
    <disk type='file' device='disk'>
      <driver name='qemu' type='qcow2'/>
      <source file='/var/lib/libvirt/images/ngfw.qcow2'/>
      <target dev='vda' bus='virtio'/>
    </disk>
    <console type='pty'/>
  </devices>
</domain>
```

##### 19.4.2.2 vhost-user 아키텍처

vhost-user를 통한 고성능 가상화:

```
┌─────────────────────────────────────────────────────────────────┐
│                        KVM + vhost-user                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│   ┌───────────────────────┐      ┌────────────────────────┐  │
│   │     QEMU Process      │      │    NGFW Application     │  │
│   │  ┌─────────────────┐  │      │  ┌────────────────────┐  │  │
│   │  │  VirtIO Frontend│  │ ←──→ │  │  VirtIO Backend   │  │  │
│   │  │   (emulated)    │  │socket│  │   (vhost-user)    │  │  │
│   │  └─────────────────┘  │      │  └────────────────────┘  │  │
│   │                       │      │                          │  │
│   │  ┌─────────────────┐  │      │  ┌────────────────────┐  │  │
│   │  │   VFIO/Eventfd │  │ ←──→ │  │   OVS/vSwitch     │  │  │
│   │  │   (I/O MMU)    │  │      │  │   or NGFW App     │  │  │
│   │  └─────────────────┘  │      │  └────────────────────┘  │  │
│   └───────────────────────┘      └────────────────────────┘  │
│            │                                    │              │
│            ▼                                    ▼              │
│   ┌───────────────────────┐      ┌────────────────────────┐  │
│   │    VFIO Passthrough   │      │   Physical NIC/VPPs    │  │
│   │      (with IOMMU)      │      │                        │  │
│   └───────────────────────┘      └────────────────────────┘  │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

**vhost-user 요구사항:**
| 기능 | 설명 | 요구사항 |
|------|------|----------|
| vhost-net | 커널 vhost-net | 권장 |
| vhost-user-net | 사용자 공간 vhost | 권장 |
| vhost-scsi | vhost SCSI | 선택 |
| vhost-vsock | vhost VSOCK | 선택 |

##### 19.4.2.3 VirtIO 네트워크 최적화

**성능 최적화 옵션:**
```xml
<!-- VirtIO 네트워크 최적화 -->
<interface type='network'>
  <source network='default'/>
  <model type='virtio'/>
  <driver name='vhost' queues='4'>
    <host csum='off'/>
    <guest csum='off'/>
    <tso4='off'/>
    <tso6='off'/>
    <ufo='off'/>
    <mrg_rxbuf='off'/>
  </driver>
</interface>

<!-- multiqueue 설정 -->
<driver name='vhost' queues='8'/>
```

**성능 비교:**
| 설정 |吞吐력 | 지연시간 |
|------|--------|----------|
| 기본 VirtIO | ~5 Gbps | ~100μs |
| vhost-user | ~10 Gbps | ~50μs |
| vhost-user + VPP | ~20 Gbps | ~20μs |
| VFIO Passthrough | ~100 Gbps | ~5μs |

#### 19.4.3 VMware ESXi 지원

##### 19.4.3.1 VMware 가상 하드웨어

**지원 가상 하드웨어 버전:**
| 버전 | 설명 | 요구사항 |
|------|------|----------|
| Virtual Hardware 14 | ESXi 7.0 | 권장 |
| Virtual Hardware 15 | ESXi 8.0 | 권장 |
| Virtual Hardware 17 | ESXi 8.0 Update 2+ | 권장 |

**VMware 가상 장치:**
| 장치 | 지원 | 비고 |
|------|------|------|
| vmxnet3 | 필수 | VMXNET3 어댑터 |
| PVSCSI | 권장 | Paravirtual SCSI |
| vCPU | 필수 | 4+ vCPU |
| Memory | 필수 | 8+ GB |
| NVMe | 권장 | NVMe 컨트롤러 |

##### 19.4.3.2 VMware Tools

| 도구 | 설명 | 요구사항 |
|------|------|----------|
| open-vm-tools | 오픈소스 VMware Tools | 필수 |
| VMware Paravirtual Drivers | 반가상화 드라이버 | 권장 |

##### 19.4.3.3 VMware 네트워크 드라이버

**vmxnet3 기능:**
| 기능 | 지원 |
|------|------|
| RSS | Yes |
| TSO | Yes |
| GRO | Yes |
| IPv6 | Yes |
| Multiqueue | Yes |
| NetQueue | Yes |

```xml
<!-- VMware VMX 예시 -->
ethernet0.virtualDev = "vmxnet3"
ethernet0.features = "15"
ethernet0.rxDescriptors = "4096"
ethernet0.txDescriptors = "4096"
ethernet0.MTU = "9000"
ethernet0.numRxQueues = "4"
ethernet0.numTxQueues = "4"
```

##### 19.4.3.4 VMware vSphere 지원

**vSphere 기능:**
| 기능 | 지원 |
|------|------|
| vMotion | 권장 |
| DRS (Distributed Resource Scheduler) | 권장 |
| HA (High Availability) | 권장 |
| FT (Fault Tolerance) | 선택 |
| vShield/NSX Integration | 권장 |

#### 19.4.4 Microsoft Hyper-V 지원

##### 19.4.4.1 Hyper-V 가상 하드웨어

**지원 버전:**
| 버전 | 설명 |
|------|------|
| Hyper-V (Windows Server 2019) | 권장 |
| Hyper-V (Windows Server 2022) | 권장 |
| Azure VM | 권장 |

**가상 프로세서/메모리:**
| 항목 | 최소 | 권장 |
|------|------|------|
| vCPU | 4 | 8+ |
| Memory | 8 GB | 16+ GB |

##### 19.4.4.2 Hyper-V 네트워크

**네트워크 어댑터:**
| 어댑터 | 설명 | 요구사항 |
|----------|------|----------|
| Synthetic | 기본 가상 어댑터 | 필수 |
| Legacy Network Adapter | 레거시 에뮬레이션 | 선택 |
| Hyper-V Default Switch | 기본 스위치 | 권장 |
| vSwitch (External) | 외부 vSwitch | 권장 |

**Hyper-V 관련 기능:**
| 기능 | 지원 |
|------|------|
| Virtual Switch | Yes |
| VLAN Trunking | Yes |
| QoS (Weighted) | Yes |
| SR-IOV | Yes |
| vRSS (Receive Side Scaling) | Yes |
| VFIO (Hyper-V) | Synthetic FID |

##### 19.4.4.3 Hyper-V 통합 서비스

| 서비스 | 설명 |
|--------|------|
| Hyper-V Guest Services | 게스트 서비스 |
| Time Synchronization | 시간 동기화 |
| Heartbeat | 하트비트 |
| Backup (Volume Shadow Copy) | 백업 |

#### 19.4.5 Xen 가상화 지원

##### 19.4.5.1 Xen 아키텍처

**Xen 지원:**
| 유형 | 설명 | 요구사항 |
|------|------|----------|
| PV (Paravirtualization) | 반가상화 | 권장 |
| HVM (Hardware Virtualization) | 하드웨어 가상화 | 권장 |
| PVH (PV in HVM) | 하이브리드 모드 | 권장 |

##### 19.4.5.2 Xen 네트워크

**네트워크 옵션:**
| 드라이버 | 설명 |
|----------|------|
| netfront/netback | Xen PV 네트워크 |
| xenbus | Xen 버스 드라이버 |
| PV Driver | 반가상화 드라이버 |

##### 19.4.5.3 Xen PCI Passthrough

| 기능 | 지원 |
|------|------|
| PCI Passthrough | Yes |
| GPU Passthrough | Yes |
| SR-IOV | Yes |
| IOMMU/VT-d | Yes |

#### 19.4.6 컨테이너 환경 지원

##### 19.4.6.1 Docker 지원

**Docker 배포:**
```dockerfile
# NGFW Dockerfile 예시
FROM ubuntu:22.04 AS builder

# 빌드 의존성 설치
RUN apt-get update && apt-get install -y \
    build-essential \
    git \
    && rm -rf /var/lib/apt/lists/*

# 소스 코드 복사 및 빌드
COPY . /src
WORKDIR /src
RUN make -j$(nproc)

# 실행 이미지
FROM ubuntu:22.04
RUN apt-get update && apt-get install -y \
    libssl3 \
    libstdc++6 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/bin/ngfw /usr/local/bin/
COPY --from=builder /src/etc/ /etc/ngfw/

EXPOSE 443 22 514
ENTRYPOINT ["/usr/local/bin/ngfw"]
```

**Docker 네트워크:**
| 네트워크 드라이버 | 지원 |
|-----------------|------|
| bridge | Yes |
| host | Yes |
| overlay | Yes |
| macvlan | Yes |
| ipvlan | Yes |

##### 19.4.6.2 Kubernetes 지원

**K8s 배포:**
```yaml
# NGFW DaemonSet 예시
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ngfw-daemon
  labels:
    app: ngfw
spec:
  selector:
    matchLabels:
      app: ngfw
  template:
    metadata:
      labels:
        app: ngfw
    spec:
      hostNetwork: true
      containers:
      - name: ngfw
        image: ngfw:latest
        securityContext:
          privileged: true
        env:
        - name: NGFW_MODE
          value: "container"
        volumeMounts:
        - name: ngfw-config
          mountPath: /etc/ngfw
        - name: xtables-lock
          mountPath: /run/xtables.lock
      volumes:
      - name: ngfw-config
        configMap:
          name: ngfw-config
      - name: xtables-lock
        hostPath:
          path: /run/xtables.lock
```

**Kubernetes 네트워킹:**
| 플러그인 | 지원 |
|----------|------|
| CNI (Generic) | Yes |
| Calico | Yes |
| Flannel | Yes |
| Weave | Yes |
| Cilium | Yes |
| Amazon VPC CNI | Yes |
| Azure CNI | Yes |
| GKE CNI | Yes |

##### 19.4.6.3 컨테이너 네트워크 인터페이스 (CNI)

**CNI 플러그인 지원:**
| 플러그인 | 설명 | 요구사항 |
|----------|------|----------|
| bridge | 기본 브릿지 | 필수 |
| host-local | IPAM | 필수 |
| loopback | 루프백 | 필수 |
| macvlan | MAC 기반 VLAN | 권장 |
| ipvlan | IP 기반 VLAN | 권장 |
| ptp | 포인트 투 포인트 | 권장 |
| bandwidth |带域限制 | 선택 |
| portmap | 포트 매핑 | 선택 |
| tuning | sysctl 튜닝 | 선택 |

##### 19.4.6.4 컨테이너 최적화

**보안 및 성능:**
| 설정 | 권장값 |
|------|--------|
| network=host | 필요한 경우 |
| privileged | 필요한 경우만 |
| cap_add | NET_ADMIN, SYS_ADMIN |
| seccomp | profile: runtime/default |
| selinux | container_runtime_t |

#### 19.4.7 클라우드 플랫폼 배포

##### 19.4.7.1 Amazon Web Services (AWS)

**AWS 인스턴스 유형:**
| 유형 | 설명 | 용도 |
|------|------|------|
| t3 | 버스티블 | 개발/테스트 |
| m5n | 네트워크 최적화 | 프로덕션 |
| c5n | 컴퓨트 최적화 | 고성능 |
| r5n | 메모리 최적화 | 대용량 세션 |

**AWS 네트워킹:**
| 기능 | 지원 |
|------|------|
| VPC | Yes |
| Security Groups | Yes (백업) |
| ENI (Elastic Network Interface) | Yes |
| ENA (Elastic Network Adapter) | Yes |
| EFA (Elastic Fabric Adapter) | 선택 |
| EBS | Yes |
| Instance Store | 선택 |

```json
{
  "ImageId": "ami-xxxxx",
  "InstanceType": "m5n.2xlarge",
  "NetworkInterfaces": [{
    "DeviceIndex": 0,
    "SubnetId": "subnet-xxxxx",
    "SecurityGroupIds": ["sg-xxxxx"],
    "InterfaceType": "efa"
  }],
  "BlockDeviceMappings": [{
    "DeviceName": "/dev/sda1",
    "Ebs": {
      "VolumeSize": 100,
      "VolumeType": "gp3"
    }
  }]
}
```

##### 19.4.7.2 Microsoft Azure

**Azure VM 크기:**
| 크기 | 시리즈 | 용도 |
|------|--------|------|
| Dsv3 | General Purpose | 프로덕션 |
| Dsv4 | General Purpose | 프로덕션 |
| Esv3 | Memory Optimized | 대용량 |
| Fsv2 | Compute Optimized | 고성능 |

**Azure 네트워킹:**
| 기능 | 지원 |
|------|------|
| VNet | Yes |
| NIC | Yes |
| Accelerated Networking | Yes |
| Azure Firewall 통합 | 권장 |
| NSG (Network Security Group) | Yes (백업) |

##### 19.4.7.3 Google Cloud Platform (GCP)

**GCP 머신 유형:**
| 유형 | 시리즈 | 용도 |
|------|--------|------|
| n2 | General Purpose | 프로덕션 |
| n2d | General Purpose | 비용 최적화 |
| c2 | Compute Optimized | 고성능 |
| m2 | Memory Optimized | 대용량 |

**GCP 네트워킹:**
| 기능 | 지원 |
|------|------|
| VPC Network | Yes |
| GVNIC | Yes |
| Traffic Director | Yes |
| Cloud NAT | Yes |
| Firewall Rules | Yes (백업) |

##### 19.4.7.4 Alibaba Cloud

**Alibaba Cloud 인스턴스:**
| 시리즈 | 설명 |
|--------|------|
| ecs.g6 | General Purpose |
| ecs.c6 | Compute Optimized |
| ecs.r6 | Memory Optimized |
| ecs.g5 | 네트워크 최적화 |

#### 19.4.8 가상화 중첩 (Nested Virtualization)

##### 19.4.8.1 중첩 가상화 지원

**중첩 시나리오:**
| 시나리오 | 지원 |
|----------|------|
| KVM on KVM | Yes |
| ESXi on ESXi | Yes |
| Hyper-V on Hyper-V | Yes |
| KVM on ESXi | Yes |

##### 19.4.8.2 중첩 가상화 요구사항

| 설정 | 요구사항 |
|------|----------|
| CPU Pass-through | 필수 |
| vCPU 제한 | 8+ vCPU |
| Memory | 16+ GB |
| VT-x/EPT | 필수 |

```bash
# KVM 중첩 활성화
# /etc/modprobe.d/kvm-intel.conf
options kvm-intel nested=y
options kvm-intel ept=y
options kvm-intel unrestricted_guest=y
```

#### 19.4.9 가상 머신 이미지 (VM Image)

##### 19.4.9.1 이미지 포맷

| 포맷 | 설명 | 용도 |
|------|------|------|
| QCOW2 | QEMU Copy-On-Write | KVM |
| VMDK | VMware Virtual Disk | VMware |
| VHD/VHDX | Hyper-V Virtual Disk | Hyper-V |
| RAW | Raw Disk Image | 모두 |
| OVA | Open Virtual Appliance | 배포 |

##### 19.4.9.2 클라우드 이미지

**기본 클라우드 이미지:**
| 플랫폼 | 이미지 형식 |
|--------|------------|
| AWS | AMI (EBS/S3) |
| Azure | VHD |
| GCP | RAW |
| Alibaba | QCOW2 |

##### 19.4.9.3 이미지 최적화

| 최적화 | 설명 |
|--------|------|
| VirtIO 드라이버 | VirtIO 설치 |
| Cloud-Init | cloud-init 설정 |
| 시리얼 콘솔 | 시리얼 콘솔 활성화 |
| QEMU 게스트 에이전트 | QGA 설치 |
| 최적화 스크립트 | 첫 부팅 최적화 |

```bash
# 이미지 최적화 스크립트 예시
#!/bin/bash
# cloud-init 설정
cat > /etc/cloud/cloud.cfg << EOF
users:
  - name: ngfwadmin
    primary_group: ngfw
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_pwauth: true
    lock_passwd: false
EOF

# VirtIO 드라이버 설치
apt-get install -y qemu-guest-agent linux-image-extra-virtio

# 부팅 최적화
systemctl enable qemu-guest-agent
```

#### 19.4.10 가상화 플랫폼 API

##### 19.4.10.1 프로비저닝 API

**지원 API:**
| 플랫폼 | API | 라이브러리 |
|--------|-----|-----------|
| KVM | libvirt | libvirt, virsh |
| VMware | vSphere API | pyvmomi, govmomi |
| Hyper-V | WMI/PowerShell | Hyper-V PowerShell |
| K8s | Kubernetes API | client-go |

##### 19.4.10.2 자동 스케일링

**클라우드 자동 스케일링:**
| 기능 | 지원 |
|------|------|
| AWS Auto Scaling | Yes |
| Azure VMSS | Yes |
| GCP Managed Instance Group | Yes |
| Alibaba ESS | Yes |

---

### 19.5 Edge 컴퓨팅 지원

#### 19.5.1 Edge 배포 시나리오

| 시나리오 | 설명 | 요구사항 |
|----------|------|----------|
| RAN (Radio Access Network) | 5G RAN 게이트웨이 | 저지연, 고대역폭 |
| MEC (Multi-access Edge) | 모바일 엣지 | 실시간 처리 |
| IoT Gateway | IoT 통합 | 경량화 |
| SD-WAN Branch | 지사 WAN | VPN 통합 |
| Embedded | 임베디드 시스템 | 저전력 |

---

## 20. 테스트 및 검증 요구사항

### 20.1 자체 구현 테스트 프레임워크

NGFW는 외부 테스트 프레임워크(CUnit, Check 등)에 의존하지 않고 자체 구현한 테스트 프레임워크를 사용해야 한다.

#### 20.1.1 테스트 프레임워크 아키텍처

```c
// 테스트 프레임워크 핵심
typedef struct test_framework {
    // 테스트 등록
    void (*register_test)(const char *suite, const char *name, 
                        test_func_t func);
    void (*register_suite)(const char *name, 
                           void (*setup)(void),
                           void (*teardown)(void));
    
    // 테스트 실행
    int (*run_suite)(const char *name);
    int (*run_all)(void);
    
    // 결과
    test_result_t* (*get_results)(void);
    void (*print_summary)(FILE *output);
} test_framework_t;

// 테스트 매크로
#define TEST_ASSERT(condition, message) \
    do { if (!(condition)) { \
        test_assert_fail(__FILE__, __LINE__, message); \
        return TEST_FAILED; \
    }} while(0)

#define TEST_ASSERT_EQUAL(expected, actual) \
    do { if ((expected) != (actual)) { \
        test_assert_fail(__FILE__, __LINE__, \
            sprintf(buf, "Expected %d, got %d", expected, actual)); \
        return TEST_FAILED; \
    }} while(0)

#define TEST_ASSERT_NULL(ptr) \
    TEST_ASSERT((ptr) == NULL, "Expected NULL")

#define TEST_ASSERT_NOT_NULL(ptr) \
    TEST_ASSERT((ptr) != NULL, "Expected non-NULL")

#define TEST_ASSERT_STR_EQUAL(expected, actual) \
    do { if (strcmp(expected, actual) != 0) { \
        test_assert_fail(__FILE__, __LINE__, "String mismatch"); \
        return TEST_FAILED; \
    }} while(0)

#define TEST_ASSERT_MEM_EQUAL(expected, actual, size) \
    do { if (memcmp(expected, actual, size) != 0) { \
        test_assert_fail(__FILE__, __LINE__, "Memory mismatch"); \
        return TEST_FAILED; \
    }} while(0)

// 테스트 스위트 정의
#define TEST_SUITE(suite_name) \
    static void suite_##suite_name##_setup(void) \
    { \
    } \
    static void suite_##suite_name##_teardown(void) \
    { \
    }

#define TEST_CASE(case_name) \
    static int test_##case_name(void)
```

#### 20.1.2 테스트 유형

| 유형 | 설명 | 대상 |
|------|------|------|
| 단위 테스트 | 개별 함수/모듈 테스트 | 모든 라이브러리 함수 |
| 통합 테스트 | 모듈 간 통합 테스트 | 모듈 간 인터페이스 |
| 시스템 테스트 | 전체 시스템 테스트 | 전체 기능 |
| 회귀 테스트 | 기존 기능 유지 확인 | 변경 사항 影响 |
| 성능 테스트 | 성능 지표 측정 | 처리량, 지연 등 |
| 보안 테스트 | 취약점 탐지 | 입력 검증, 버퍼 오버플로우 |
| 부하 테스트 | 고부하 상황 테스트 | 동시 연결, 대역폭 |

### 20.2 단위 테스트

#### 20.2.1 테스트 대상별 테스트 케이스

**암호화 모듈:**
```c
TEST_CASE(test_aes_cbc_encrypt)
{
    uint8_t key[16] = {0};
    uint8_t iv[16] = {0};
    uint8_t plaintext[16] = "Hello World!";
    uint8_t ciphertext[16];
    
    TEST_ASSERT_EQUAL(0, aes_cbc_encrypt(key, 16, iv, plaintext, 16, ciphertext));
    TEST_ASSERT_NOT_NULL(ciphertext);
}

TEST_CASE(test_aes_cbc_decrypt)
{
    // ...
}

TEST_CASE(test_sha256_hash)
{
    const char *input = "test";
    uint8_t hash[32];
    
    TEST_ASSERT_EQUAL(0, sha256_hash(input, 4, hash));
    // 예상 해시 검증
    uint8_t expected[] = {0x9f, 0x86, 0xd8, 0x17, /* ... */};
    TEST_ASSERT_MEM_EQUAL(expected, hash, 32);
}
```

**세션 관리:**
```c
TEST_CASE(test_session_create)
{
    session_entry_t *session = session_create(SESSION_PROTO_TCP, 
        0xC0A80101, 0x08080808, 80, 443);
    
    TEST_ASSERT_NOT_NULL(session);
    TEST_ASSERT_EQUAL(SESSION_STATE_NEW, session->state);
}

TEST_CASE(test_session_lookup)
{
    // ...
}
```

### 20.3 통합 테스트

#### 20.3.1 패킷 처리 테스트

| 테스트 항목 | 테스트 시나리오 | 예상 결과 |
|-----------|----------------|----------|
| TCP 상태 기계 | 3-way handshake | ESTABLISHED |
| TCP 상태 기계 | FIN 수신 | FIN_WAIT → CLOSED |
| NAT 변환 | SNAT | 소스 IP 변환됨 |
| NAT 변환 | DNAT | 대상 IP 변환됨 |
| 정책 매칭 | Allow 규칙 | 패킷 허용 |
| 정책 매칭 | Deny 규칙 | 패킷 거부 |
| IPS 탐지 | 시그니처 매칭 | 위협 탐지 및 차단 |

#### 20.3.2 시나리오 테스트

```c
TEST_CASE(test_packet_flow)
{
    // 시나리오: 외부 → 방화벽 → 내부 서버
    
    // 1. 패킷 수신
    packet_t *pkt = packet_alloc();
    pkt->eth->src = MAC_WAN;
    pkt->eth->dst = MAC_FW;
    pkt->ip->src = IP_WAN_CLIENT;
    pkt->ip->dst = IP_LAN_SERVER;
    pkt->tcp->src_port = 12345;
    pkt->tcp->dst_port = 80;
    pkt->tcp->flags = TCP_SYN;
    
    // 2. 세션 테이블 조회
    session_entry_t *session = session_lookup(pkt);
    TEST_ASSERT_NULL(session); // 새로운 연결
    
    // 3. 정책 검사
    policy_result_t result = policy_check(pkt);
    TEST_ASSERT_EQUAL(POLICY_ALLOW, result.action);
    
    // 4. NAT 적용
    nat_result_t nat = nat_apply(pkt);
    TEST_ASSERT_EQUAL(NAT_SNAT, nat.type);
    TEST_ASSERT_EQUAL(IP_FW_WAN, nat.new_src_ip);
}
```

### 20.4 성능 테스트

#### 20.4.1 성능 벤치마크

| 항목 | 최소 기준 | 목표 기준 | 테스트 도구 |
|------|----------|----------|------------|
| 처리량 (필터링) | 10 Gbps | 20 Gbps | pktgen, Trex |
| 처리량 (IPS) | 5 Gbps | 10 Gbps | Snort test suite |
| 처리량 (SSL 검사) | 3 Gbps | 8 Gbps | OpenSSL s_server |
| 지연시간 (평균) | < 1ms | < 0.5ms | Custom latency test |
| 지연시간 (최대) | < 5ms | < 2ms | Custom latency test |
| 동시 연결 | 1M | 5M | Connection stress |
| CPS | 100K | 500K | httpress/ab |
| 패킷 처리율 | 14.88 Mpps | 30 Mpps | pktgen |

#### 20.4.2 스트레스 테스트

```c
typedef struct stress_test_config {
    uint32_t duration_seconds;
    uint32_t num_threads;
    uint32_t packets_per_thread;
    uint32_t packet_size_min;
    uint32_t packet_size_max;
    uint32_t target_bps;
    uint32_t target_cps;
    uint32_t max_connections;
} stress_test_config_t;
```

### 20.5 보안 테스트

#### 20.5.1 취약점 테스트

| 테스트 항목 | 방법 |
|-----------|------|
| 버퍼 오버플로우 | 큰 입력 데이터 전송 |
| 포맷 문자열 | %s, %n 등 포함 입력 |
| SQL 인젝션 | SQL 메타문자 삽입 |
| XSS | 스크립트 태그 삽입 |
| 경로 순회 | ../ 포함 경로 |
| NULL 포인터 역참조 | NULL 값 전송 |
| 정수 오버플로우 | 최대값 전송 |

#### 20.5.2 펄 테스트 도구

```bash
#!/bin/bash
# security-test.sh

# 버퍼 오버플로우 테스트
for i in {1..1000}; do
    payload=$(python3 -c "print('A'*$i)")
    curl -X POST http://$NGFW/api/v1/log -d "msg=$payload"
done

# 동시성 테스트
for i in {1..100}; do
    curl http://$NGFW/api/v1/stats &
done
wait
```

### 20.6 CI/CD 통합

#### 20.6.1 빌드 파이프라인

```yaml
# .ngfw-ci.yml
stages:
  - build
  - unit_test
  - integration_test
  - performance_test
  - security_test
  - package

build:
  stage: build
  script:
    - make clean
    - make -j$(nproc)

unit_test:
  stage: unit_test
  script:
    - make test
  coverage: '/Coverage: \d+\.\d+%/'

integration_test:
  stage: integration_test
  script:
    - make integration-test

performance_test:
  stage: performance_test
  script:
    - make perf-test
  timeout: 1h
```

---

## 21. 문서화 요구사항

### 21.1 코드 문서화

모든 소스 코드에 다음 문서 포함:

- 파일 헤더 (저자, 목적, 라이선스)
- 함수 헤더 (파라미터, 반환값, 설명)
- 주석 (복잡한 로직 설명)

### 21.2 API 문서

API 문서 형식:

- 함수原型
- 파라미터 설명
- 반환값 설명
- 사용 예시

### 21.3 사용자 문서

- 설치 가이드
- 설정 가이드
- 운영 매뉴얼
-CLI 참조
- troubleshooting 가이드

---

## 22. 확장성 요구사항

### 22.1 모듈식 확장

#### 22.1.1 플러그인 시스템

```c
// 플러그인 인터페이스
typedef struct ngfw_plugin {
    const char *name;
    const char *version;
    int (*init)(void);
    int (*start)(void);
    int (*stop)(void);
    int (*cleanup)(void);
    void *(*get_api)(const char *api_name);
} ngfw_plugin_t;
```

#### 22.1.2 모듈 로딩

동적 모듈 로딩 지원:

```c
// 모듈 관리자
typedef struct module_manager {
    int (*load_module)(const char *path);
    int (*unload_module)(const char *name);
    void* (*get_module_symbol)(const char *module, const char *symbol);
    module_info_t* (*list_modules)(void);
} module_manager_t;
```

### 22.2 기능 확장 포인트

| 확장 포인트 | 설명 |
|------------|------|
| Packet Handler | 새로운 프로토콜 핸들러 추가 |
| Policy Engine | 새로운 정책 유형 추가 |
| Logging Backend | 새로운 로깅 백엔드 추가 |
| Authentication | 새로운 인증 방법 추가 |
| Threat Intelligence | 새로운 위협 인텔리전스 소스 추가 |

---

## 23. 보안 요구사항

### 23.1 안전한 프로그래밍

#### 23.1.1 보안 가이드라인

- 버퍼 오버플로우 방지
- 정수 오버플로우 검사
- Null 포인트 디레퍼런스 방지
- 메모리 누수 방지
- 시드/random 안전

### 23.2 자체 구현 보안 기능

#### 23.2.1 비밀번호 해시

```c
// 비밀번호 해시 인터페이스
typedef struct password_hasher {
    int (*hash)(const char *password, const uint8_t *salt, char *output);
    int (*verify)(const char *password, const char *hash);
    const char *(*get_algorithm)(void);
} password_hasher_t;
```

---

## 부록 A: 프로젝트 디렉토리 구조

```
ngfw/
├── include/
│   ├── core/           # 코어 헤더
│   ├── network/        # 네트워크 관련
│   ├── security/       # 보안 모듈
│   ├── platform/       # 플랫폼 추상화
│   └── common/         # 공통 유틸리티
├── src/
│   ├── core/           # 코어 구현
│   │   ├── main.c
│   │   ├── model/      # MVC Model
│   │   ├── view/       # MVC View
│   │   └── controller/ # MVC Controller
│   ├── network/        # 네트워크 처리
│   ├── security/       # 보안 모듈
│   │   ├── ips/        # IPS
│   │   ├── appctrl/    # 애플리케이션 컨트롤
│   │   ├── urlfilter/  # URL 필터링
│   │   └── antivirus/  # 맬웨어 방지
│   ├── vpn/            # VPN
│   ├── crypto/         # 암호화 (자체 구현)
│   ├── http/           # HTTP 서버/클라이언트
│   ├── json/           # JSON 처리
│   ├── cli/            # CLI
│   ├── web/            # 웹 서버
│   ├── platform/       # 플랫폼 의존 코드
│   │   ├── x86_64/
│   │   ├── arm64/
│   │   └── riscv64/
│   └── common/         # 공통 유틸리티
├── tests/              # 테스트
├── scripts/            # 스크립트
├── docs/               # 문서
├── Makefile
└── README.md
```

---

## 부록 B: 커널 인터페이스 매핑

### B.1 Netfilter Hooks

| Hook | 사용처 |
|------|--------|
| NF_INET_PRE_ROUTING | 수신 패킷 초기 검사 |
| NF_INET_LOCAL_IN | 로컬 수신 패킷 |
| NF_INET_FORWARD |转发 패킷 |
| NF_INET_LOCAL_OUT | 로컬 송신 패킷 |
| NF_INET_POST_ROUTING | 송신 패킷 최종 |

### B.2 iptables/nftables 매핑

```
iptables      → nftables
-----------     ----------
-A            → nft add rule
-I            → nft insert rule
-p tcp        → ip protocol tcp
--dport       → tcp dport
-j ACCEPT     → accept
-j DROP       → drop
-j REJECT     → reject
-j LOG        → counter log
-m state      → ct state
-m limit      → limit
```

---

## 부록 C: 구현 체크리스트

### C.1 필수 구현 항목

| 번호 | 항목 | 우선순위 |
|------|------|---------|
| 1 | 플랫폼 추상화 계층 | 높음 |
| 2 | 세션 테이블 | 높음 |
| 3 | 패킷 필터링 | 높음 |
| 4 | 상태적 검사 | 높음 |
| 5 | NAT/PAT | 높음 |
| 6 | 정책 엔진 | 높음 |
| 7 | 로깅 시스템 | 중간 |
| 8 | 웹 UI | 중간 |
| 9 | CLI | 중간 |
| 10 | REST API | 중간 |
| 11 | IPS | 중간 |
| 12 | URL 필터링 | 중간 |
| 13 | SSL 검사 | 중간 |
| 14 | IPsec VPN | 낮음 |
| 15 | DDoS 완화 | 낮음 |
| 16 | QoS | 낮음 |

---

*문서 끝 - Version 2.0*
