# 01. 제품 개요 (Overview)

## 1. 제품 정의

`ngfw`는 Linux 커널(6.12+) 위에서 동작하는 자체 구현 Next Generation Firewall이다.
부트로더와 Linux 커널, libc만을 실행 기반으로 하며, 나머지 전 기능(데이터플레인, 검사 엔진,
관리, VPN, HA)을 C로 자체 구현한다(R01).

배치 형태:

| 형태 | 설명 | 우선순위 |
|---|---|---|
| 어플라이언스 이미지 | GRUB/U-Boot 부팅 → 전용 커널+rootfs(`ngfw-init` PID 1) | M1 이후 |
| 범용 Linux 설치 | 배포판 위 데몬+커널 모듈 설치(`make install`) | M0~M1 |
| VM (QEMU/KVM) | 검증·개발 표적. virtio-net 표준 | M0부터 |
| 컨테이너 | 유저랜드 데몬만 이식 매트릭스 검증용(커널 모듈은 호스트 커널 의존) | M0부터 |

## 2. 목표 / 비목표

**목표**

1. NGFW 풀 기능 구현(R11): 스테이트풀 필터링, NAT, APP-ID, IPS/IDS, URL/콘텐츠 필터, TLS 검사,
   VPN, 사용자 식별, 라우팅/서비스, HA, QoS, 오프로드.
2. 고성능·저리소스: 오프로드 활용(`14-performance-offload.md`), 소형 VM(2 vCPU/1GiB)에서도 기본
   방화벽+APP-ID 동작.
3. 타사 호환: 표준 프로토콜 상호운용 + Suricata/Snort 시그니처 부분 호환.
4. 완전한 자가 검증: 모든 기능이 `ngfw selftest`로 검증 가능(R04).
5. 이식성: glibc/musl/uClibc, x86_64/aarch64(R05).

**비목표(범위 밖)**

- 자체 커널/부트로더 개발(기존 Linux 커널/부트로더 사용).
- 커널 모듈의 6.12 미만 호환(최소 지원 커널 6.12).
- 스케일아웃 컨트롤러형 중앙관리 제품군(단일 장치 관리 + HA까지만 범위; 원격 다중 장치 관리는
  REST API로 외부 연동만 제공).
- 라이선스/과금, 클라우드 마켓플레이스 이미지.

## 3. 기능 카탈로그 (F-카탈로그)

기능 범위의 유일 출처(P-A). 각 항목은 로드맵(`21-roadmap.md`)에 배치되고 selftest 케이스를 갖는다(R11).

| ID | 기능 | 요지 | 상세 문서 |
|---|---|---|---|
| F01 | 스테이트풀 패킷 필터링 | 존 기반/주소/서비스/앱/사용자/시간 매칭, TCP 상태머신, 기본 deny | `04`, `05` |
| F02 | NAT | SNAT/DNAT/PAT, port forwarding, 정적/동적, NPTv6, NAT64(후기) | `05` §7 |
| F03 | APP-ID | 포트 무관 애플리케이션 식별, 계층형 분류, 세션 캐시 재평가 | `06` |
| F04 | IPS/IDS | 시그니처 엔진(Suricata 부분 호환), 프로토콜 분석기, 임계치/이상탐지 | `07` |
| F05 | URL/콘텐츠 필터 | URL 카테고리 DB, SNI 기반 HTTPS 필터, MIME/파일 정책 | `07` §5~6 |
| F06 | TLS 검사 | SNI/암호스위트 식별, 선택적 MITM 복호화(자체 TLS 1.2/1.3) | `07` §7 |
| F07 | VPN | IPsec(IKEv2+xfrm), WireGuard(커널) 연계, SSL VPN, GRE/L2TP | `08` |
| F08 | 사용자 식별 | 로컬/RADIUS/LDAP/AD 인증, 그룹 매핑, 세션-사용자 바인딩 | `10` |
| F09 | 라우팅/서비스 | 정적/BGP/OSPF(단계적), DHCP, DNS, NTP, 브리지/VLAN | `09` |
| F10 | HA | VRRPv3, 세션/설정 동기화, 페일오버 | `13` |
| F11 | QoS | 클래스 기반 대역폭, 우선순위, DSCP 마킹, per-Session 셰이핑 훅 | `09` §7 |
| F12 | 관리 | `ngfw` CLI, REST API, WebUI, 설정 트랜잭션/롤백/커밋-확인 | `11` |
| F13 | 로깅/모니터링 | 구조화 로그, syslog/IPFIX/NetFlow/SNMP 익스포트, 메트릭 | `12` |
| F14 | 오프로드 | NIC/KERNEL/XDP/암호 오프로드 매트릭스 | `14` |
| F15 | selftest/진단 | `ngfw selftest`, `ngfw-doctor`, 부트 자가진단 | `17`, `12` |
| F16 | 플러그인 | 파서/인증/로그싱크/정책 액션 플러그인 ABI | `19` |
| F17 | 멀티존/가상화 | 인터페이스 존, VLAN, 브리지, VRF(단계적) | `09` §5 |
| F18 | DoS/DDoS 방어 | SYN flood, rate limit, XDP 사전 필터(단계적) | `04` §6 |
| F19 | 멀웨어/파일 검사 | 파일 해시/타입 기반 정책, 아카이브 순회(후기) | `07` §8 |
| F20 | 세션 상세 조회/디버그 | `ngfw show session`, 커널 세션 덤프, 플로우 추적 | `12` §7 |

## 4. 모델 티어

소프트웨어는 동일 빌드로 배포되며, 모델은 리소스 한계/활성 기능 집합만 구성으로 구분한다
(`20-naming-versioning.md`). 초기 티어:

| 모델 | 대상 | 기준 리소스 | 비고 |
|---|---|---|---|
| `ngfw-VM` | 가상화/소형 | 2 vCPU, 1 GiB RAM | 기본 FW+APP-ID |
| `ngfw-VM+` | 가상화/중형 | 4 vCPU, 2 GiB RAM | +IPS/TLS 검사 |
| `ngfw-X` | 베어메탈/고성능 | 8+ vCPU, NIC 하드웨어 오프로드 | 전 기능+오프로드 |

모델 한계(동시 세션 수, 신규 세션/s, 검사 처리량)는 측정으로 확정하며 `14` §2의 측정 절차로
검증된 값만 문서화한다(P-G).

## 5. 표준 준수 요약

기능↔표준 전체 매핑은 `docs/standards/standards-map.md`가 유일 출처이다. 요약:

- 데이터 플레인: IPv4(RFC 791), IPv6/ICMPv6(RFC 8200/4443), TCP(RFC 793, 9293 재판), UDP(RFC 768).
- VPN: IPsec(RFC 4301/4302/4303), IKEv2(RFC 7296), NAT-T(RFC 3947), WireGuard(커널 구현 준수).
- 검사 호환: Suricata 규칙 문법 부분 집합(문법 정의는 docs/research/signature-formats.md).
- 관리/가시성: syslog(RFC 5424/6587), NetFlow v5/v9, IPFIX(RFC 7011), SNMP(RFC 3411~), 
  REST API는 OpenAPI 3.1 문서 제공.
- 품질: C11(ISO/IEC 9899:2011), GNU 코딩 스타일, Linux 커널 코딩 스타일, SemVer 2.0.0.

## 6. 용어집

| 용어 | 정의 |
|---|---|
| NGFW | Next Generation Firewall. 전통적 방화벽 + 앱 인식/검사/사용자 기반 정책 |
| APP-ID | 애플리케이션 식별. 포트가 아닌 페이로드/행위 기반 분류 |
| fast/deep path | `designs/README.md` §4 참조 |
| policy artifact | 컴파일된 정책 이진 산출물(커널 적재 대상) |
| xfrm | 커널 IPsec 변환 프레임워크(ESP 데이터 플레인 담당) |
| genetlink | Generic Netlink. 커널 모듈↔유저랜드 제어 채널 |
| fail-open/close | 검사 엔진 장애 시 트래픽 통과/차단 정책 |
| commit confirm | 설정 적용 후 확인 타임아웃 미수신 시 자동 롤백 |
| RCU | Read-Copy-Update 동기화(커널/유저랜드 레코드 교체에 사용) |

## Change log

- 2026-10-23: 초판 작성.
