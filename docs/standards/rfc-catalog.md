# 참조 RFC 카탈로그 (rfc-catalog)

설계/구현에서 참조하는 표준 문서 목록. 원문 사본 위치: `references/<number>.txt`
(수집 안내는 `references/README.md`). 분류 순서: 기초 → 보안 → 관측/관리 → 서비스.

## 1. 기초 데이터/전송

| RFC | 제목(요지) | 사용 위치 |
|---|---|---|
| RFC 791 | Internet Protocol (IPv4) | 파서/정책 필드 |
| RFC 768 | User Datagram Protocol | 세션/파서 |
| RFC 793 (→ 9293) | Transmission Control Protocol | TCP 상태머신 |
| RFC 8200 | Internet Protocol v6 | 파서/정책 |
| RFC 4443 | ICMPv6 | 세션 매칭 |
| RFC 6296 | IPv6 Prefix-based NPTv6 | NAT |
| RFC 2474 | DiffServ (DSCP) | QoS |
| RFC 9000 | QUIC v1 | DPI 식별 |

## 2. 보안/VPN

| RFC | 제목(요지) | 사용 위치 |
|---|---|---|
| RFC 4301 | Security Architecture for IP | VPN 정책 정렬 |
| RFC 4303 | ESP | xfrm 연계 |
| RFC 3947 | NAT-T | IKEv2 |
| RFC 7296 | IKEv2 | 자체 구현 |
| RFC 4555 | MOBIKE | IKEv2 M4 |
| RFC 8446 | TLS 1.3 | 자체 스택/검사 |
| RFC 5246 | TLS 1.2 | 검사/스택 |
| RFC 4987 | TCP SYN Flooding 대응 개요 | DoS 설계 참고 |

## 3. 관측/관리

| RFC | 제목(요지) | 사용 위치 |
|---|---|---|
| RFC 5424 | The Syslog Protocol | 로그 싱크 |
| RFC 6587 | syslog 전송(프레이밍) | 로그 싱크 |
| RFC 7011 | IPFIX | 플로우 익스포트 |
| RFC 3954 | NetFlow v9 | 호환 모드 |
| RFC 3411~3418 | SNMP 프레임워크/운용 | 에이전트 |
| RFC 5798 | VRRPv3 | HA |
| RFC 9110 / 9112 | HTTP 의미론 / HTTP/1.1 | REST 서버 |
| RFC 9113 | HTTP/2 | 선택 활성 |
| RFC 2119 | 요구 수준 키워드(BCP 14) | 문서 규약 |

## 4. 인증/서비스

| RFC | 제목(요지) | 사용 위치 |
|---|---|---|
| RFC 2865/2866 | RADIUS / Accounting | 사용자 인증 |
| RFC 2131/3315 | DHCP / DHCPv6 | 서비스 |
| RFC 1035 | DNS | 리졸버/프록시 |
| RFC 4033~4035 | DNSSEC | M5 |
| RFC 4271 | BGP4 | 라우팅 M3 |
| RFC 2328 / 5340 | OSPFv2/v3 | 라우팅 M4 |

## 5. 비RFC 표준/참고

| 문서 | 사용 위치 |
|---|---|
| ISO/IEC 9899:2011 (C11) | 언어 표준(R02) |
| GNU Coding Standards | 유저랜드 스타일(R02) |
| Linux kernel coding style (Documentation/process/coding-style.rst) | 커널 스타일(R12) |
| POSIX.1-2017 (IEEE Std 1003.1-2017) | 플랫폼 API 범위(R05) |
| SemVer 2.0.0 | 버전 규칙(R14) |
| Suricata rule syntax (공개 문서) | 시그니처 호환 대상(`research/signature-formats.md`) |
| OpenAPI 3.1 | REST 명세(`designs/11` §3) |
