# 기능↔표준 매핑 총표 (standards-map)

R10(표준 준수)의 유일 출처. 각 기능이 의존하는 표준과 준수 방법/범위를 기록한다.
RFC 전체 목록은 `rfc-catalog.md`, 원문은 `references/`에 있다.

| 기능(ID) | 표준/프로토콜 | 참조 | 준수 방법 | 준수 범위/제약 |
|---|---|---|---|---|
| F01 필터링 | IPv4 | RFC 791 | 커널 스택 활용, ngfw는 필드 파싱만 | 헤더 정규 포맷 |
| F01 | IPv6 | RFC 8200 | 확장 헤더 파싱(`04` §5) | 최소 표준 확장 헤더 |
| F01 | ICMP/ICMPv6 | RFC 792/4443 | 요청-응답 세션 매칭 | 에러 임베드 매칭 |
| F01 | TCP | RFC 9293(793 후속) | 상태머신 추적(`04` §3.1) | strict 모드 옵션 |
| F02 NAT | NPTv6 | RFC 6296 | 무상태 구현 | 전체 |
| F02 | NAT64 | RFC 6146 | stateful 구현(M5) | DNS64는 RFC 6147 병행 |
| F07 VPN | IPsec 아키텍처 | RFC 4301 | 정책 모델 정렬 | SPD/SAD는 xfrm 위임 |
| F07 | ESP | RFC 4303 | 커널 xfrm | - |
| F07 | IKEv2 | RFC 7296 | 자체 구현 | RFC 7383(자식 SA 다중)/7427(신뢰성) 부분 |
| F07 | NAT-T | RFC 3947 | 감지/캡슐 | 전체 |
| F07 | MOBIKE | RFC 4555 | 자체 구현(M4) | 선택 |
| F06/F08 TLS | TLS 1.3 | RFC 8446 | 자체 스택(`07` §7) | 1.2는 RFC 5246 부분 |
| F03 QUIC | QUIC v1 | RFC 9000 | 초기 패킷 메타/키 도출 식별 | 전체 구현 아님 |
| F12 관리 | HTTP/1.1 | RFC 9110/9112 | 자체 서버 | 서버 부분 |
| F12 | HTTP/2 | RFC 9113 | 선택 활성(M4) | 서버 부분 |
| F13 로그 | syslog | RFC 5424 + 6587 | 클라이언트 전송 | - |
| F13 플로우 | IPFIX | RFC 7011 | 익스포터 | 템플릿/기본 IE |
| F13 | NetFlow v9/v5 | RFC 3954/3951 | 호환 모드 | v5는 고정 레이아웃 |
| F13 SNMP | SNMPv2c/v3 | RFC 3411~3418 | 에이전트 최소 | GET/GETNEXT/GETBULK/트랩 |
| F10 HA | VRRPv3 | RFC 5798 | 자체 구현 | v4/v6 |
| F08 인증 | RADIUS | RFC 2865/2866 | 클라이언트 | MS-CHAPv2(RFC 2548) 부분 |
| F08 | DHCP | RFC 2131/3315 | 서버/클라이언트/릴레이 | 옵션 주요 세트 |
| F09 라우팅 | BGP4 | RFC 4271 | 자체 구현(M3) | eBGP 우선 |
| F09 | OSPFv2/v3 | RFC 2328/5340 | 자체 구현(M4) | 단일 에어리어 |
| F09 DNS | DNS | RFC 1035 | 리졸버/포워더 | DNSSEC(M5, RFC 4033~4035) |
| F11 QoS | DiffServ 필드 | RFC 2474 | DSCP 마킹 | - |
| F18 DoS | SYN flood 대응 | RFC 4987 참고 | 쿠키 방식 핸들링 | - |
| F15 selftest | 요구 수준 키워드 | RFC 2119 | 문서 표기 규약 | - |

- 신규 기능 추가 시 이 표에 행을 추가하고, 표준 위반/예외는 행의 "준수 범위/제약"과 해당 설계
  문서에 근거를 기록한다.
- "부분" 표기는 지원 서브셋을 뜻하며, 상호운용 검증 항목은 `research/interop-matrix.md`에서
  관리한다.
