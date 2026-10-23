# 09. 네트워크 서비스 (Routing / DHCP / DNS / NTP / L2 / QoS)

libngfw `services` 서브시스템. 커널 데이터 플레인 활용 + 자체 컨트롤 플레인(R01).

## 1. 인터페이스 관리

- 구성: IP/서브넷/게이트웨이, VLAN(802.1Q), 브리지(커널 bridge, STP는 커널 기능 사용), 본딩
  (커널 bonding), VRF(커널, M4).
- 관리 단위: `interface` 객체 → zone 매핑(`05` §2). MAC/IP 충돌 감지 이벤트.
- 모든 구성은 설정 트랜잭션(`11` §4)을 통해서만 적용 — netlink 직접 수동 조작은 비정상 상태로
  감지/경보.

## 2. 라우팅

| 요소 | 설계 |
|---|---|
| RIB/FIB | 자체 RIB(경로 우선순위: 연결>정적>동적) → netlink로 커널 FIB 동기화 |
| 정적 라우팅 | 목적지/게이트웨이/인터페이스/메트릭, BFD(자체 구현, M3) 연동 실패 감지 |
| BGP | 자체 구현(RFC 4271 기본 + eBGP 우선). M3: 기본 경로/정책 필터, M5: iBGP/커뮤니티 |
| OSPF | 자체 구현(RFC 2328/5340). M4: 단일 에어리어 |
| RIP | 비목표(현대 배치에서 요구 낮음 — 카탈로그 제외, 필요 시 ADR로 추가) |
| ECMP | 커널 ECMP 사용, 해시 정책 옵션 |
| 라우트 맵/필터 | 접두사 목록 + 커뮤니티 필터(간결 모델) |

동적 라우팅 구현은 M3 이후 단계적이며, 각 단계 상호운용 대상(단말 벤더 무관 RFC 준수)은
docs/standards/standards-map.md에 기록한다.

## 3. DHCP(v4/v6)

- 역할: server(주소 풀, 옵션 세트, 리스 DB 지속), client(WAN/업링크), relay(옵션 82 포함).
- 구현: libngfw `services/dhcp`, UDP 소켓 기반(커널 도움 없이), 리스 데이터는 설정 파티션
  저널 기록(크래시 안전).
- DHCPv6: IA_NA/IA_PD 기본.

## 4. DNS

- resolver: 자체 스텁 리졸버(캐시, RR 반올림/우선순위), forwarder(조건부 전달).
- 로컬 존 권한 서버(정적 기록), DNSSEC 검증은 M5(암호 스택 의존).
- DNS 프록시 필터: URL 필터 카테고리와 연동한 응답 필터링(`07` §5).
- FQDN 정책 객체 해석은 이 resolver 재사용(`05` §2).

## 5. NTP

- client(시간 동기, 다중 서버), server(내부 제공, M3). 시간 소스 이상 시 경보(정책 스케줄/
  인증서 검증 영향 고려).

## 6. L2 브리지/스위칭

- 커널 bridge 사용: 포트/VLAN/STP(커널 기능). ngfw 훅은 브리지 위 IP 계층에서 동작(`04` §2.1).
- IGMP/MLD snooping: M5(커널 기능 구성).

## 7. QoS

- 모델: 클래스 기반(큐/우선순위/보장/최대), DSCP 마킹(정책 class-id↔DSCP 매핑).
- 실행: 커널 qdisc(hfsc/fq_codel) 구성을 `ngfwd`가 수행. 정책 artifact의 class-id와 연동(`03` §4).
- 세션 단위 셰이핑 훅: M4(표시/카운터 기반).

## 8. 멀티캐스트

- IGMP/MLD 프록시: M5. 커널 멀티캐스트 라우팅 기능 활용.

## 9. selftest 연계

`ngfw selftest services`: 인터페이스 구성 왕복, DHCP 리스 수명, DNS 캐시/포워더, 정적 라우팅
FIB 동기화, QoS 클래스 적용. 동적 라우팅은 QEMU 토폴로지 시스템 테스트(`17` §5).

## Change log

- 2026-10-23: 초판 작성.
