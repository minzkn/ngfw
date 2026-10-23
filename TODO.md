# TODO.md — 남은 구현 작업 목록

## 관리 규칙

1. 이 파일은 `designs/` 설계 문서에 정의된 내용 중 **아직 구현되지 않은 모든 항목**을 관리한다.
   설계 내용의 유일 출처는 designs/ 문서이며, TODO.md는 요약+출처 참조만 한다(P-A).
2. **구현이 완료되면 해당 항목 줄을 즉시 삭제한다.** 체크(`[x]`)만 남겨두지 않는다.
3. 완료 판정: 코드가 빌드되고 `make check` 통과 + 해당 문서의 "selftest 연계" 케이스가
   통과하는 것까지 포함한다(R04).
4. 새 설계 항목이 생기면 designs/ 문서를 먼저 갱신한 뒤(P-F) 이곳에 추가한다.
5. 항목 형식: `- [ ] <작업 요지> — <출처 문서 §섹션> (<기능 Fnn>)`
6. 마일스톤 배정은 `designs/21-roadmap.md` 기준이며, 미배정 항목은 마지막 섹션에 두고
   구현 착수 전에 배정한다.

## M0 — 골격 (잔여)

- [ ] Docker 이식 매트릭스 실행 검증(ubuntu glibc / alpine musl) — `17` §6, scripts/docker-matrix.sh (docker 데몬 필요)

## M1 — 기본 방화벽

### 커널 데이터플레인 — `03-kernel-dataplane.md`

- [ ] `ngfw.ko` 모듈 골격: Kbuild, 로드/언로드 순서, 모듈 파라미터(session_buckets/tap_queues/default_pending 등) — `03` §2~3 (F01)
- [ ] netfilter 훅 배치(v4/v6 4훅, 우선순위 상수, skb mark 비트 규약, conntrack 공존 규약) — `03` §4 (F01)
- [ ] 세션 테이블: per-CPU hashtable, 정규화 5-tuple, slab 캐시, 한도/overflow-action, 세션 이동 — `03` §5 (F01)
- [ ] 세션 상태머신/타임아웃(artifact session-profile 주입) — `03` §5.2, `04` §3
- [ ] 세션 GC(per-CPU delayed work, tombstone, RCU 해제) — `03` §5
- [ ] genetlink family `ngfw` v1: ops 1~10, nla_policy 검증, multicast `ngfw-events`, TLV 이벤트 타입 1~6, 레이트 리밋 — `03` §7
- [ ] POLICY_LOAD→ACTIVATE 2단 staging/RCU 스왑, 이전 artifact 참조 해제 — `03` §7.1
- [ ] tap 서브모듈: NFQUEUE 인계(큐=CPU), verdict=pending, tap-verdict-timeout 후 pending-action — `03` §8 (F01)
- [ ] NAT 서브모듈: SNAT(per-CPU 포트 커서)/DNAT/NPTv6, ICMP 에러 세션 어핀 — `03` §9 (F02)
- [ ] per-CPU 통계/카운터와 STATS_DUMP, 통계 문지름 이벤트 — `03` §2, §7.2 (F13)
- [ ] selftest kernel 그룹(genl 왕복/세션 생성·만료/tap 타임아웃/NAT/통계) — `03` §13 (F15)

### 정책 엔진 — `05-policy-engine.md`

- [ ] 정책 객체 모델 + JSON 스키마(zone/address/service/app/user/schedule/profile/rule) — `05` §2~3 (F01)
- [ ] 컴파일 파이프라인: 스키마/참조 검증, 객체 해석(FQDN 캐시), 섀도 분석 경고 — `05` §4
- [ ] 매칭 구조/알고리즘: src/dst LPM trie, 포트 비트맵, app/user 역인덱스, top-down 최소 인덱스 — `05` §5
- [ ] NGFWPOL v1 직렬화/역직렬화(CRC, generation, 카운터 섹션 분리, 버전 호환 규칙) — `05` §8
- [ ] 규칙 히트 카운터(커널 per-CPU 쓰기 영역) — `05` §9
- [ ] NAT 의미론(hairpin 세션 경로, 포트 고갈 처리) — `05` §6 (F02)
- [ ] 세션 재평가 트리거 5종(gen 불일치/app-id 변경/user 바인딩/스케줄 경계/위협 verdict) — `05` §7
- [ ] selftest policy(스키마 오류/섀도/매칭 골드/artifact 라운드트립) — `05` §10

### 파이프라인/예외 — `04-packet-pipeline.md`

- [ ] 파이프라인 단계 구현: ingress zone 분류, prefilter, DNAT, routing 연계, verdict 적용(+gen 재평가), POSTROUTING SNAT/GSO, 호스트 트래픽 존 — `04` §2 (F01)
- [ ] 브리지 모드 접점(브리지 포트 zone 매핑, 훅 재진입) — `04` §2.1 (F17)
- [ ] TCP 상태머신(SYN/FIN/RST, strict 모드), UDP/ICMP 추적 — `04` §3 (F01)
- [ ] 예외 경로: 프래그먼트 캐시, IPv6 확장 헤더, MTU/PMTUD, 세션 CPU 이동 — `04` §5
- [ ] DoS 커널 단: 신규 세션 레이트(토큰버킷), SYN 쿠키 방식 핸들링, ICMP flood — `04` §6 (F18)
- [ ] fail-open/close 스위치와 전환 이벤트/doctor 항목 연계 — `04` §7
- [ ] reject 동작(RST/ICMP unreachable 생성, 레이트 제한) — `04` §2.3

### 관리/서비스/관측 — `02`, `09`, `11`, `12`

- [ ] `ngfwd` 데몬 골격: 이벤트 루프 통합, kapi(genl 클라이언트), 스레드 모델(log-writer 등) — `02` §4
- [ ] zone/인터페이스 관리(IP/서브넷, VLAN, 브리지, 본딩 구성, netlink 적용) — `09` §1 (F17)
- [ ] CLI 명령 트리(동사 일관 규칙, 대화형 모드, JSON 출력, 컨텍스트 도움말) — `11` §2 (F12)
- [ ] 설정 트랜잭션(candidate/validate/commit/confirm 타임아웃/저널 롤백/diff) — `11` §4
- [ ] 설정 적용 순서화(genl 2단 + xfrm/qdisc/netlink, 실패 시 자동 복원) — `11` §4
- [ ] 로컬 append-only 저널 로그(회전, 감사 해시 체인 기초) — `12` §2 (F13)
- [ ] syslog 클라이언트(RFC 5424/6587, TLS 전송 옵션은 M3) — `12` §2
- [ ] 이벤트 버스 최소형(카테고리/심각/레이트 리밋/집계) — `12` §1
- [ ] `ngfw show policy`(히트 카운터) / `ngfw show session`(필터) — `12` §6 (F20)
- [ ] NIC 기본 오프로드 구성(TSO/USO/GSO/GRO/checksum/RSS, IRQ affinity 스크립트) — `14` §3, §5 (F14)
- [ ] 로컬 사용자 DB(해시/솔트)와 인증, 계정 관리 CLI — `10` §2 (F08)
- [ ] selftest mgmt(CLI 회귀/트랜잭션)·observ(이벤트/저널/syslog) 그룹 최소형 — `11` §8, `12` §9

## M2 — NGFW 검사 1단

### crypto 선행 — ADR-005 (`02` §5)

- [ ] 자체 해시/HMAC(SHA-256/512), AEAD(AES-GCM-128/256, ChaCha20-Poly1305) 프리미티브 — `02` §5 (ADR-005)
- [ ] 커널 crypto API(AF_ALG) 가속 백엔드 연계 추상화 — `02` §5 (ADR-005), `14` §3
- [ ] 시크릿 암호화 볼트(AES-GCM 볼트, KDF: PBKDF2/Argon2i 서브셋), 로테이션 명령 — `18` §4
- [ ] 하드닝 빌드 옵션(PIE, -fstack-protector-strong, FORTIFY, LTO) — `18` §2
- [ ] configure 옵션 확장: `--enable-debug`(sanitizer), `--with-kernel`, `--enable-xdp`, `--enable-openssl-compat`(기본 off) — `16` §2

### DPI/APP-ID — `06-dpi-framework.md`

- [ ] `ngfw-engine` 데몬: tap-in 스레드(큐=CPU), NFQUEUE mmap 배치 수신/verdict 송신 — `06` §5
- [ ] TCP/UDP 스트림 재조립(갭 관리, 플로우당 버퍼 한도, 검사 중단 정책) — `06` §3
- [ ] APP-ID 5단계 분류(포트 사전→메타 필드→시그니처→파서 검증→세션 캐시 학습) — `06` §4 (F03)
- [ ] 계층형 APP-ID 테이블(category/app/subtype) + 사용자 정의 앱 — `06` §4
- [ ] 파서 플러그인 ABI v1(내장 파서가 동일 계약 사용) — `06` §6, `19` §2 (F16)
- [ ] 내장 파서 1차: DNS, HTTP/1.x, TLS 메타, QUIC(v1), SMTP, FTP, SSH 배너, SMB, RDP, SIP — `06` §6 (F03)
- [ ] 커널↔엔진 이벤트 릴레이(ngfwd 중계, unix seqpacket + 공유 링) — `06` §7, `02` §6
- [ ] 세션 verdict/패킷 verdict 구분 및 TAP_VERDICT 기록 — `06` §5, `03` §8
- [ ] 자원 한도(동시 검사 플로우/재조립 버퍼/이벤트 레이트) + 메트릭 노출 — `06` §8
- [ ] selftest dpi(재조립 골드/파서 샘플/재평가/tap 왕복/한도) — `06` §9

### IPS/콘텐츠 보안 — `07-ips-content-security.md`

- [ ] 시그니처 컴파일러(헤더 파싱, 지원 키워드 목록, 미지원 키워드 명시적 오류) — `07` §2.1 (F04)
- [ ] Aho-Corasick 멀티패턴 매처 + 규칙 옵션 VM(content/depth/offset/distance/within/nocase, http_*/tls.sni/dns.query) — `07` §2.2 (F04)
- [ ] 제한 pcre(선형 목표 NFA 서브셋, 백트래킹 상한) — `07` §2.2
- [ ] 프로토콜 분석기(HTTP/TLS/SMTP/FTP/DNS/SMB/SSH) + anomaly 이벤트 등록 — `07` §3
- [ ] threshold / detection_filter / suppression — `07` §4
- [ ] URL 필터: DB 포맷+임포터 어댑터, SNI 기반 HTTPS 분류, HTTP Host/URL, DNS 프록시 연동 — `07` §5 (F05)
- [ ] 파일 경계 추출(HTTP multipart/body, SMTP 첨부, FTP) + 해시/타입 정책 — `07` §6 (F19 1차)
- [ ] TLS inspect-sni 심화(버전/암호스위트/SNI-인증서 불일치 정책) — `07` §7 (F06 1차)
- [ ] IDS/IPS 모드 전환(alert/drop/reset, 세션 threat-verdict 기록) — `07` §1
- [ ] selftest ips/url(골드 트레이스, 오탐 억제) — `07` §9

### HA — `13-high-availability.md`

- [ ] VRRPv3 자체 구현(v4/v6, 가상 MAC, preempt 옵션) — `13` §1 (F10)
- [ ] HA 링크(전용/폴백)와 피어 모니터, 추적 인터페이스 가중치 — `13` §1
- [ ] 설정 동기화(마스터→슬레이브 원자 전파, 버전 확인+서명, 슬레이브 커밋 차단) — `13` §1, §4
- [ ] 세션 동기화 프로토콜(TLV 프레임, 델타+스냅샷 재조정) + genl SESSION_SYNC 확장 — `13` §2, `03` §7.1
- [ ] 페일오버 절차(VIP/가상 MAC 인수, ARP 갱신, 정책 최신성 확인) — `13` §3
- [ ] split-brain 방지(이중 판정, 자기 강등) — `13` §3
- [ ] selftest ha(QEMU 2노드: 선출/전환/복귀/split-brain) — `13` §5

### 사용자 식별 — `10-user-identity.md`

- [ ] RADIUS 클라이언트(RFC 2865/2866, 어트리뷰트→그룹 매핑) — `10` §2 (F08)
- [ ] LDAP/AD 클라이언트(바인드/검색, SID→그룹 매핑) — `10` §2
- [ ] Captive portal(HTTPS, WebUI 재사용) — `10` §2
- [ ] 바인딩 라이프사이클(만료/이동/경합) + 커널 user_id 전파/재평가 — `10` §3
- [ ] 그룹 해석(외부→로컬 매핑, 변경 시 배치 재평가) — `10` §4
- [ ] 인증 실패/락아웃/감사 로그 — `10` §2, §5
- [ ] selftest identity(로컬/RADIUS·LDAP 시뮬레이터/포탈) — `10` §6

### 오프로드 — `14-performance-offload.md`

- [ ] tc flower 세션 오프로드(조건 필터: ESTABLISHED+allow+검사 완료, 검사 세션 절대 제외, SW 폴백) — `03` §10, `14` §3 (F14)
- [ ] XDP 사전 필터(선택적 eBPF 빌드, 없어도 기능 손실 없음) — `04` §6, `14` §3
- [ ] flow steering(n-tuple/flow director) 구성 — `14` §3

## M3 — VPN/가시성/서비스 심화

### VPN — `08-vpn.md`

- [ ] RSA/ECDSA/Ed25519 + X.509 파서/검증(인증서 인증용) — `02` §5 (ADR-005)
- [ ] 자체 TLS 1.3 스택(클라이언트/서버, SSL VPN·full-mitm 선행) — `07` §7, `08` §4
- [ ] IKEv2 자체 구현(상태머신 INIT→AUTH→CHILD, 리타이밍, DPD) — `08` §2 (F07)
- [ ] xfrm 연계(SA/SP netlink 주입, mark 비트 규약, 정책 충돌 없는 우선순위) — `08` §2
- [ ] NAT-T(RFC 3947 감지/캡슐) — `08` §1 (F07)
- [ ] IPsec remote access(EAP/EAP-TLS) — `08` §1
- [ ] WireGuard 연계(커널 WG netlink 구성, 키 볼트 연계, zone 매핑) — `08` §3
- [ ] SSL VPN(TLS 1.3 + 자체 터널 프레임 프로토콜, ngfw-vpn-client) — `08` §4 (F07)
- [ ] GRE/L2TPv2(컨트롤 자체 구현 최소) — `08` §5
- [ ] selftest vpn(QEMU 토폴로지 핸드셰이크/NAT-T/xfrm 일치성) — `08` §7

### 가시성 — `12-observability.md`

- [ ] IPFIX(RFC 7011) 익스포터(템플릿 관리, ngfw 확장 IE, 버퍼링/리트라이) — `12` §3 (F13)
- [ ] NetFlow v5/v9 호환 모드 — `12` §3
- [ ] SNMP 에이전트(v2c/v3: GET/GETNEXT/GETBULK/트랩) + docs/mibs/ 엔터프라이즈 MIB — `12` §4
- [ ] 메트릭 엔드포인트(Prometheus 텍스트 + JSON 스냅샷, 필수 메트릭 세트) — `12` §5
- [ ] `ngfw trace` 플로우 추적 모드 — `12` §6
- [ ] `ngfw-doctor` 진단 그룹(빌드/실행/네트워크/보안/성능) — `12` §7
- [ ] selftest observ 확장(IPFIX/SNMP 목표 수신 검증, 메트릭 일관성) — `12` §9

### 네트워크 서비스 — `09-network-services.md`

- [ ] BGP4 eBGP(경로/접두사 필터) — `09` §2 (F09)
- [ ] 정적 라우팅 BFD 연동 실패 감지 — `09` §2
- [ ] DHCP server/client/relay(v4/v6, 리스 저널 지속) — `09` §3
- [ ] DNS resolver/forwarder/로컬 존 권한 서버 — `09` §4
- [ ] NTP client(다중 서버)/server — `09` §5
- [ ] selftest services 확장(동적 라우팅은 QEMU) — `09` §9

## M4 — 운영 성숙

- [ ] TLS 1.2 지원 추가(자체 스택) — `07` §7
- [ ] TLS full-mitm(자체 CA 운영, 인증서 발급, 제외 카테고리, 핀닝 감지 우회, 세션 감사 로그) — `07` §7 (F06)
- [ ] OSPFv2/v3(단일 에어리어) — `09` §2 (F09)
- [ ] VRF — `09` §1 (F17)
- [ ] QoS 셰이핑 훅(세션 단위, DSCP 마킹 매핑 확장) — `09` §7 (F11)
- [ ] MOBIKE(RFC 4555) — `08` §2
- [ ] AD 그룹 심화, SAML/OIDC(관리 평면) — `10` §2
- [ ] 2FA(TOTP, 자체 구현) — `11` §1
- [ ] REST 서버 HTTP/2 활성(선택) — docs/standards/standards-map.md (RFC 9113)
- [ ] active/active HA 설계 착수(신규 ADR) — `13` §1
- [ ] io_uring 관리/로그 IO — `14` §3
- [ ] selftest mgmt-ux 그룹(UX 회귀 케이스) — `11` §8

## M5 — 고급/확장

- [ ] NAT64(RFC 6146)/DNS64(RFC 6147) — `05` §6, `09` §4
- [ ] DNSSEC 검증(RFC 4033~4035) — `09` §4
- [ ] iBGP/커뮤니티 필터 — `09` §2
- [ ] IGMP/MLD snooping/프록시 — `09` §6, §8
- [ ] 아카이브 순회(자체 zip inflate, 중첩 한도) + 정적 서명(자체 미니 문법) — `07` §6 (F19)
- [ ] active/active HA 구현 — `13` §1
- [ ] 플러그인 동적 로딩 정식화(dlopen, 매니페스트/서명 검증, allowlist 경로) — `19` §2~3 (F16)
- [ ] Kerberos/SPNEGO 검토(필요 시 ADR) — `10` §2
- [ ] sFlow 도입 검토(ADR) — `12` §3

## M6 — 안정화/릴리스

- [ ] 성능 풀 측정 + `docs/benchmarks/` 기록(환경/시나리오/지표 전체 매트릭스) — `14` §2
- [ ] 보안 감사: 퍼징 결과 정리, selftest security 전체 통과 — `18` §8, `17` §7
- [ ] 문서-코드 일치 감사(설계 문서 갱신 선행 원칙 점검) — `00` P-F
- [ ] 어플라이언스 이미지 확정: ngfw-image 빌더, 파티션(부트/설정/시스템 A/B/로그), GRUB/U-Boot, 부트 카운터 롤백 — `16` §5
- [ ] `ngfw-init`(PID 1): 마운트/자가진단/기동 순서/재부팅 루프 감지/복구 모드 — `02` §8, `12` §8
- [ ] 릴리스 절차(scripts/release.sh, 태그, CI 게이트 연동, 산출물 게시) — `16` §6, `20` §5
- [ ] 문서 생성 파이프라인(OpenAPI 3.1 JSON, MIB 검증, 매뉴얼) — `16` §7

## 횡단/인프라 (마일스톤과 독립)

- [ ] `scripts/check-layering.sh`(include 방향 검사) — `17` §3, `02` §7 (R08)
- [ ] `scripts/check-style.sh`(유저랜드 GNU/커널 스타일 최소 점검) — `17` §3, docs/standards/style-guides.md
- [ ] `scripts/ci-local.sh`(전 게이트 로컬 재현) — `17` §8
- [ ] 퍼저 인프라(대상: 패킷 파서/IKEv2/TLS 핸드셰이크/설정 파서/규칙 컴파일러/genl 속성, sanitizer 연동) — `17` §7
- [ ] 시나리오 자산(tests/scenarios/*.yaml, tests/pcap/ 골드 트레이스) — `17` §5
- [ ] 커널 빌드 매트릭스(6.12 이상 다중 커널 헤더) — `17` §4 (R12)
- [ ] platform API 확장: RNG(getrandom/폴백), 저널 안전 쓰기, 권한 강하/seccomp 적용 래퍼 — `15` §3, `18` §3
- [ ] 권한 분리/샌드박스(ngfwd 권한 강하+특권 헬퍼, ngfw-engine seccomp/landlock 프로파일) — `18` §3
- [ ] 감사 로그 해시 체인 검증 명령(`ngfw audit verify`) — `18` §5
- [ ] 펌웨어 패키지(.ngfwup) 서명/다운그레이드 방지 — `11` §5, `18` §6
- [ ] SIMD 선택 최적화 경로(`--enable-simd`, 기본은 순수 C11 경로 유지) — `15` §4
- [ ] VERSION 주입 확대(커널 MODULE_VERSION, 패키지/이미지/시그니처 DB 메타) — `20` §3
- [ ] selftest version 확장(전 구성요소 버전 일치 검증) — `20` §3
- [ ] selftest security 그룹(권한 강하/seccomp/볼트/서명 위조 거부/감사 체인/레이트 제한) — `18` §9
- [ ] selftest perf 스모크(측정 기록 대비 하락율 규칙) — `14` §6
- [ ] selftest version/mgmt/observ 그룹 전체 확충(모듈 문서의 selftest 연계 케이스 전부) — 각 모듈 문서

## 마일스톤 미배정 (구현 착수 전 배정할 것)

(현재 없음 — 신규 항목 발생 시 여기에 추가하고 배정 후 해당 섹션으로 이동)
