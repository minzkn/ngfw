# 주요 NGFW 기능 비교 조사

- 문서 상태: 초판 (리서치 참고 문서)
- 작성일: 2026-10-23
- 목적: 상용·오픈소스 방화벽 4종의 주요 기능을 축별로 비교하고, `ngfw` 프로젝트 설계에 반영할 교훈을 도출한다.
- 표기: 제품 고유 사실 중 본 문서 작성 시점에 확인 불가한 항목은 `(미검증)`으로 표기했다.
- 용어: 본 문서는 `ngfw` 프로젝트 용어를 사용한다.
  - **fast path** = 커널 세션 캐시 경로
  - **deep path** = 유저랜드 검사 경로
  - **APP-ID** = 계층형 앱 식별 (category/app/subtype)
  - **session** = 커널 5-tuple 상태 레코드
  - **policy artifact** = 컴파일된 정책 이진 (NGFWPOL)

## 1. 비교 대상 개요

| 구분 | 분류 | 특징 |
| --- | --- | --- |
| Palo Alto NGFW | 상용 | 단일 OS(PAN-OS)에 식별·검사·정책을 통합. App-ID 기반 정책 모델의 대표 사례 |
| Fortinet FortiGate | 상용 | NPU/암호화 프로세서 오프로드 중심의 성능 설계. UTM 기능을 엔진 단위로 통합 |
| pfSense / OPNsense | 오픈소스 배포판 | FreeBSD 기반. 코어는 pf 상태방화벽이며 NGFW 기능은 패키지/플러그인으로 보강 |
| iptables / nftables | 리눅스 커널 프레임워크 | 패킷 필터 자체는 L3/L4 중심. NGFW 기능은 외부 컴포넌트 조합으로 구성 |

## 2. 축별 비교 요약표

| 축 | Palo Alto NGFW | Fortinet FortiGate | pfSense·OPNsense | iptables·nftables |
| --- | --- | --- | --- | --- |
| 앱 식별 | App-ID. 앱에 category/subcategory 등 계층 메타 부여 (미검증: 최신 필드 구성) | Application Control. 시그니처 + 카테고리 분류, 구독 갱신 | 기본 제공 없음(pf는 L3/L4). Zenarmor(Sensei) 플러그인으로 보완 (미검증) | 없음. NFQUEUE로 유저랜드 DPI 연동 |
| IPS 시그니처 형식 | 자체 포맷. 커스텀 시그니처는 UI/API로 작성 (미검증: 포맷 상세) | 자체 IPS 시그니처 언어(키워드 기반) + FortiGuard 구독 채널 | Snort/Suricata 텍스트 규칙(sid/rev) 그대로 사용 | 없음. Suricata/Snort를 외부 엔진으로 배치 |
| URL 필터 | PAN-DB 클라우드 카테고리 + 로컬 커스텀 카테고리 | FortiGuard Web Filter 클라우드 카테고리 + 로컬 리스트/예외 | 프록시 계열(Squid+squidGuard, DNSBL)로 구현. 카테고리 DB는 외부/유료 의존 | 없음. 투명 프록시(Squid 등) 별도 구성 |
| TLS 검사 | Decryption 정책(인바운드/아웃바운드/미러). 핀닝 앱 예외 목록 | SSL/SSH Inspection 2단계: certificate-inspection / deep-inspection | Squid SSL bump(동적 인증서 생성). 전 구간 MITM은 아님 | 없음 |
| VPN | IPsec(IKEv1/v2) + GlobalProtect(SSL VPN) | IPsec + SSL VPN(웹/터널 모드). FortiOS 7.6에서 SSL VPN 터널 모드 축소 (미검증) | OpenVPN·IPsec·WireGuard(내장/플러그인) | IPsec(strongSwan 계열)·WireGuard 커널 모듈·OpenVPN 유저랜드 |
| HA 방식 | Active/Active·Active/Passive. 전용 HA 링크(HA1/HA2/HA3)와 session 동기화 | FGCP A/P·A/A 내장, session 동기화 포함. FGSP(분리형 session 동기화) | CARP + pfsync. A/P 지향, session 상태 동기화 | 자체 없음. keepalived(VRRP) + conntrackd 조합 |
| 관리/설정 모델 | Panorama 중앙관리. candidate→commit 모델, device group/template 계층 | FortiManager(ADOM 단위). 설치 전 config diff 미리보기 | 노드별 웹 GUI + config.xml 파일 기반. 중앙관리는 외부 연동 (미검증) | 텍스트 규칙 파일 + nft batch(atomic) 적용. IaC는 외부 도구 |
| 로그·플로우 익스포트 | syslog 포워딩 프로파일, XML API, 클라우드 로그 전송 (미검증: 서비스명 변경 이력) | FortiAnalyzer 수집, syslog, NetFlow/sFlow | 원격 syslog, pf 필터 로그. NetFlow는 softflowd 등 외부 (미검증) | LOG/NFLOG 타깃, ulogd2, nft counter/meter. IPFIX는 softflowd 등 외부 |
| 오프로드 | 모델 의존 하드웨어 가속(암호화/세션) (미검증: 세부 구성) | NPU(SoC/NP 계열) + CP(암호화 프로세서) 오프로드가 설계 중심 | NIC 체크섬/TSO/LRO 수준. 상태 오프로드는 제한적 | nftables flowtable(소프트웨어/하드웨어 flow offload), XDP/eBPF |

## 3. 축별 상세

### 3.1 앱 식별 (APP-ID)

- Palo Alto NGFW: 포트 기반 추정이 아니라 프로토콜 디코드 + 시그니처 + 휴리스틱을 결합해 앱을 식별한다. 식별된 앱은 category/subcategory/technology/risk 같은 메타를 갖고, 정책 매칭과 로그 필드가 동일한 계층을 공유한다 (미검증: 최신 PAN-OS 필드 구성).
- Fortinet FortiGate: IPS 엔진 기반의 애플리케이션 시그니처에 카테고리 분류를 붙인 형태. 카테고리 정의는 FortiGuard 구독 갱신에 의존한다.
- pfSense / OPNsense: pf 자체에는 계층 7 식별이 없다. OPNsense 생태계의 Zenarmor(Sensei)가 앱/웹 카테고리 식별을 제공하며, 라이선스 등급에 따라 기능 차이가 있다 (미검증).
- iptables / nftables: L7 식별 개념이 코어에 없다. l7-filter 계열은 사실상 소멸했고, 현실적 구성은 NFQUEUE로 패킷을 유저랜드 DPI(Suricata 등)에 넘기는 방식이다.
- `ngfw` 시사점: 식별은 커널이 아니라 deep path(유저랜드 검사 경로)의 몫이며, 결과만 session에 각인해 fast path(커널 세션 캐시 경로)가 재사용하는 구조가 정답에 가깝다.

### 3.2 IPS 시그니처 형식

- 사실상의 교환 포맷은 Snort/Suricata 텍스트 규칙(header + options, sid/rev 버전 관리)이다. pfSense·OPNsense는 이 포맷을 그대로 소비한다.
- Palo Alto와 FortiGate는 자체 포맷을 유지하며, 커스텀 시그니처도 벤더 UI/API로 작성한다. 포맷 이식성은 낮지만 벤더 엔진과의 최적화는 쉽다.
- 업데이트 모델: 구독 기반 원격 채널(FortiGuard, Threat Prevention 등) + 로컬 커스텀 룰의 이원화가 표준 패턴이다.
- `ngfw` 시사점: Suricata 규칙 부분 호환을 목표로 하는 현재 방향은 오픈소스 생태계와의 자산 재사용 측면에서 합리적이다. 파서는 헤더/공통 옵션 중심으로 부분 집합을 명시하고, 미지원 옵션은 컴파일 시 경고로 남기는 편이 안전하다.

### 3.3 URL 필터

- 카테고리 DB 자체가 구독 상품(PAN-DB, FortiGuard)이라 오프라인/자급 환경에서는 로컬 리스트 기반으로 후퇴한다.
- 오픈소스 계열은 프록시(Squid) 계층에서 해결하며, 방화벽 코어와 분리되어 있다. HTTPS 환경에서는 SNI 기반 분류가 사실상 표준이 되었다.
- `ngfw` 시사점: URL 필터를 코어 기능이 아니라 선택적 컴포넌트로 두고, 코어에는 SNI/HTTP Host 기반 최소 매칭(정책 artifact에 반영 가능한 형태)만 넣는 구조가 현실적이다.

### 3.4 TLS 검사

- 상용 양사 모두 2단계 모델이다. FortiGate는 명시적으로 certificate-inspection(인증서만 보고 제어)과 deep-inspection(전체 복호화)을 구분하고, PAN-OS는 decryption policy에 예외 목록(핀닝 앱, 인증서 신뢰 문제 그룹)을 둔다.
- 복호화 비용이 가장 큰 성능 병목이므로, 검사 대상을 정책으로 좁히고 나머지는 fast path로 통과시키는 운영이 일반적이다.
- 오픈소스 계열은 Squid SSL bump 정도가 전부이며, 투명한 전 구간 MITM에는 한계가 있다.
- `ngfw` 시사점: 기본값은 cert-only 제어, full MITM은 명시적 토글. 핀닝/예외 목록은 policy artifact(NGFWPOL)에 함께 컴파일해 fast path에서 먼저 걸러지도록 한다.

### 3.5 VPN

- IPsec(IKEv2)은 4종 모두가 지원하는 공통 기반이다. SSL VPN은 벤더 고유 형태(Palo Alto GlobalProtect, FortiOS SSL VPN)다.
- 오픈소스 계열은 WireGuard를 빠르게 채택해 커널 내장/플러그인으로 제공한다. 코드 기반이 작고 공격 표면이 작아 방화벽 배포판과 궁합이 좋다.
- `ngfw` 시사점: IPsec은 fast path 세션과 결합되어야 하므로(XFRM 정책과 session의 관계), 커널 측 인터페이스 설계를 초기에 고정할 필요가 있다.

### 3.6 HA 방식

- 차이의 본질은 session 동기화다. pfsync(CARP+pf), FGCP(FortiGate), PAN-OS HA2는 모두 상태 동기화 전용 채널을 별도로 둔다.
- A/A 구성은 session 소유권·비대칭 흐름 처리가 추가로 필요해 구현 난이도가 크게 올라간다. 오픈소스 계열은 A/P 중심이다.
- `ngfw` 시사점: session(커널 5-tuple 상태 레코드) 복제는 HA의 1급 기능이다. 복제 프로토콜과 fast path 웜업(페일오버 직후 캐시 재구성 비용)을 함께 설계해야 한다.

### 3.7 관리/설정 모델

- 상용 양사 모두 "선언적 원하는 상태 → 커밋/컴파일 → 장비 배포" 모델이다. Panorama는 candidate/running 구분과 device group 계층, FortiManager는 ADOM과 설치 전 diff 미리보기를 제공한다.
- pfSense/OPNsense는 노드 단위 config.xml 파일 모델로, 단순하지만 중앙관리는 외부 도구 의존이다.
- nftables는 ruleset 전체를 batch로 원자적(atomic) 교체하는 모델로, 소스 규칙 파일이 곧 desired state다.
- `ngfw` 시사점: 소스 정책 → 컴파일 → policy artifact(NGFWPOL) → 원자적 설치/롤백의 3단계 파이프라인이 위 세 사례의 공통 패턴이다. diff 미리보기(적용 전 영향 분석)는 운영 신뢰의 핵심이다.

### 3.8 로그·플로우 익스포트

- 표준 경계는 syslog + NetFlow/IPFIX다. 벤더 고유 수집(FortiAnalyzer, 클라우드 로그)은 자체 API/포맷으로 확장한다.
- flow export는 대개 별도 프로세스(softflowd 등)가 방화벽 상태를 샘플링하는 형태로, 방화벽 코어와 느슨하게 결합되어 있다.
- `ngfw` 시사점: session이 소멸할 때 fast path 카운터를 배치로 export하는 구조면 유저랜드 부담 없이 표준 포맷(IPFIX) 경계를 유지할 수 있다.

### 3.9 오프로드

- FortiGate는 ASIC(NPU/CP) 오프로드를 설계 중심에 두고, 세션 성립 후 NPU로 흐름을 넘기는 모델이다. "식별은 CPU, 전달은 ASIC"의 원형이다.
- nftables flowtable은 커널이 fast path 역할을 네이티브로 제공하는 사례로, 소프트웨어/하드웨어(NIC 스위치 드라이버 협력) 오프로드를 모두 지원한다.
- pfSense 계열은 NIC 수준 체크섬/TSO/LRO 정도이며, 상태 처리 오프로드는 제한적이다.
- `ngfw` 시사점: fast path(커널 세션 캐시 경로)와 flowtable의 관계 — 대체인지 병행인지 — 를 초기에 결정해야 한다. session이 유지되는 한 flowtable 항목도 세션 라이프사이클을 따르는 것이 일관성 있다.

## 4. 결론: `ngfw` 설계에 반영할 교훈

- **fast path / deep path 분리가 성능의 전제다.** 모든 성숙한 구현은 "첫 패킷은 deep path에서 식별 → 결과를 session에 각인 → 이후 패킷은 fast path에서 처리" 구조다. deep path 재진입 조건(정책 변경, 시그니처 갱신, 세션 만료, 앱 재평가 필요 표지)을 명시적으로 정의하라.
- **session 복제는 HA의 1급 기능이다.** pfsync, FGCP, PAN-OS HA2 모두 상태 동기화 전용 경로를 둔다. `ngfw`의 session(커널 5-tuple 상태 레코드) 복제 프로토콜과 페일오버 시 fast path 웜업을 함께 설계하라.
- **APP-ID는 계층형(category/app/subtype)으로 유지하고 정책·로그가 같은 계층을 공유하게 하라.** Palo Alto처럼 앱 메타가 정책 매칭과 로그 필드에서 동일하게 쓰이면 운영 일관성이 크게 올라간다.
- **정책은 "소스 → 컴파일 → policy artifact(NGFWPOL) → 원자적 설치" 파이프라인으로.** Panorama commit, FortiManager diff 미리보기, nftables atomic 교체가 모두 같은 패턴이다. 적용 전 diff/영향 분석과 롤백을 기본 동작으로 만들어라.
- **IPS 시그니처는 텍스트 포맷(Suricata 부분 호환)을 채택하라.** sid/rev 기반 버전 관리, 구독 채널과 로컬 커스텀 룰의 분리, 미지원 옵션의 컴파일 타임 경고가 오픈소스 생태계 호환의 최소 조건이다.
- **TLS 검사는 2단계(cert-only / full MITM)로 설계하고 기본값은 cert-only다.** FortiGate의 2모드 구분이 실제 운영 패턴이며, 핀닝 앱 예외는 policy artifact에 컴파일해 fast path에서 먼저 분기시켜라.
- **URL 필터링은 코어 밖 선택적 컴포넌트로.** 코어는 SNI/HTTP Host 기반 최소 매칭만 제공하고, 카테고리 DB는 구독/플러그인으로 분리한다(오프라인 우선 원칙).
- **로그·플로우는 표준 포맷(syslog, NetFlow/IPFIX) 경계에서만 외부와 통신하라.** 벤더 고유 수집은 코어 밖 에이전트의 영역이며, session 종료 시 fast path 카운터 배치 export로 유저랜드 부담을 피할 수 있다.
- **오프로드는 fast path의 확장으로 취급하라.** nftables flowtable이 커널 네이티브 fast path의 실증 사례다. fast path 캐시와 flowtable을 병행/대체 중 무엇으로 볼지 초기에 결정하고, session 라이프사이클에 flowtable 항목을 종속시켜라.

## Change log

- 2026-10-23: 초판 작성.
