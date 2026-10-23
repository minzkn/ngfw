# NGFW 설계 문서 (`designs/`)

`ngfw`(Next Generation Firewall) 제품의 전체 설계 문서 모음이다. 요구사항의 원천은 저장소 루트의
`requirement.txt`이며, 표준/조사 자료는 `docs/`에 둔다. 코드는 본 설계 문서에 따라 구현하며,
설계 문서와 코드가 어긋나면 문서를 먼저 갱신한 뒤 코드를 수정한다(문서 선행 원칙).

## 1. 문서 맵

| 문서 | 내용 | 주요 독자 |
|---|---|---|
| `00-principles.md` | 설계 원칙(requirement.txt 매핑), 설계 규칙, 결정 기록(ADR) 운영 규칙 | 전체 |
| `01-overview.md` | 제품 개요, 목표/비목표, 기능 범위(F-카탈로그), 모델 티어, 용어집 | 전체 |
| `02-architecture.md` | 전체 아키텍처, 계층/컴포넌트 맵, 프로세스·스레드 모델, 데이터/컨트롤 플로우, 디렉터리 레이아웃 | 전체 |
| `03-kernel-dataplane.md` | 커널 모듈 `ngfw.ko` 설계: netfilter 훅, 세션 테이블, genetlink API, 오프로드 연계 | 커널 개발자 |
| `04-packet-pipeline.md` | 패킷 처리 파이프라인(단계별), 세션 생명주기, 예외 경로, fail-open/close | 데이터플레인 |
| `05-policy-engine.md` | 정책 모델, 컴파일러, 매칭 알고리즘, NAT, 정책 아티팩트 이진 포맷 | 정책/DPI |
| `06-dpi-framework.md` | DPI 프레임워크, 스트림 재조립, 프로토콜 파서, APP-ID 분류 체계 | DPI |
| `07-ips-content-security.md` | IPS/IDS 시그니처 엔진(타사 규칙 호환), URL 필터, TLS 검사, 파일 검사 | IPS |
| `08-vpn.md` | VPN: IKEv2/IPsec(xfrm 연계), WireGuard 연계, SSL VPN, GRE/L2TP | VPN |
| `09-network-services.md` | 라우팅(RIB/FIB), DHCP, DNS, NTP, L2 브리지/VLAN, QoS | 서비스 |
| `10-user-identity.md` | 사용자 식별(USER-ID), 인증 연동(RADIUS/LDAP/AD), 그룹 해석 | ID/보안 |
| `11-management.md` | 관리: `ngfw` CLI, REST API, WebUI, 설정 트랜잭션, 펌웨어 업그레이드 | 관리 |
| `12-observability.md` | 로깅, NetFlow/IPFIX, SNMP, 메트릭, `ngfw-doctor`, 이벤트 버스 | 운영 |
| `13-high-availability.md` | HA: VRRPv3, 세션/설정 동기화, 페일오버, split-brain 방지 | HA |
| `14-performance-offload.md` | 성능 설계(per-CPU/lock-free), 오프로드 매트릭스, 성능 측정 절차 | 성능 |
| `15-portability.md` | 플랫폼 이식성: libc 추상화, 아키텍처 매트릭스, 이식 계층 규칙 | 빌드/이식 |
| `16-build-deploy.md` | 빌드(Autotools/Make), 패키징, 어플라이언스 이미지, 설치/업그레이드 | 빌드/배포 |
| `17-testing-selftest.md` | 테스트 체계: 단위/selftest/시스템(QEMU·KVM·Docker), 퍼징 | QA |
| `18-security-hardening.md` | 자체 보안: 권한 분리, 샌드박스, 하드닝 빌드 옵션, 취약점 대응 | 보안 |
| `19-plugin-architecture.md` | 플러그인 아키텍처: 플러그인 종류, ABI, 로딩 규칙 | 확장 |
| `20-naming-versioning.md` | 제품명/모델명/버전 관리 규칙(단일 출처 `VERSION`) | 전체 |
| `21-roadmap.md` | 구현 로드맵(M0~M6), 마일스톤 수용 기준 | 전체 |

## 2. 읽는 순서

1. 신규 참여자: `00` → `01` → `02` → 담당 영역 문서.
2. 데이터플레인 담당: `02` → `03` → `04` → `05` → `14`.
3. 검사(NGFW 기능) 담당: `04` → `05` → `06` → `07` → `10`.
4. 관리/운영 담당: `02` → `11` → `12` → `13`.
5. 빌드/이식 담당: `15` → `16` → `17` → `20`.

## 3. 문서 규약

- **언어**: 본문 한국어, 기술 용어/식별자/코드/명령어는 영문 원형 유지.
- **요구 강도**: RFC 2119 키워드(MUST/SHOULD/MAY)를 사용한다(docs/references/rfc2119.txt 참조).
- **참조 형식**: 문서 간 참조는 `designs/XX-name.md#섹션`, 표준은 RFC 번호로 표기
  (예: RFC 7296). 코드 참조는 `src/lib/...:파일.c` 형식(구현 후 갱신).
- **숫자**: 성능 수치는 반드시 측정 절차(docs/research/performance-methods.md)와 함께 "목표"로
  표기한다. 측정 전 수치는 확정 수치로 표기하지 않는다.
- **변경 관리**: 각 문서 하단에 `Change log` 섹션을 두고, 의미 있는 설계 변경은
  `designs/00-principles.md`의 ADR(설계 결정 기록)으로 남긴다.
- **단일 출처**: 제품명/모델명/버전(`20`), 기능 목록(`01`), 모듈 맵(`02`), 인터페이스 계약
  (각 기술 문서)은 위 문서가 유일한 출처다. 다른 문서/코드 주석은 복제하지 않고 참조만 한다.

## 4. 용어 규약(전 문서 공통)

| 용어 | 정의 |
|---|---|
| fast path | 커널 내에서 세션 캐시만으로 처리되는 패킷 경로 |
| deep path | 첫 패킷 또는 검사 대상 플로우가 유저랜드 검사 엔진으로 전달되는 경로 |
| session | 5-tuple 기반 커널 커넥션 상태 레코드(conntrack 상당) |
| flow | session과 동의어. 문서에서 session으로 통일 |
| policy artifact | 정책 컴파일러가 생성하는 커널 적재용 이진 산출물 |
| tap | 유저랜드 검사를 위한 패킷 복제/인계 채널(NFQUEUE 기반) |
| zone | 인터페이스 보안 구역. 정책 매칭의 기본 단위 |
| object | 정책에서 참조되는 재사용 개체(주소/서비스/앱/사용자/스케줄/프로파일) |
| M0~M6 | `21-roadmap.md`의 마일스톤 |

## 5. 제품 식별 요약

- 프로젝트/제품명: `ngfw`. 상세 명명/버전 규칙은 `20-naming-versioning.md`가 유일 출처다.
- 커널 모듈: `ngfw.ko`. 유저랜드 데몬: `ngfwd`, `ngfw-engine`. 관리 CLI: `ngfw`.
- 빌드/이식/검증 절차는 `16`, `17`에서 정의하며 모든 절차는 `ngfw selftest`로 자체 검증 가능해야 한다.
