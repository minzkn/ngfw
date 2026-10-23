# 00. 설계 원칙

`requirement.txt`의 14개 요구 항목을 원칙 ID(R01~R14)로 고정하고, 각 항목을 구체적인 설계 규칙과
수용 기준으로 전개한다. 모든 기술 문서는 이 원칙 ID를 참조하여 설계 근거를 남긴다.

## 1. 원칙 매핑 (requirement.txt → 설계 규칙)

| ID | 요구(원문 요지) | 설계 규칙 | 수용 기준(검증) |
|---|---|---|---|
| R01 | 자체 구현, 외부 의존 최소화(부트로더, Linux Kernel, 다양한 libc만 사용) | 런타임 외부 라이브러리 금지. 유저랜드는 POSIX/libc만 사용(`15-portability.md`), 커널 기능(netfilter/xfrm/bridge/WireGuard/crypto API)은 커널 제공본을 사용. 서드파티 백엔드(OpenSSL 등)는 **빌드 타임 옵트인 검증용으로만** 허용하고 기본 빌드는 비활성 | `ldd`에 비libc 동적 의존 0개(기본 빌드). `ngfw selftest platform`이 의존성 감사 출력 |
| R02 | C 중심, 주석 영문, GNU 스타일, C11 준수 | 모든 핵심 코드는 C11(커널 부분은 커널 표준 gnu11). 유저랜드 GNU 코딩 스타일, 커널은 커널 코딩 스타일. 주석/식별자 영문 | 컴파일 `-std=c11 -Wall -Wextra` 0 경고(docs/standards/c11-coding-notes.md). 스타일 검사 스크립트 |
| R03 | 빌드 통일(GNU Make, Autotools, Shell) | Autotools(autoconf/automake) + GNU Make + shell 스크립트만 사용. 커널 모듈은 Kbuild(커널 관례). CMake/Bazel 등 금지 | `./configure && make && make check` 3단계로 전체 빌드(`16-build-deploy.md`) |
| R04 | 가시성: 빌드→설치→실행→모니터링 트러블슈팅 + selftest | 단계별 진단 명령(`ngfw-doctor`, `ngfw selftest`), 구조화 로그, `make check` 유닛 테스트. 모든 기능은 selftest 케이스를 갖는다 | `ngfw selftest all`이 전 기능 검증 통과(`17-testing-selftest.md`) |
| R05 | 플랫폼 이식 | libc 독립 추상화(`platform` 서브시스템), 아키텍처 매트릭스(x86_64/aarch64 우선), autoconf 기능 탐지 | 이식 매트릭스 CI 통과(`15-portability.md`) |
| R06 | 사용자 경험(편의/직관/안정/성능) | 일관된 CLI 문법(동사-명사), 설정 트랜잭션+롤백, 커밋-확인(commit confirm), 명확한 오류 메시지, 기본값 보수적(기본 deny) | `11-management.md` UX 규칙 만족, selftest에 UX 회귀 케이스 포함 |
| R07 | 구조적 설계: 모듈화/느슨한 결합/인터페이스 표준화/파편화 금지 | 관심사별 **단일** 서브시스템만 둔다. 동일 목적의 중복 구현 생성 금지 — 신규 기능은 기존 서브시스템 확장이 우선. 모듈 간 접점은 문서화된 인터페이스(`02-architecture.md` §6)만 허용 | 코드 리뷰 기준 + `02` 모듈 맵 외 신규 컴포넌트 생성 시 ADR 필수 |
| R08 | 계층적 설계: 관심사 분리/레이어 경계/재사용 | L0~L4 계층 정의(`02` §2), 상위→하위 단방향 의존, 역방향은 이벤트 콜백으로만 | include 방향 검사 스크립트(`scripts/check-layering.sh`, `17`) |
| R09 | 확장성: 수평/수직, 플러그인, 미래 대응 | 플러그인 ABI(`19-plugin-architecture.md`), 정책/파서/인증/로그 싱크 플러그인 포인트. 수평 확장은 HA/클러스터(`13`) | 플러그인 적재 selftest, ABI 버전 협상 테스트 |
| R10 | 표준 준수 | 기능↔표준 매핑 표 유지(docs/standards/standards-map.md), 위반 시 예외 사유 기록 | 표준 매핑 표의 "준수 방법" 열이 구현 이슈와 연결됨 |
| R11 | 기능 범위: 풀 기능/타사 호환/고성능/저리소스/오프로드 | 기능 카탈로그(`01-overview.md` F-카탈로그)가 범위의 유일 출처. 타사 호환: Suricata/Snort 시그니처 부분 호환(`07`), RFC 표준 프로토콜 상호운용. 오프로드 매트릭스(`14`) | 카탈로그의 모든 F 항목이 로드맵에 배치되고 selftest 존재 |
| R12 | 커널 모듈: 커널 관례 준수, 6.12+ 호환 | 커널 코딩 스타일, 커널 제공 인프라(netfilter/genetlink/rhashtable/percpu) 사용, deprecated API 금지, 최소 API 표면 | 다중 커널(6.12 이상) 헤더 빌드 매트릭스 통합(`17` §4) |
| R13 | QEMU/KVM/Docker 검증 활용 | 시스템 테스트는 QEMU/KVM 부팅 + 실 트래픽 검증, 이식 매트릭스는 Docker 컨테이너 빌드/테스트(`17` §5~6) | `scripts/qemu-run.sh`로 부팅→정책 적용→트래픽 검증 자동화 |
| R14 | 제품명/모델명/버전 관리 용이 | `VERSION` 파일 단일 출처, 빌드 시 전 산출물에 동일 버전 주입, SemVer 2.0.0 | `ngfw --version`/`ngfw selftest version`이 전 산출물 버전 일치 검증(`20`) |

## 2. 공통 설계 원칙(파생 원칙)

| ID | 원칙 | 내용 |
|---|---|---|
| P-A | 단일 출처(Single Source of Truth) | 이름/버전/기능목록/모듈맵/포맷 정의는 지정 문서 1곳에만 둔다. 중복 서술 금지, 참조만 허용 |
| P-B | 명시적 계약 | 모듈 경계는 헤더+문서로 계약화. 비공개 헤더는 모듈 내부에만 노출(`02` §6) |
| P-C | Fail-fast + 관측 가능성 | 초기화 실패는 즉시 기록 후 상위 정책(fail-open/close)에 따라 동작. 모든 경로는 카운터/로그/이벤트를 남긴다 |
| P-D | 최소 권한 | 데몬은 권한 분리(`18-security-hardening.md`). 커널 인터페이스는 genetlink 권한 검사 |
| P-E | 결정 기록(ADR) | 구조적 선택(예: 자체 conntrack vs nf_conntrack)은 ADR로 기록. 형식: 배경/선택지/결정/결과 |
| P-F | 문서 선행 | 코드 변경 전 해당 설계 문서 갱신. 코드-문서 불일치는 결함으로 분류 |
| P-G | 데이터 우선 검증 | 성능/메모리/커버리지 수치는 측정 절차 문서와 함께 제공. 측정 없는 수치 주장 금지 |

## 3. 주요 구조적 결정(ADR 인덱스)

신규 결정은 아래 표에 추가하고 상세는 해당 문서의 "ADR" 섹션에 기록한다.

| ADR | 결정 | 요지 | 상세 |
|---|---|---|---|
| ADR-001 | 자체 세션 테이블 채택 | nf_conntrack 재사용 대신 자체 세션 테이블(per-CPU hashtable) 구현. 이유: NGFW 확장 필드(app-id/user-id/검사 상태)와 정책 재평가의 원자적 결합 필요. 대가: nftables flowtable 호환 계층 별도 구현 | `03-kernel-dataplane.md` ADR-001 |
| ADR-002 | 하이브리드 검사 구조 | fast path(커널) + deep path(유저랜드 DPI) 2단 구조. 이유: 유저랜드 전처리는 성능 한계, 커널 전체 DPI는 복잡도 폭증 | `04-packet-pipeline.md` |
| ADR-003 | 단일 정적 라이브러리 | 유저랜드 공용 코드를 `libngfw` 하나로 통합(파편화 방지). 서브시스템은 디렉터리+헤더 계약으로 분리 | `02-architecture.md` §7 |
| ADR-004 | IPsec 컨트롤 플레인 자체 구현 + 커널 데이터 플레인 | IKEv2 데몬은 자체 구현, ESP는 커널 xfrm 사용(커널=허용 의존) | `08-vpn.md` |
| ADR-005 | 자체 암호 라이브러리 | TLS/IKEv2/시그니처 무결성 등을 위해 자체 `crypto` 서브시스템 구현. 커널 crypto API(AF_ALG)를 하드웨어 가속 경로로 사용 | `02` §5, `18` |
| ADR-006 | 설정 포맷 = JSON + 스키마 버전 | 파서 단순성/툴 생태계/롤백 diff 용이성. CLI는 트리 문법으로 동일 모델 조작 | `11-management.md` |
| ADR-007 | 원격 관리는 HTTPS(REST/웹터미널), 자체 SSH 서버 미구현 | SSH 서버 자체 구현 비용 대비 HTTPS REST가 자체 스택으로 충분하고 표준 클라이언트 생태계가 큼. 로컬 CLI/콘솔은 유지. 재검토 시 신규 ADR로 | `11-management.md` §1 |

## 4. ADR 작성 형식

```markdown
### ADR-NNN: <제목>
- 배경: <문제/제약>
- 선택지: <대안 1/2/3 + 장단>
- 결정: <선택> (근거)
- 결과: <긍정/부정 효과, 후속 과제>
- 날짜/상태: <YYYY-MM-DD / proposed|accepted|superseded-by ADR-XXX>
```

## 5. ADR 승인 현황

2026-10-23 검토 결과:

| ADR | 상태 | 검토 요약 |
|---|---|---|
| ADR-001 (자체 세션 테이블) | **accepted** | 승인. NGFW 핵심 요구(세션 부착 app-id/user-id/검사 상태, 분류 변경 시 원자적 재평가)가 nf_conntrack 확장 방식으로는 충족 불가하므로 비용 대비 정당. 유의사항 3가지를 수용 조건으로 기록: (1) ngfw/nf_conntrack 병행 시 훅 우선순위 규약 준수(`03` §4) (2) 오프로드 상태는 세션 라이프사이클에 종속(`03` §10) (3) 자체 TCP 상태머신 정확성은 `17` 시나리오/퍼징 테스트로 담보 |
| ADR-007 (원격 관리 HTTPS 전용) | **accepted** | 승인. 자체 SSH 서버 구현 비용(프로토콜+자체 암호 통합+키 관리) 대비 HTTPS REST의 표준 생태계가 유리. 단, 원격 관리 보안이 자체 TLS 스택(ADR-005)에 집중되므로 다음을 의무화: (1) mgmt TLS 경로는 `17` §7 퍼징/보안 테스트 필수 대상 (2) 관리 평면 레이트 제한·감사 로그(`10`, `12`) (3) SSH 서버 도입 요구가 제기되면 신규 ADR로 재검토 |
| ADR-002~006 | accepted | 설계 문서 초판 작성 시 결정된 사항으로 본 검토에서 재확인(추가 이의 없음) |

## Change log

- 2026-10-23: ADR 승인 현황(§5) 추가 — ADR-001/007 검토 승인 및 수용 조건 기록.
- 2026-10-23: 초판 작성.
