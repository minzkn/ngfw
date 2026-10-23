# netlink / genetlink API 설계 관례 조사

- 문서: `docs/research/netlink-api-notes.md`
- 기준 커널: Linux 6.12 (세부 필드/시그니처는 구현 시점에 `include/net/genetlink.h`, `include/net/netlink.h`에서 재확인 전제)
- 목적: ngfw generic netlink family 계약 설계 전, 커널 측 설계 관행을 정리하고 계약 항목별 부합 여부를 점검
- 표기: `(미검증)` — 문헌/소스 확인 전이라 사실 확인이 필요한 문장

## 1. netlink / genetlink 개요와 구조

### 1.1 netlink 기본 프레이밍

- netlink는 커널↔유저스페이스(및 유저↔유저) 양방향 메시지 버스. `AF_NETLINK` 소켓, 데이터그램 기반(경계 보존, 순서 보장).
- 모든 메시지는 `struct nlmsghdr { len, type, flags, seq, pid }` + payload.
  - `portid`는 프로세스가 아니라 소켓 단위 식별자. 커널 측은 0.
  - `seq`로 요청-응답을 대응. 응답은 요청의 seq를 그대로 복사.
  - 에러/ACK는 `NLMSG_ERROR` 타입 회신. payload의 정수: 양수=errno(실패), 0=ACK.
- 멀티파트 응답: 각 파트에 `NLM_F_MULTI`를 set하고 마지막에 `NLMSG_DONE` 전송.
- 덤프: `NLM_F_DUMP`(ROOT|MATCH) 요청 → 커널이 skb 예산 단위로 끊어 순차 전송, 소켓별 dump 상태 유지.

### 1.2 generic netlink 계층: family / ops / attrs

- 고정 netlink family 번호는 희소 → genetlink는 family를 동적 할당하고 탐색을 내장 컨트롤 family(`nlctrl`, id 16)의 `CTRL_CMD_GETFAMILY`로 수행. 유저는 여기서 family id와 multicast group id를 얻음.
- 요청 payload 선두는 `struct genlmsghdr { cmd, version, reserved }`.
- 계층 구조:
  - **family** (`struct genl_family`): 이름, 동적 id, version, ops 배열, multicast group 목록. 유저 관점의 단위.
  - **ops** (`struct genl_ops`): 명령 단위. `doit`(동기 요청-응답), `dumpit`(이터레이터), `start`/`done`(덤프 준비/정리), `policy`(명령별 attr 검증), flags(`GENL_ADMIN_PERM`, `GENL_UNS_ADMIN_PERM`).
  - **attrs**: TLV. `struct nlattr { nla_len, nla_type }` 반복, 4바이트 정렬. `nla_type` 상위 비트에 `NLA_F_NESTED`/`NLA_F_NET_BYTEORDER` 예약.
- 응답/이벤트 구성 흐름: `genlmsg_new()` → `genlmsg_iput()`(또는 구식 `genlmsg_put()`)로 헤더 기록 → attrs 추가(`nla_put_*`) → `genlmsg_end()` → `genlmsg_unicast()` / `genlmsg_reply()` / `genlmsg_multicast()`.

### 1.3 표준 제어 흐름

1. 커널: `genl_register_family()` — ops, policy, multicast groups를 family에 포함해 등록. 실패 시 모듈 로드를 실패 처리.
2. 유저: `AF_NETLINK, NETLINK_GENERIC` 소켓 → `CTRL_CMD_GETFAMILY`(이름으로 조회) → family id, version, multicast group id 획득.
3. 유저: 요청 조립(`nlmsghdr` + `genlmsghdr` + attrs) 후 `sendmsg()`.
4. 커널 코어: family/cmd 검색 → `.policy` 기반 attr 검증 → op 권한 플래그 체크 → `doit`/`dumpit` 호출.
5. `doit`: 새 skb로 응답을 만들어 `genlmsg_reply()`. `dumpit`: `NLM_F_MULTI` 파트를 이어 보내고 마지막에 `NLMSG_DONE`.
6. 상태 변화는 응답과 별개로 multicast 이벤트로 발행.

## 2. 커널 관행

### 2.1 nla_policy 기반 속성 검증

- op별 `struct nla_policy[]`를 붙이면 커널 코어가 파싱 단계에서 검증: 타입(`NLA_U32`, `NLA_STRING`, `NLA_NESTED` 등), 길이(`NLA_POLICY_EXACT_LEN`, `NLA_POLICY_MAX_LEN`), 범위(`NLA_POLICY_RANGE`), 문자열(`NLA_POLICY_NUL_STRING`) 등.
- genetlink는 기본 strict 파싱: 정책 밖 attr, `nla_type 0`, 잘못된 nested 구조를 즉시 반려. 구형 family용 `nla_parse_nested_deprecated()` 계열 헤퍼가 남아 있으나 신규 코드 사용은 관행상 금지.
- doit/dumpit 진입 후에는 파서가 돌려준 `struct nlattr **`만 사용. 수동 `nla_for_each_attr` 재파싱은 검증 우회가 되므로 지양.
- `NLA_NESTED` + 하위 policy 배열로 트리 구조를 검증. nest 깊이는 실무 관행상 2단계 이내 유지.
- 검증은 fail-fast: `EINVAL`로 즉시 반려하고 부분 적용을 남기지 않음 — 상태 변경(setter) op에서 특히 중요.
- policy는 컨트롤 채널로 introspection 가능(3절 참조) → 코드와 유저 도구가 같은 스펙을 공유.

### 2.2 do / dump ops 분리

- `doit`: 1요청-1응답. 짧은 조회, setter, 제어 명령에 사용. 응답은 요청 skb를 재활용하지 않고 새 skb로 `genlmsg_reply()`, 실패는 errno 회신.
- `dumpit`: 목록 이터레이션. 커널이 skb 예산만큼 끊어 전송하므로 대량 데이터(세션 테이블, 통계)는 반드시 dump로 설계.
  - dump 상태는 `struct netlink_callback`에 저장. `start`에서 락/준비, `done`에서 해제 — 클라이언트 중단/소켓 종료 시에도 커널이 `done` 호출을 보장.
  - dump는 "일관성 스냅샷"이 아니라 순차 스캔. 스캔 중 상태가 변할 수 있음을 계약에 명시하는 것이 관행.
  - 유저는 `NLM_F_MULTI` 체인을 끝까지 읽을 책임이 있고, 커널 재개 호출에 대비해 dump 진행 상태를 재진입 가능하게 유지.
- 덤프 요청에 필터 attr이 필요하면 dump op에도 `.policy`를 지정.

### 2.3 GENL_ADMIN_PERM 권한

- `GENL_ADMIN_PERM`: init 네임스페이스 기준 `CAP_NET_ADMIN` 요구. `GENL_UNS_ADMIN_PERM`: family가 등록된 네트워크 네임스페이스를 소유한 userns 기준 — 컨테이너 지원 관행상 신규 family는 UNS 계열 선호. (정확한 체크 경로는 `net/netlink/genetlink.c` 확인 요함, 미검증)
- 관례: 변경(setter) 명령과 민감한 조회는 op 단위 플래그로 보호. 통계/세션 dump도 노출 민감도에 따라 보호 대상.
- multicast 구독에는 op 권한 플래그가 적용되지 않음 → 이벤트 payload에 기밀 데이터 금지.

### 2.4 multicast group 이벤트

- `struct genl_multicast_group` 배열을 family에 연결. 유저는 group **이름**으로 구독하고 id는 CTRL 응답으로 매핑.
- 이벤트 skb: `genlmsg_iput(skb, 0 /* portid */, 0 /* seq */, family, hdrlen, 0 /* flags */, cmd, version)` → attrs → `genlmsg_end()` → `genlmsg_multicast(&family, skb, 0, group, GFP_KERNEL)`.
- 관례: 이벤트는 요청-응답 채널과 독립. 상태 변화의 사실만 전달하고, 요청에 대한 성공/실패 회신은 unicast로만.
- 유실 감지를 위해 monotonic 시퀀스/세대(generation) 번호 attr 포함이 좋은 관행. 이벤트 발행 실패(메모리 부족, 수신 큐 오버플로)는 유실로 이어지므로 소비자는 seq 갭으로 이를 탐지.
- 그룹은 논리 이벤트 클래스 단위로 분할 가능 — 커널은 그룹 단위 구독만 지원하므로 세분 필터링이 필요하면 그룹을 나누는 설계가 일반적.

### 2.5 버전 관리 (genl_info / family version)

- family 단위 버전은 `genl_family.version`이고 genlmsghdr에 실려 전달. 커널 코어는 값을 검증하지 않고 전달만 하므로 각 op doit이 `info->genlhdr->version`을 확인해야 함.
- 관례:
  - 지원하지 않는 version → `EINVAL`/`EOPNOTSUPP`로 반려. "무시하고 처리" 금지.
  - 상위 버전은 하위 버전 메시지를 수용(하위호환). 신규 attr 추가는 optional로 하여 구버전 클라이언트에 영향 없게.
  - wire 포맷 비호환 변경 시 version bump가 원칙. family version만 불충분하면 cmd별 version 정책을 문서화.
  - 이벤트에도 동일 version을 기록해 소비자가 발신자 버전을 판별 가능하게 유지.
- VERSION 전용 op는 ABI 자기기술 수단으로 관행에 부합(devlink, nl80211 등도 family version + 문서 병용).

## 3. 커널 6.12 기준 주의점

- **YNL YAML 스펙 기반 코드젠**: `Documentation/netlink/specs/*.yaml`이 다수 family의 uAPI 헤더와 유저 도구의 생성 원천으로 확산. 신규 family는 YAML 스펙 작성이 사실상 표준. (미검증: 6.12 기준 커버리지)
- **`genlmsg_iput()`** (≈6.3+): family 포인터 기반 헬퍼로 수동 family id 지정 회피. (미검증: 정확한 시그니처)
- **strict 파싱 기본**: 신규 family는 자동 strict. deprecated 헤퍼와 `NLA_UNSPEC` 남용을 회피할 것.
- **`resv_start_op`**: genl_family가 미지원 명령 경계를 선언해 커널이 `EOPNOTSUPP`로 일괄 반려 — capability 탐지가 단순화됨. (미검증: 6.12 적용 범위/의미)
- **정책 introspection**: `CTRL_CMD_GETPOLICY`(5.3 전후 도입)로 attr policy를 컨트롤 채널로 내보낼 수 있음 → op별 `.policy`를 정확히 채워두면 유저 도구의 자동 검증이 가능. (미검증)
- **크기/정렬 계산**: attr 크기는 `nla_total_size()` 계열로만 계산. 64bit 정렬 attr 혼용 시 패딩 차이 주의. (미검증: 헬퍼 도입 시점)
- **객체 수명**: 이벤트 skb는 수신자별 복사본이므로 커널 객체 포인터를 attrs에 넣지 말 것 — 값/식별자만 전달.
- **deprecated/폐기 회피 목록**: `genl_register_family_with_ops`(폐기 — ops는 family에 포함), 수동 attr 파싱, 응답 없는 doit, skb 재사용, `NLA_MAX` 기반 고정 배열.
- 커널 내부 API는 마이너 버전마다 변동. 위 항목은 구현 전 해당 트리 소스에서 확정할 것. (미검증)

## 4. ngfw family 설계 점검표

계약(현재 정의): family `ngfw` v1, ops 1~10, staging→activate 2단 정책 스왑, multicast `ngfw-events`, TLV 이벤트 타입 1~6.

평가 기준: 2절의 관행 항목 각각에 대해 부합 / 주의 / 미정으로 분류.

| 항목 | 계약 | 관행 부합 평가 | 개선 제안 |
|---|---|---|---|
| family `ngfw` v1 | 이름 문자열 + version 1 | 부합 — 동적 id + 이름 탐색 표준 | YNL YAML 스펙 병행, `version=1` 상수 정의 |
| ops 1~10 | cmd 1부터 연속 배치 | 부합 — 0 미사용은 strict 호환 | enum 끝에 sentinel 두고 번호 영구 고정/재사용 금지 원칙 명시 |
| PING(1) | 무인가 keepalive | 부합 | 응답에 내부 지표(세션 수 등) 미포함 — 무인가 노출 방지 |
| POLICY_LOAD(2) | staging 테이블 기록 | 부합 — validate-then-swap 전반부 | `GENL_UNS_ADMIN_PERM` + strict policy 적용, 실패 시 staging 파기 여부를 계약에 명시 |
| POLICY_ACTIVATE(3) | staging→active 스왑 | 부합 — RCU 포인터 스왑 패턴과 일치 | 스왑 후 generation 증가 + 이벤트 발행, 동시 activate는 직렬화 |
| SESSION_DUMP(4) | 세션 목록 조회 | 부합 — 규모상 dumpit 필수 | `start/done`으로 세션 락 획득/해제, 덤프 중 상태 변경 허용임을 명시 |
| SESSION_FLUSH(5) | 세션 전체 제거 | 부합 | `GENL_UNS_ADMIN_PERM`, scope attr(전체/단일)로 과잉 삭제 방지 |
| STATS_DUMP(6) | 통계 조회 | 부합 | 카운터는 per-CPU/atomic 스냅샷으로 수집, overflow 정책 문서화 |
| TAP_CONFIG(7) | TAP 설정 setter | 부합 | 멱등 동작 보장, 적용 후 현재값 회신, `NLA_POLICY_RANGE`로 값 상한 강제 |
| OFFLOAD_SET(8) | 오프로드 토글 | 부합 | 동일 setter 관행 적용, 실패 시 partial state 없음 보장 |
| VERSION(9) | ABI 확인 | 부합 | build/git 식별자·지원 이벤트 타입 비트맵 포함 권장 |
| TAP_VERDICT(10) | 방향 미명시 | **주의** — genl op은 유저→커널 요청만 담당 | 커널→유저 통보면 이벤트(notify), 유저 확정이면 op. 방향을 계약에 명확히 기술할 것 |
| staging→activate 2단 스왑 | 무중단 정책 교체 | 부합 | activate 이벤트에 old/new generation 기록, 실패 시 staging 보존 정책 문서화 |
| multicast `ngfw-events` | 단일 그룹 | 대체로 부합 | 이벤트량 증가 시 그룹 분할(policy/session/tap) 검토 |
| TLV 이벤트 타입 1~6 | 1부터 연속 배치 | 부합 — 0 예약 관행 준수 | 타입별 의미 문서화, 중간 삽입/재사용 금지, 부수 attr(seq, generation, timestamp) 표준화 |

### 종합 개선 제안

1. ops/TLV 번호 원칙을 계약서에 명시: "번호 영구 고정, 미사용 번호 재사용 금지, 신규는 끝에 추가" — netlink uAPI 관행의 핵심.
2. op별 `.policy` 전수 정의 + 필요 op에 `GENL_UNS_ADMIN_PERM`. 현재 계약에 권한 플래그가 명시돼 있지 않으므로 추가 권장.
3. `TAP_VERDICT` 방향 재검토가 1순위 설계 리스크 — op과 이벤트 중 어느 쪽인지 계약서에서 확정.
4. 이벤트 공통 프리앰블 `{event_type, seq, generation}` 도입으로 유실 감지와 정책 스왑 추적을 한 번에 해결.
5. YAML(YNL) 스펙을 관리 대상에 포함해 userspace 도구와 테스트가 같은 스펙을 공유하게 유지.

### 설계 시 확정 필요 항목

- `TAP_VERDICT`의 방향과 payload 소유자(커널 생성 vs 유저 생성).
- `SESSION_FLUSH`의 scope attr 도입 여부.
- staging이 이미 존재할 때 `POLICY_LOAD`의 동작(교체 vs 거부) — 계약 미정의.
- 이벤트 그룹 분할 기준(이벤트율 임계값과 판정 주체).

## Change log

- 2026-10-23: 초판 작성.
