# 03. 커널 데이터플레인 (`ngfw.ko`)

## 1. 목적/범위

커널 모듈 `ngfw.ko`는 fast path를 담당한다: 세션 테이블, 정책 실행, NAT, tap 인계, 통계, 오프로드
연계, `ngfwd`와의 genetlink 제어 채널. 유저랜드 검사(DPI/IPS)는 포함하지 않는다(`06`).

설계 제약(R12): 커널 코딩 스타일 준수, 커널 제공 인프라(netfilter/genetlink/rhashtable/percpu) 사용,
최소 지원 커널 6.12 이상 전 호환, deprecated API 사용 금지.

## 2. 모듈 구성(단일 모듈 원칙)

파편화 방지(R07)에 따라 커널 모듈은 `ngfw.ko` 하나이며, 내부 서브모듈은 다음과 같다:

| 서브모듈 | 책임 | 파일(Kbuild 단위 소스) |
|---|---|---|
| main | 로드/언로드, 파라미터, 상태머신 | `kernel/main.c` |
| hook | netfilter 훅 배치/디스패치 | `kernel/hook.c` |
| session | 세션 테이블/생명주기/GC | `kernel/session.c` |
| policy | artifact 해석/매칭/RCU 교체/카운터 | `kernel/policy.c` |
| nat | SNAT/DNAT/NPTv6 포트 풀 | `kernel/nat.c` |
| tap | NFQUEUE 인계/pending-action | `kernel/tap.c` |
| genl | genetlink family/ops/이벤트 | `kernel/genl.c` |
| stats | per-CPU 카운터/덤프 | `kernel/stats.c` |
| offload | 세션 단위 tc flower 오프로드 | `kernel/offload.c` |

## 3. 로드/초기화

- 모듈 파라미터(부팅 고정값, 런타임 변경은 genl로):
  - `session_buckets` (기본: `2^17 × nr_cpus`), `session_max`(기본: 1M/1GiB RAM 기준 산식),
    `tap_queues`(기본 nr_cpus), `default_pending`(deny|accept, 기본 deny), `hw_offload`(bool).
- 초기화 순서: 통계 → 세션 테이블 → 정책(빈 artifact = 모두 deny) → genl → netfilter 등록.
- 언로드: tap 차단 → 훅 해제 → 세션 드레인(타임아웃 즉시화) → genl 해제. 오류 시 자체 해제 후
  기본 커널 포워딩이 복원되도록 부수효과(마스킹/마크) 정리를 보장한다(`02` §9).

## 4. netfilter 훅 배치

`nf_inet_hooks` 기준 v4/v6 공용 등록(`register_netfilter_notifier` 아님, `nf_register_net_hook`):

| 훅 | 우선순위 | 동작 |
|---|---|---|
| PREROUTING | NF_IP_PRI_NGFW_PRE(= -200, conntrack보다 앞) | ingress zone 분류, 사전 ACL(prefilter), DNAT, 세션 룩업 준비 |
| FORWARD | NF_IP_PRI_NGFW_FWD(= 0) | 세션 확정/생성, 정책 verdict, tap 인계, 검사 플래그 |
| POSTROUTING | NF_IP_PRI_NGFW_POST(= +150) | SNAT, 오프로드 대상 마킹, TX 카운터 |
| LOCAL_IN / LOCAL_OUT | NGFW_PRI | 호스트(관리 평면) 트래픽 정책 |

- 커널 conntrack(nf_conntrack)과의 공존: 기본 구성에서 ngfw는 **conntrack 비사용**(ADR-001).
  사용자가 nftables/conntrack을 병행하는 경우 우선순위 조정 파라미터로 배치 순서를 문서화.
- 마크 사용 규약: skb->mark 비트 필드 `[31:28]=ngfw-magic, [27:16]=zone-id, [15:0]=class-id`.
  문서화 후 변경 시 genl 버전 증가.

## 5. 세션 테이블

### 5.1 데이터 구조

```c
/* Per-flow connection state record (kernel). Aligned to 64B cache line groups. */
struct ngfw_session {
	struct hlist_node	s_node;		/* per-CPU bucket chain */
	struct rcu_head		s_rcu;		/* deferred free */
	struct ngfw_tuple_tuple	tt;		/* canonical 5-tuple (v4/v6) */
	u16			zone_in;	/* ingress zone id */
	u16			zone_out;	/* egress zone id (resolved at first fwd) */
	u8			proto;		/* IPPROTO_* */
	u8			state;		/* NGFW_SESS_* state machine */
	u8			verdict;	/* cached action: allow/deny/pending */
	u8			flags;		/* NGFW_SF_* (nat, tap, ha-sync, offload) */
	u32			app_id;		/* last known application id (0=unclassified) */
	u32			user_id;	/* bound user id (0=anonymous) */
	u32			profile_bits;	/* attached profile bitmask */
	u32			gen;		/* policy generation at verdict */
	u32			sync_id;	/* HA session sync id */
	u64			pkt_in, byte_in;
	u64			pkt_out, byte_out;
	u64			expire;		/* jiffies timeout (per-proto/state) */
	struct ngfw_nat		nat;		/* NAT binding (when NGFW_SF_NAT) */
};
```

- 키: 정규화 5-tuple(방향 무관 정규화: 작은 쪽 우선 비교). 역방향 조회는 정규화로 동일 버킷 적중.
- 테이블: per-CPU hashtable(버킷 spinlock, 체인). 패킷은 ingress CPU에서 처리되므로(RSS 정렬
  가정) 로컬 적중이 기본; 역방향 패킷이 다른 CPU에 도착하면 원격 CPU 테이블을 RCU 읽기로 조회 후
  필요 시 세션 이동(migration, 드묾 경로)한다.
- 할당: per-CPU slab 캐시(fast path 무할당). 한도 초과 시 `session_full` 카운터 증가 + 정책의
  `overflow-action`(deny 기본) 적용.
- GC: per-CPU delayed work, 1s 주기. 만료 세션은 HA 동기화 대상이면 tombstone 브로드캐스트 후
  `call_rcu`/`kfree_rcu` 해제.

### 5.2 상태머신/타임아웃

| 프로토콜 | 상태 | 기본 타임아웃(변경 가능) |
|---|---|---|
| TCP | SYN_SENT 60s / ESTABLISHED 3600s / FIN_WAIT 120s / TIME_WAIT 30s / RST 즉시 | 정책별 오버라이드 |
| UDP | 단일 상태 30s(스트림형 180s 옵션) | - |
| ICMP/ICMPv6 | 요청-응답 매칭 10s | - |
| 기타(GRE 등) | 120s | - |

타임아웃은 policy artifact의 `session-profile` 섹션으로 주입한다(`05` §8).

## 6. 정책 실행 요약(fast path 최소 작업)

fast path에서 MUST NOT: 메모리 할당, 로그 동기 출력, 해시 재계산 다중화, spinlock 장기 홀드.
수행 목록: L2/L3 체크섬 검증(오프로드 상태 존중) → zone 분류 → prefilter → 세션 룩업 →
verdict 적용 → NAT → 카운터. 상세 파이프라인은 `04-packet-pipeline.md`.

## 7. genetlink API (family `ngfw` v1)

유일한 커널 제어 계약(P-B). 유저랜드 `kapi` 서브시스템이 유일 클라이언트이다(`02` §6).

### 7.1 ops 테이블

| cmd | 이름 | 권한 | 요청 attrs | 응답 |
|---|---|---|---|---|
| 1 | PING | - | - | kernel version, cap flags |
| 2 | POLICY_LOAD | GENL_ADMIN_PERM | artifact blob(페이지 분할), size, crc32 | generation assigned |
| 3 | POLICY_ACTIVATE | GENL_ADMIN_PERM | generation | 이전 gen, 스왑 완료 시각 |
| 4 | SESSION_DUMP | GENL_ADMIN_PERM | 필터(tuple prefix) | 세션 레코드 스트림 |
| 5 | SESSION_FLUSH | GENL_ADMIN_PERM | 필터 | 제거 수 |
| 6 | STATS_DUMP | - | - | per-CPU 카운터 집계 |
| 7 | TAP_CONFIG | GENL_ADMIN_PERM | queue 수, queue→cpu 매핑 | 적용 결과 |
| 8 | OFFLOAD_SET | GENL_ADMIN_PERM | session id, enable/disable | 결과 |
| 9 | VERSION | - | - | 모듈 버전(genl 계약 버전) |

- 모든 요청은 `nla_policy`로 검증, 미지원 cmd는 `-EOPNOTSUPP`.
- POLICY_LOAD는 staging → POLICY_ACTIVATE로 2단 분리(원자적 RCU 스왑). 활성 중 이전 artifact는
  참조 카운트 소진 후 해제.

### 7.2 multicast group

- 그룹 `ngfw-events`: 세션 이벤트(생성/만료/verdict 변경), 통계 문지름(1s 집계), 정책 스왑 완료,
  자원 임계 경보. 레이트 리밋: 그룹별 초당 최대 이벤트 수(기본 1024), 초과 시 집계 이벤트로 합침.

### 7.3 이벤트 페이로드(TLV, TLV 유형 표는 `03`과 유일 계약)

| type | 필드 | 비고 |
|---|---|---|
| 1 | event_kind(u8), session_id(u32), gen(u32) | 세션 이벤트 공통 헤더 |
| 2 | tuple(정규화) | - |
| 3 | verdict(u8), app_id(u32), user_id(u32) | verdict/app/user 변경 |
| 4 | counters(집계 구조) | 통계 문지름 |
| 5 | policy gen swap 정보 | - |
| 6 | 경보(kind, 임계, 현재값) | 자원/성능 경보 |

## 8. tap 인계(NFQUEUE)

- 큐 번호 = CPU 번호(RSS 정렬). `tap_queues`만큼 등록, mmap mode 유저랜드(`06` §5).
- 인계 조건: 세션 생성 직후 첫 패킷, 또는 정책 `inspect` 플래그(재검사), 또는 bytes/packets
  임계 도달(심층 검사 재개).
- 인계 후 세션 verdict = `pending`; 커널은 `tap-verdict-timeout`(기본 5s) 내 유저랜드 verdict
  미수신 시 pending-action 적용(deny 기본). 유저랜드 verdict는 genl TAP_VERDICT(cmd 10)로 기록.
- 패킷 소유권: 커널→유저랜드 인계 동안 커널은 skb 참조 유지, verdict 수신 시 처리 재개.

## 9. NAT 서브모듈

- SNAT: postrouting, per-zone 아웃바운드 풀(IP 집합 + 포트 범위). 포트 할당: per-CPU 커서 →
  고갈 시 전역 조정(잠금 최소화). 세션 생성 시 확정 후 세션에 캐시(패킷마다 재할당 없음).
- DNAT: prerouting, 정책 rule의 nat 섹션. port forwarding/리다이렉션 포함.
- NPTv6(RFC 6296): prefix translation, 무상태 구현.
- ICMP 에러의 세션 어핀(NAT 내부 호스트 에러): embedded tuple 역변환 후 매칭(`04` §5).

## 10. 오프로드 연계(`14`와 분담)

- 기준: ESTABLISHED + verdict allow + 검사 완료 + NAT 고정 + 수명 임계(기본 10s) 충족 세션만
  `offload.c`가 tc flower 규칙(ndo_setup_tc)으로 NIC에 요청. 검사 요구 플로우는 오프로드 제외.
- 오프로드 중에도 커널 세션은 유지(카운터/만료/HA 목적). NIC 카운터 주기 폴링으로 동기화.
- 실패/미지원 드라이버: SW fast path로 즉시 폴백(기능 차단 없음).

## 11. 커널 6.12+ 호환 규칙

| 항목 | 규칙 |
|---|---|
| 사용 API | nf_register_net_hook, genl_register_family(+nla_policy), percpu alloc, rhashtable(전역 룩업 필요 시), kfree_rcu/call_rcu, tc flower(ndo_setup_tc), skb 확장 검사 API |
| 금지 | deprecated 별칭(__exit/__init 외 구형 매크로), 직접 sk_buff 내부 재해석, 모듈 로컬 시스템콜 우회, 개별 netdev priv 오프셋 접근 |
| 빌드 | Kbuild + `ccflags-y` 최소화, `MODULE_LICENSE("GPL")`, `MODULE_VERSION`은 `20`의 VERSION 산출물 주입 |
| 스타일 | Linux 커널 코딩 스타일(checkpatch 유사 검사 스크립트, `17`) |

## 12. ADR-001: 자체 세션 테이블 채택

- 배경: NGFW 확장 필드(app-id/user-id/검사 상태/HA sync)와 정책 재평가의 원자적 결합 필요.
- 선택지: (a) nf_conntrack 재사용+확장 — 커널 의존 심화, 재평가 원자성 약함 (b) 자체 구현 —
  초기 비용 있으나 필드/생명주기 완전 제어 (c) nftables flowtable 의존 — HW 오프로드 공짜이나
  세션 확장 불가.
- 결정: (b) 자체 구현 + (c)의 효과는 `offload.c`가 tc flower로 직접 달성(§10).
- 결과: 커널 코드량 증가, 대신 커널 버전 의존 최소화와 HA 동기화 단순화. nf_conntrack 공존 규약은 §4.
- 날짜/상태: 2026-10-23 / accepted(검토 승인. 수용 조건은 `00-principles.md` §5).

## 13. selftest 연계(F15)

`ngfw selftest kernel` 케이스 목록: genl PING/VERSION, POLICY_LOAD→ACTIVATE→SESSION_DUMP
왕복, 세션 생성/만료(테스트 인터페이스), tap verdict 타임아웃 동작, NAT 바인딩, 통계 증가, 오프로드
프로그래밍 성공/폴백. 상세 절차는 `17-testing-selftest.md` §4.

## Change log

- 2026-10-23: 초판 작성.
