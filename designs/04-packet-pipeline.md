# 04. 패킷 처리 파이프라인

## 1. 개요

패킷은 커널 `ngfw.ko`의 단일 파이프라인을 통과한다(v4/v6 공용 로직, 패밀리별 파서만 분기).
2단 구조(ADR-002): fast path(커널 완결)와 deep path(유저랜드 `ngfw-engine` 검사).

```mermaid
flowchart LR
    RX["RX (NIC/RSS)"] --> H1[PREROUTING<br/>zone/prefilter/DNAT]
    H1 --> RT[routing decision]
    RT --> H2[FORWARD<br/>session lookup/create]
    H2 --> V{verdict?}
    V -- deny --> DROP[drop + 카운터]
    V -- pending --> TAP[tap → ngfw-engine]
    V -- allow --> NATP[POSTROUTING<br/>SNAT/마킹]
    TAP --> TX[TX (GSO/TSO)]
    NATP --> TX
```

## 2. 단계별 명세

### 2.1 ingress 분류(PREROUTING)

1. 링크 계층 접점: 라우티드 모드(기본)/브리지 모드 구분. 브리지 모드는 `zone`이 브리지 포트에
   매핑되고 커널 bridge에 위임 후 ngfw 훅이 재진입한다.
2. zone 매핑: 수신 인터페이스→zone(id). 미등록 인터페이스는 `untrusted` 기본 zone.
3. prefilter(선택): artifact의 `prefilter` 규칙(주소/포트/프로토만) — 명백한 deny를 세션 생성 전
   드랍. DoS 레이트 필터도 이 단계(`§6`).
4. DNAT: 규칙 매칭 후 변환, 변환 결과를 세션 키에 반영(정규화 tuple).

### 2.2 라우팅 결정

커널 라우팅 테이블 사용(FIB). `ngfwd`가 netlink로 RIB→FIB 동기화(`09` §2). 라우팅 실패(ICMP
unreachable)는 정책상 drop으로 계수(별도 카운터), `send_redirect` 정책 옵션.

### 2.3 세션 룩업/생성(FORWARD)

- 룩업: 정규화 5-tuple(`03` §5.1). 적중 → verdict 캐시 확인.
- 미적중 → 생성: 정책 매칭(`05` §5)으로 verdict/NAT/inspect 결정.
  - allow + inspect 불필요 → fast path 즉시.
  - allow + inspect 필요 또는 pending-action 규칙 → 세션 verdict=pending, 첫 패킷 tap 인계.
  - deny/reject → 세션 미생성(카운터만). reject는 RST/ICMP unreachable 생성(레이트 제한).
- 생성 실패(한도 초과): `overflow-action`.

### 2.4 verdict 적용

- verdict 캐시의 `gen` 필드가 현재 artifact gen과 다르면 **정책 재평가**(verdict만 재결정, 세션
  유지 — 설정 변경 시 기존 세션의 즉시 차단/허용 변경 반영). app-id 변화로 인한 재평가는 유저랜드
  이벤트 기반(`06` §7).
- deny 시 로깅 조건(정책 `log` 플래그)에 따라 세션 이벤트 발행(동기 출력 금지, 멀티캐스트 큐잉).

### 2.5 egress(POSTROUTING)

- SNAT(세션에 캐시된 바인딩 적용), TTL/홉 리밋, GSO/TSO 분할(오프로드 상태 존중), tx 카운터.

### 2.6 호스트 트래픽(LOCAL_IN/OUT)

관리 평면(SSH 대체 CLI, HTTPS, syslog 발신 등)은 자체 정책 존 `host`로 보호: 관리 소스 ACL,
레이트 제한. 세션 테이블 공유(같은 메커니즘, zone=host).

## 3. 프로토콜 상태 추적

### 3.1 TCP

- 상태머신: SYN/SYN-ACK/ESTABLISHED/FIN1/FIN2/TIME_WAIT/RST. 비정상 시퀀스(아웃오브윈도우 RST,
  이전 세그먼트 재도착)는 카운터 후 폐기 또는 무시(정책 `tcp-strict` 모드, 기본 관대 모드).
- 세션 종료 감지로 즉시 만료(FIN 정상 종료 시 TIME_WAIT 단축).
- 윈도우 스케일/옵션 파싱은 deep path 재조립에 필요한 정보만 커널이 저장(선택: mss/wscale).

### 3.2 UDP/기타

- UDP: 양방향 첫 패킷 기준 단일 상태, 타임아웃 갱신. ICMP 에러 매핑.
- ICMP/ICMPv6: 요청-응답 세션, 에러는 embedded tuple로 원 세션 어핀(`03` §9).
- GRE/ESP 등: session 키에 SPI/콜ID 포함, `08-vpn.md` 연계.

## 4. tap 인계 규칙(deep path)

| 항목 | 규칙 |
|---|---|
| 인계 시점 | 세션 생성 직후(기본), 정책 `reinspect`(중간 재검사), 위협 이벤트 재평가 |
| 인계량 | 첫 N패킷 또는 B바이트까지(정책 `inspect-budget`, 기본 16 pkt/256KiB), 이후 fast path |
| 인계 방법 | NFQUEUE 큐=CPU, mmap 배치 수신(`06` §5) |
| 인계 중 커널 동작 | verdict=pending, tap-verdict-timeout(5s) 후 pending-action |
| verdict 기록 | genl TAP_VERDICT: verdict+app_id+profile 재평가 결과 |
| 재조립 | 커널 미수행, 유저랜드 엔진이 스트림 재조립(`06` §3). 커널은 프래그먼트 완결성만 추적 |

## 5. 예외 경로

| 상황 | 처리 |
|---|---|
| IPv4 프래그먼트 | 첫 프래그먼트만 정책 평가 대상. 세션 키는 unfrag 부분. 후속 프래그먼트는 세션
  매칭(프래그먼트 캐시, TTL 30s)으로 전달, 세션 없으면 드랍. 재조립은 수신 호스트 몫 |
| IPv6 확장 헤더 | 라우팅/홉바이홉 헤더 스킵 파서, 최소 처리. 알 수 없는 헤더는 drop 카운터 |
| MTU 초과 | 커널 기본(PMTUD 전달) 유지, ICMP too-big은 세션 어핀 |
| 세션 이동(CPU 이방) | RCU 조회 후 migration, 드묾 경로 카운터 |
| tap 유저랜드 부재 | pending-action 즉시 적용 + `engine-down` 카운터/경보 |

## 6. DoS/DDoS 방어(커널 단)

| 기능 | 위치 | 설명 |
|---|---|---|
| 신규 세션 레이트 | 세션 생성 단계 | per-zone/per-source 초당 신규 한도(토큰버킷), 초과 drop 카운터 |
| SYN flood | 세션 생성 단계 | SYN 한도 초과 시 SYN 쿠키 방식의 경량 핸들링(응답 후 세션 미생성) |
| ICMP flood | prefilter | 레이트 필터 |
| XDP 사전 필터 | 선택적(M2+) | eBPF XDP 프로그램(빌드 타임 clang 필요 옵션)으로 초고속 ACL. 없어도 기능 손실 없음 |

## 7. fail-open/close 명세

| 값 | 동작 | 기본 |
|---|---|---|
| fail-close | 엔진 다운 시 신규 검사 대상 플로우 deny, 기존 fast path 세션 유지 | **기본** |
| fail-open | 신규 플로우 allow(검사 없음) + 경보 | 설정 옵션 |

- 결정 단위: 정책 `security-profile`의 전역 스위치 + 룰별 예외. 변경은 설정 트랜잭션으로 반영.
- 상태 전환은 genl 이벤트 + `ngfw-doctor` 진단 항목으로 관측(R04).

## 8. 성능 특성 계약

- fast path는 세션 히트 시: 1회 해시 룩업 + verdict 분기 + NAT 변환 + 카운터. 할당/자물쇠 없음
  (버킷 spinlock은 미적중-생성에만).
- deep path 전환은 세션당 1회(재검사 제외) — 유저랜드 지연이 후속 패킷에 전파되지 않음.
- 목표치는 `14-performance-offload.md` §2의 측정 절차로만 검증·기록(P-G).

## Change log

- 2026-10-23: 초판 작성.
