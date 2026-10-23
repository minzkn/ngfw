# 14. 성능 및 오프로드

## 1. 성능 설계 원칙

| 원칙 | 적용 |
|---|---|
| fast path 무할당/무시스템콜 | 세션 per-CPU 캐시, 카운터 per-CPU(`03` §5/§8) |
| 데이터 지향 배치 | NFQUEUE mmap 배치 수신, 이벤트 집계 배치(`06` §5) |
| single-writer | 엔진 스레드 자료구조 소유, 공유는 RCU 읽기(`02` §4.3) |
| 캐시 친화 | 세션 레코드 캐시라인 정렬, 규칙 핫 데이터 분리(`03` §5.1) |
| 컴파일 타임 최적화 | 정책 trie/bitmap 선생성(`05` §5), 시그니처 AC 사전 구축(`07` §2.2) |
| NUMA/IRQ 정렬 | RSS 큐↔tap 스레드↔세션 테이블 정렬, irq affinity 스크립트(`16` §6) |

## 2. 성능 측정 절차(수치의 유일 근거, R-P-G)

1. 기준 하드웨어/VM 스펙 기록(버전별 재측정), 환경 변수(QEMU/KVM/베어메탈) 명시.
2. 트래픽 발생: 자체 `ngfw-tgen`(multi-core 발생, 정확 측정용 타임스탬프) + 필요 시 공개 툴.
3. 시나리오 매트릭스: 64B/1500B L3 포워딩, 신규 세션/s, 동시 세션, HTTP/HTTPS(APP-ID/TLS),
   IPS 적용 시 처리량, HA 동기 오버헤드.
4. 지표: 처리량(packets/s, Gbps), 지연(p50/p99), CPU/메모리, 드랍률. 결과는 `docs/benchmarks/`
   에 측정일/환경과 함께 기록.
5. 회귀 감지: 벤치마크 selftest(짧은 스모크) + 정기 풀 측정.

**모든 문서의 성능 수치는 이 절차의 산출물만 인용한다.** 측정 전 수치는 "목표"로만 표기.

## 3. 오프로드 매트릭스(F14)

| 계층 | 기능 | 사용 위치 | 상태 |
|---|---|---|---|
| NIC | TSO/USO/GSO/GRO/LSRO | 커널 스택 구성 | M1 |
| NIC | checksum offload (TX/RX) | 커널 구성 | M1 |
| NIC | RSS/aRFS | 큐-CPU 정렬 | M1 |
| NIC | flow steering(n-tuple/flow director) | 특정 세션/서비스 고정 | M3 |
| NIC | inline crypto(MACsec/IPsec) | 커널 xfrm offload 구성 | M4 |
| KERNEL | tc flower 세션 오프로드 | `ngfw.ko` offload 서브모듈(`03` §10) | M2 |
| KERNEL | GRO aggregation | 커널 구성 | M1 |
| KERNEL | xfrm crypto offload(AF_ALG/드라이버) | IPsec | M3 |
| eBPF | XDP 사전 필터 | 선택적 빌드 옵션(`04` §6) | M2+ |
| IO | io_uring(관리/로그 IO) | 유저랜드 | M4 |

- 오프로드는 **가속이지 의존이 아니다**: 모든 기능은 SW 경로로도 동작하며, 오프로드 상태는
  `ngfw-doctor`/메트릭으로 가시화(`12` §5).
- 안전 규칙: 검사 필요 세션은 절대 오프로드 금지(`03` §10), 오프로드 해제는 세션 안전 무효화.

## 4. 저리소스 목표(R11)

- 기본 모델(2 vCPU/1GiB)에서: 기본 방화벽+APP-ID+로그, 세션 한도 자동 산식(`03` §3).
- 메모리 예산: 커널 세션 테이블/엔진/시그니처 DB 배분은 기동 시 자원에 따라 스케일(설정 오버라이드).

## 5. 튜닝 절차(운영자 문서 관점)

- `ngfw doctor --perf` : 병목 진단(큐 적체/CPU 분포/드랍 원인).
- 권장 튜닝 세트(IRQ affinity, RPS 설정, 큐 수)는 설치 시 자동 적용 + 수동 오버라이드 문서.

## 6. selftest 연계

`ngfw selftest perf`: 스모크 벤치마크(통과 임계는 측정 기록 대비 하락율 규칙), 오프로드
프로그래밍/폴백 동작. `17` §4.

## Change log

- 2026-10-23: 초판 작성.
