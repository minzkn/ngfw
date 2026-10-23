# 패킷 오프로드 기법 조사 (Packet Offload Techniques)

- 문서 상태: 초판 (2026-10-23)
- 범위: 리눅스 커널이 제공하는 패킷 오프로드(NIC / 커널 fast path / eBPF) 정리와 ngfw offload 설계의 정합성 검증
- 용어: fast path = 커널 세션 캐시 경로, session = 5-tuple 커널 상태, offload 서브모듈 = ngfw.ko의 offload 서브모듈
- 주의: 커널 버전·경로 표기 중 확신이 없는 것은 (미검증)으로 표기했다. git 로그/문서 대조는 별도 검증 단계에서 수행.

## 1. NIC 오프로드 (NIC Offload)

### 1.1 세그멘테이션/병합: TSO, USO, GSO, GRO, LSO

| 기법 | 방향 | 수행 주체 | 의미 |
|------|------|-----------|------|
| TSO (TCP Segmentation Offload) | TX | NIC | MSS보다 큰 TCP skb를 NIC가 MSS 단위로 분할 |
| USO (UDP Segmentation Offload) | TX | NIC | UDP 분할. 소프트웨어 UDP GSO(UDP_SEGMENT)는 4.18 전후, NIC USO는 그 이후 (미검증) |
| GSO (Generic Segmentation Offload) | TX | 커널(소프트웨어) | NIC 미지원 시 스택이 동일한 분할을 대행 |
| GRO (Generic Receive Offload) | RX | 커널(소프트웨어) | 수신 segment를 큰 skb로 병합 후 스택에 전달 |
| LRO (Large Receive Offload) | RX | NIC | GRO의 하드웨어 대응물 (포워딩 시 헤더 정보 손실로 권장되지 않음) |
| LSO (Large Send Offload) | TX | NIC | TSO의 벤더 명칭 (일부 NIC/드라이버에서 사용, LSOv2 등 변형 존재) |

경계 (boundary):

- 소프트웨어 GSO: 스택 내부 skb 상태에서 분할. NIC 지원 여부와 무관하게 항상 가능.
- 하드웨어 TSO/USO: NIC descriptor 단계에서 분할. NETIF_F_TSO 등 feature 비트와 드라이버 지원에 의존.
- wire 상으로는 항상 MSS/L2 MTU 이하 단위. 차이는 "누가, 스택의 어느 시점에서 나누는가"뿐.
- 검사 관점: RX 병합(GRO)은 스택 진입 전에, TX 분할(TSO/USO)은 검사 이후 마지막에 일어난다. 검사기가 보는 skb 크기는 달라질 수 있으나 per-packet 의미(IP ID, TCP seq, checksum 책임 소재)는 커널이 일관성 있게 관리하므로 검사 자체와 충돌하지 않는다.

### 1.2 Checksum offload

- TX: skb의 ip_summed = CHECKSUM_PARTIAL로 표시하고 NIC가 최종 checksum을 완성 (NETIF_F_HW_CSUM / IP_CSUM / IPV6_CSUM).
- RX: NIC가 검증 결과를 skb에 표시 (CHECKSUM_UNNECESSARY). 호스트는 재계산을 생략.
- 상호 의존: TSO/USO는 checksum offload와 함께 동작할 때 의미가 있고(NIC가 segment마다 재계산), GRO는 RX checksum 검증 결과를 전제로 병합을 허용한다.
- ngfw 관점: 검사기가 skb payload를 수정하면 checksum offload의 전제가 깨지므로, 수정 후에는 소프트웨어 재계산으로 되돌려야 한다.

### 1.3 RSS / aRFS (큐-CPU 정렬)

- RSS (Receive Side Scaling): NIC가 4-tuple 해시로 RX queue를 선택하고, IRQ affinity 설정으로 각 queue를 CPU에 매핑. 목표는 동일 session을 동일 CPU에서 처리해 캐시/락 지역성 확보.
- aRFS (accelerated RFS): 소프트웨어 RFS(소비 애플리케이션이 있는 CPU로 steering)를 NIC의 flow steering 테이블로 가속. CONFIG_RFS_ACCEL + 드라이버 지원 필요 (드라이버 인터페이스명 (미검증)).
- flow director / n-tuple filter: 벤더 명칭(Intel 계열). 5-tuple 또는 부분 필드 매치로 특정 RX queue에 steering. ethtool nfc (ethtool -N)로 관리.
- ngfw 관점: steering은 "정책 우회"가 아니라 "처리 위치 선택"이므로 검사 요구와 충돌하지 않음. 다만 queue 배치가 session 처리 CPU와 어긋나면 ngfw.ko session 락 경합과 캐시 미스가 커지므로, IRQ affinity를 fast path 지역성 정책과 정렬해야 한다.

## 2. 커널 오프로드 (Kernel Fast Path)

### 2.1 nftables flowtable

- nf_flow_table: ESTABLISHED session을 flowtable 엔트리로 등록하고, 이후 패킷을 netfilter hook 대부분을 우회하는 소프트웨어 fast path로 처리한다 (routing decision 캐시 재사용, ct timeout 갱신은 유지).
- software flowtable: 커널 스택 안에서만 fast path. 도입 시점 4.16 전후 (미검증).
- hardware flowtable: 드라이버가 ndo_setup_tc의 TC_SETUP_FT를 지원하면 flowtable 엔트리가 NIC로 offload되어 호스트를 완전히 우회하는 스위칭이 된다.
- 함정: flowtable은 "연결 전체"를 자동 등록하며, 우회 대상에 netfilter 검사 hook이 포함된다. 검사 필요 세션이 등록되면 검사가 영구 우회된다.

### 2.2 tc flower 하드웨어 오프로드 (ndo_setup_tc)

- tc flower classifier의 hw offload: 드라이버가 ndo_setup_tc(TC_SETUP_CLSFLOWER)를 구현하면 5-tuple 매치 규칙이 NIC의 TCAM/flow table에 프로그래밍된다.
- 선행 조건: ethtool의 hw-tc-offload feature 활성화 + 드라이버 지원 (mlx5, nfp, bnxt 계열 등에서 구현, (미검증: 정확 드라이버 목록)).
- 동작 모델: 규칙에 매치한 패킷은 NIC에서 steering/처리하고, 매치하지 못한 패킷은 기존대로 호스트 스택으로 들어온다. 즉 기본 경로는 항상 호스트이며, 프로그래밍된 세션만 가속된다.
- 프로그래밍 주체: 사용자 공간 tc 명령 또는 커널 내부 서브시스템(flowtable이 TC_SETUP_FT로 재사용하는 경우).
- 제약: TCAM/flow table 용량 한도, 규칙 추가/삭제가 커널 session 수명과 동기화되어야 함(aging mismatch 시 잔재 규칙이 의도치 않은 fast path를 만든다).

### 2.3 xfrm 암호 오프로드 (IPsec ESP)

- xfrm_state에 hw offload 플래그를 지정하면 드라이버의 xfrmdev_ops(ndo_xfrm_dev_state_add/delete 계열)가 ESP 암복호를 NIC에 프로그래밍한다 (인터페이스 상세 (미검증)).
- inline 모델: NIC가 복호화한 평문을 호스트 스택으로 전달하므로, 호스트는 평문에 대해 정책/검사를 계속 수행할 수 있다.
- 정책 우회 없음: SA(Security Association) 단위 offload이며 xfrm 정책 판단은 커널에 남는다.
- ngfw 관점: ESP 종단인 NGFW에서 복호화 이후 검사는 호스트에서 수행되므로 검사 요구와 충돌하지 않는다. 다만 offload SA 경로와 비-offload SA 경로의 처리 차이를 검사기가 인지해야 한다.

## 3. eBPF

### 3.1 XDP

- XDP (eXpress Data Path): 드라이버 RX 단계(skb 할당 이전)에서 동작하는 프로그램. drop/forward/redirect를 최고 속도로 수행.
- generic XDP: skb 할당 이후 스택 초입에서 실행. 드라이버 지원이 불필요하지만 성능 이득이 제한적.
- native XDP: 드라이버 지원(ndo_xdp 계열) 시 skb 이전에 실행. 실질적인 성능 모델.
- multi-buffer XDP: jumbo frame 지원이 점진 확대되는 중 (버전별 상태 (미검증)).

### 3.2 AF_XDP

- XSK(UMEM) 기반 raw 패킷 소켓. zero-copy 모드에서 패킷을 유저 공간으로 직접 전달.
- 용도: 고속 수집/포워딩/부하 분산. 커널 스택과 session 상태를 공유하지 않는다.

### 3.3 제약 (트래킹/세션 유지 어려움)

- XDP는 netfilter/conntrack 이전에 동작하므로, XDP가 drop/forward한 패킷은 커널 session(연결 추적)에 반영되지 않는다.
- session 상태를 유지하려면 BPF map에 자체 5-tuple 상태를 구현해야 하고, 이는 커널 상태와의 이중화 및 불일치(divergence)를 구조적으로 유발한다.
- L7 검사, 재조립(reassembly), NAT, 정책 엔진 결합이 사실상 불가능하므로 검사 필요 세션의 오프로드 대상으로 부적합하다.
- 적합 용도: 사전 필터(DDoS 완화, bogon drop), 부하 분산. "session 단위 오프로드"가 아니라 "패킷 단위 선처리"로만 평가해야 한다.

## 4. 커널 6.12+ 기준 각 기법 상태

아래 상태는 커널 git 로그/릴리스 노트와 직접 대조하지 않은 일반 지식 기반 정리이다. 버전 특정 주장은 (미검증) 표기를 유지한다.

| 기법 | 6.12+ 상태 | 비고 |
|------|------------|------|
| GSO/GRO | 안정 (오래 표준) | BIG TCP/GSO max size 확대는 6.1 전후 도입 (미검증) |
| TSO/USO | 안정, USO 지원 드라이버 확대 중 | USO 도입 버전 (미검증) |
| checksum offload | 안정 | 표준 경로 |
| RSS/aRFS | 안정 | aRFS는 드라이버 편차가 큼 |
| flow director/n-tuple | 안정 | 벤더별 UI 차이 (ethtool nfc) |
| nftables flowtable (SW) | 안정 | 장기 표준 fast path |
| flowtable HW offload (TC_SETUP_FT) | 일부 드라이버 지원 | mlx5/nfp 계열 중심 (미검증: 드라이버 목록) |
| tc flower HW offload | 성숙 | ndo_setup_tc + hw-tc-offload |
| xfrm ESP offload | 성숙 | inline/full offload 구분은 드라이버별 |
| XDP (generic/native) | 안정 | multi-buffer 지원은 드라이버별 편차 |
| AF_XDP | 안정 | zero-copy는 드라이버별 |

해석: 6.12 시점에서 세션 단위 프로그래밍/삭제에 가장 잘 맞는 인터페이스는 tc flower HW offload이다. flowtable HW offload는 "연결 전체 자동 등록" 모델이라 검사 정책과 조합이 어렵고, XDP는 상태 유지 모델 자체가 커널 session과 다르다.

## 5. ngfw offload 매트릭스 대응 검증표

검증 기준은 ngfw.ko의 offload 서브모듈이 채택한 설계 명제이다.

설계 명제:

1. 검사 필요 세션 — 절대 오프로드 금지.
2. ESTABLISHED + allow + 검사 완료 세션만 tc flower 프로그래밍.
3. 프로그래밍 실패 시 SW 폴백 (호스트 경로 유지).

| 기법 | 명제 1과의 정합성 | 명제 2/3과의 정합성 | 판정 |
|------|-------------------|---------------------|------|
| TSO/USO/GSO/GRO/LSO | 양립 (RX 병합은 검사 전, TX 분할은 검사 후) | 무관 (정책 우회가 아님) | 충돌 없음 |
| checksum offload | 양립 (payload 수정 시 소프트웨어 재계산으로 복귀) | 무관 | 충돌 없음 |
| RSS/aRFS/flow director | 양립 (처리 위치 선택일 뿐) | 양립 (선호 큐 지정과 결합 가능) | 충돌 없음 |
| nftables flowtable (SW) | 충돌 (hook 우회 = 검사 우회) | 자동 등록 모델이라 세션 선별 제어 불가 | 채택 부적합 |
| flowtable HW offload | 충돌 (호스트 우회 스위칭) | 동일 | 채택 부적합 |
| tc flower HW offload | 양립 (세션 단위 선별 프로그래밍 가능) | 양립 (ESTABLISHED+allow+검사완료만 등록, 실패/만료 시 삭제 → SW 경로 유지) | 채택 적합 |
| xfrm ESP offload | 양립 (복호화 후 호스트에서 검사) | 양립 | 조건부 채택 (IPsec 경로 한정) |
| XDP (generic/native) | 부적합 (conntrack 우회, 상태 이중화) | session 단위 제어가 BPF map 자체 구현을 요구 → ngfw.ko session과 불일치 위험 | 사전 필터 용도로만 |
| AF_XDP | 동일 | 동일 | 수집/사전 필터 용도로만 |

평가:

- 명제 1~3은 "오프로드 = 정책 우회"가 아니라 "검사 완료 세션에 한한 전달 가속"으로 정의되어 있다. tc flower HW offload는 규칙 추가/삭제가 세션 수명과 1:1로 매핑되므로 이 모델과 가장 정합적이다.
- SW 폴백 명제는 하드웨어 프로그래밍을 "보장"이 아니라 "가속"으로 전제한다. 실패해도 정확성이 유지되는 구조이므로 TCAM 용량, 드라이버 편차 같은 기법 제약과 양립한다.
- 잔여 위험:
  - (a) 규칙 삭제가 session 만료보다 늦으면 TCAM 잔재가 우발적 fast path를 형성할 수 있다.
  - (b) 검사 완료 판정 이후 세션이 재분류(reclassification)되면 기존 규칙의 즉시 삭제가 필요하다.
  - (c) RSS/aRFS 재설정으로 세션 처리 CPU가 이동하면 fast path 지역성 가정이 깨질 수 있다.
  - (d) flowtable이 같은 NIC에서 hw-tc-offload와 동시에 쓰이면 규칙 공간(TCAM) 경합이 발생할 수 있다.

## 6. 참고 문서 경로 (커널 소스 기준)

- Documentation/networking/checksum-offloads.rst
- Documentation/networking/gso.rst
- Documentation/networking/scaling.rst (RSS/RPS/RFS/aRFS/XPS)
- Documentation/networking/af_xdp.rst
- Documentation/networking/filter.rst (XDP/BPF 개요)
- Documentation/networking/xfrm_device.rst (ESP 하드웨어 오프로드)
- Documentation/networking/netdev-features.rst (미검증)
- Documentation/networking/skbuff.rst (미검증)
- flowtable 관련 전용 문서: 정확 파일명 확인 필요 (미검증)
- tc flower hw offload 전용 문서: 정확 파일명 확인 필요 (미검증), tc(8) man page 참고
- XDP multi-buffer 관련: 커널 커밋 로그 / Documentation/bpf 확인 필요 (미검증)

## Change log

- 2026-10-23: 초판 작성.
