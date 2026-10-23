# 21. 구현 로드맵 (Roadmap)

각 마일스톤의 수용 기준은 selftest/시스템 테스트로 검증 가능한 형태로 정의한다(R04/R13).
세부 케이스는 각 기능 문서의 "selftest 연계" 섹션이 출처이다.

## M0 — 골격 (기반)

- 저장소 구조(`02` §7), Autotools/Make 뼈대, `VERSION` 주입, 유닛 프레임워크, 플랫폼 서브시스템,
  이벤트 루프/로그/설정 트리, selftest 골격, Docker 매트릭스.
- 수용: `./configure && make && make check` 통과, `ngfw selftest platform core` 통과.

## M1 — 기본 방화벽

- `ngfw.ko`: 세션 테이블/genl/NIC 기본 오프로드 구성, `ngfwd` 정책 컴파일/적재, zone/룰/NAT
  기본, CLI/설정 트랜잭션, 로컬 로그/syslog.
- 수용: QEMU 2-노드에서 룰 기반 차단/허용, NAT, 세션 조회, commit/rollback 동작.

## M2 — NGFW 검사 1단

- `ngfw-engine`: tap/재조립/APP-ID(내장 파서 1차), IPS 시그니처 엔진(기본 키워드), URL 필터
  (SNI), tc flower 세션 오프로드, HA 1단(VRRPv3+설정 동기), RADIUS/LDAP 인증, captive portal.
- 수용: HTTP/TLS 트래픽 APP-ID 분류, 시그니처 차단, HA 전환 세션 유지.

## M3 — NGFW 검사 2단 + VPN

- IPsec IKEv2(site-to-site, NAT-T), WireGuard 연계, TLS inspect-sni 심화/Threshold, IPFIX/NetFlow,
  SNMP, BGP(eBGP), 세션 오프로드 심화(flow steering), XDP 옵션.
- 수용: VPN 터널을 통한 정책 적용, 플로우 익스포트 검증, 동적 라우팅 수렴.

## M4 — 운영 성숙

- TLS full-mitm, 파일/해시 정책, AD 그룹 심화, OSPF, VRF, QoS 셰이핑 훅, MOBIKE, active/active
  HA 설계 착수, io_uring 관리 IO.
- 수용: 복호화 정책+제외 카테고리 동작, 대규모 그룹 재평가 성능 기준 충족.

## M5 — 고급/확장

- NAT64, DNSSEC, iBGP/커뮤니티, 멀티캐스트, 아카이브 파일 검사, active/active HA, 플러그인
  동적 로딩 정식화, sFlow(ADR 시), Kerberos 검토.
- 수용: 해당 기능 시나리오 selftest/시스템 테스트 통과.

## M6 — 안정화/릴리스

- 성능 풀 측정(`14` §2), 보안 감사(퍼징 결과 정리), 문서 완성도 점검(문서-코드 일치 감사),
  어플라이언스 이미지 확정, 릴리스 절차(`16` §6 게이트).

## 마일스톤 우선순위 원칙

- 각 마일스톤은 "동작하는 전체 수직 슬라이스"를 목표로 한다(레이어별 완성형이 아니라
  사용자 시나리오가 끝까지 동작하는 상태).
- 성능 수치는 측정 전까지 목표로만 기록(P-G). 마일스톤 수용 기준의 성능 조건은 측정 절차 참조형
  ("`14` §2 시나리오 X 기준선 이상")으로 서술.

## Change log

- 2026-10-23: 초판 작성.
