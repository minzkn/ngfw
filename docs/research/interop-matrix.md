# 상호운용(호환성) 검증 매트릭스

## 1. 목적/원칙

NgFW의 상호운용(interoperability) 검증은 두 가지 목표를 동시에 추구한다.

1. **표준 프로토콜 상호운용**: RFC 및 업계 표준을 따르는 제3자 구현과의 실제 동작 검증.
   규격 문서 읽기만으로 상호운용을 단정하지 않으며, 반드시 대표 오픈소스 구현과의
   랩 인터럽(가급적 ngfw-tgen 트래픽 생성기 사용)으로 확인한다. 대상 요구사항은 R11
   (상호운용성 목표)에 근거한다.
2. **Suricata 시그니처 부분 호환**: 공개 Suricata 규칙 세트의 서브셋을 로드·컴파일하고
   탐지를 재현할 수 있어야 한다. 100% 규칙 호환은 목표가 아니며, "부분 호환
   (partial compatibility)"을 명시적으로 측정하고 그 비율을 기록한다.

기본 원칙:

- **검증은 재현 가능해야 한다**: 모든 검증은 버전이 고정된 대상 구현과 스크립트화된
  시나리오로 수행하고, 결과를 검증 기록 양식(섹션 3)에 남긴다.
- **대상은 예시이며 미검증이다**: 본 문서의 대상 상대(오픈소스 참조 구현)는 예시
  목록일 뿐이며, 나열 자체는 어떠한 검증 결과도 의미하지 않는다.
- **실패는 자산이다**: 실패 케이스는 버그 트래커에 등록하고, 재현 시나리오는 회귀
  테스트로 승격한다(섹션 5).
- **selftest 우선**: 각 기능 영역의 사전 자가 점검은 selftest 모듈 그룹으로 수행하고,
  자가 점검을 통과한 빌드만 외부 대상과의 상호운용 검증에 투입한다.
- **F-카탈로그 대응**: 각 검증 행은 가능한 한 F-카탈로그(F01~F20)의 기능 항목에
  대응시켜, 기능 요구사항과 상호운용 검증이 1:1로 추적 가능하도록 한다.

## 2. 매트릭스

기능 영역 × 대상 상대 × 검증 시나리오 × 수용 기준. 대상 상대 열의 오픈소스 참조
구현(strongSwan, libreswan, wireguard-tools, rsyslog, snmpd, dnsmasq, FRR 등)은
**예시이며 미검증** — 실제 검증 대상 버전은 검증 기록 양식(섹션 3)에 기록한다.

| 기능 영역 | 대상 상대 (예시, 미검증) | 검증 시나리오 | 수용 기준 |
|---|---|---|---|
| IPsec IKEv2 | strongSwan | IKEv2 SA 설립 (IKE_SA_INIT + IKE_AUTH), ESP 트래픽 양방향 전달 | 터널 설립 성공, 양방향 ping loss 0%, ngfw-tgen 측정 스루풋이 단독 베이스라인 대비 감소율 허용치 이내 |
| IPsec IKEv2 | strongSwan | Rekey (IKE SA / Child SA), DPD(Dead Peer Detection) 후 재접속 | Rekey 무중단, DPD 감지 후 설정 시간 내 터널 복구 |
| IPsec IKEv2 | strongSwan | NAT-T 환경 (중간 NAT 뒤 터널), EAP/PSK/인증서 인증 | NAT 뒤에서도 터널 설립, 각 인증 방식별 성공 |
| IPsec IKEv2 | libreswan | 동일 시나리오 세트(설립/Rekey/NAT-T) 상호 크로스 체크 | strongSwan 결과와 불일치 없음, 미달 항목은 버그 등록 |
| WireGuard | wireguard-tools | 피어 키 교환 후 터널 설립, 암호화 트래픽 전달 | 핸드셰이크 성공, 양방향 트래픽 무손실 |
| WireGuard | wireguard-tools | 피어 roaming(엔드포인트 IP 변경) 및 keepalive 동작 | 재설립 무중단, keepalive 파라미터 준수 |
| WireGuard | wireguard-tools | 다중 피어 설정(수십 개 피어) 동시 운용 | 모든 피어 동시 트래픽 처리, 크래시/누수 없음 |
| syslog | rsyslog | RFC 5424 형식 원격 전송(TCP/UDP), 심각도(priority) 보존 | rsyslog 수신 파서가 형식 오류 없이 전량 수신, severity 왜곡 없음 |
| syslog | rsyslog | TLS 전송(rsyslog TLS 리시버) 및 전송 단절 시 큐잉/재전송 | TLS 핸드셰이크 성공, 단절 후 복구 시 유실 로그 0건 |
| syslog | syslog-ng (보조 대상) | 동일 RFC 5424 시나리오 크로스 체크 | rsyslog 결과와 불일치 없음 |
| IPFIX/NetFlow | nfcapd/nfdump | IPFIX 템플릿 교환(옵션 템플릿 포함) 및 플로우 레코드 export | nfdump가 레코드 파싱 성공, 플로우 카운트가 ngfw-tgen 생성 트래픽과 정합 |
| IPFIX/NetFlow | nfcapd/nfdump | NetFlow v9 폴백(레거시 수집기) export | v9 수집기에서 동일 정합성 확보 |
| SNMP | snmpd (Net-SNMP) | snmpwalk로 전체 MIB 트리 조회 (GET/GETNEXT/GETBULK) | 오류 응답 0건, 타임아웃 없음, OidDefinition 카탈로그와 일치 |
| SNMP | snmpd (Net-SNMP) | SNMPv3 (authPriv) 접속 및 trap/inform 수신 측 검증 | v3 보안 레벨 협상 성공, 트랩 수신 확인 |
| HTTP/TLS 검사 | (일반 웹서버/프록시 대상) | TLS 핸드셰이크 인터셉션(MITM), SNI 기반 정책 분류 | 인증서 경고 없이 정책대로 allow/block/detect 분류 |
| HTTP/TLS 검사 | (일반 웹서버/프록시 대상) | HTTP/1.1 및 HTTP/2 요청·응답 body 검사, 큰 전송(chunked 포함) | 파일/URL 정책 적중, 스트림 재조립 후 탐지 정상 |
| HTTP/TLS 검사 | (일반 웹서버/프록시 대상) | 업로드·다운로드 대용량 파일 검사 시 성능·안정성 | 검사 지연 허용치 이내, 장시간 운용 메모리 누수 없음 |
| DHCP | dnsmasq | DHCP 서버 모드(주소 할당) 및 DHCP 릴레이 동작 | 할당/갱신/해제 정상, 옵션 전달 정확 |
| DHCP | dnsmasq | DHCP 스누핑·스푸핑 차단 (가짜 서버 패킷 필터링) | 비인가 DHCP 서버 응답 차단, 정상 서버 통과 |
| DNS | dnsmasq, (보조: bind/unbound) | DNS 포워딩·캐싱, NXDOMAIN/타임아웃 처리 | 질의·응답 정확 전달, 캐시 TTL 준수 |
| DNS | dnsmasq | DNS 터널링/초장 레이블 등 이상 질의 탐지 연동 | 탐지 규칙 적중, 정상 질의 오탐 없음 |
| BGP | FRR | eBGP/iBGP 피어링 설립, 라우트 광고·철회, 커뮤니티 처리 | 세션 Established, 광고/철회가 FRR 라우팅 테이블에 정확 반영 |
| BGP | FRR | 세션 flap 및 재수렴(수천 경로 로드 후 전체 재전송) | 설정 시간 내 재수렴, 경로 누락/중복 없음 |
| OSPF | FRR | OSPFv2/v3 인접 형성, LSA 플러딩, 최단 경로 수렴 | 인접 FULL 도달, 링크 다운 후 재수렴 시간 기준 충족 |
| OSPF | FRR | Area/Stub 구성 및 타 벤더 라우터(에뮬레이터) 혼재 토폴로지 | 라우팅 테이블 일관성, 불일치 없음 |
| VRRPv3 | keepalived | 마스터 선출·우선순위(preempt) 동작, 가상 IP 인계 | 장애 주입 후 설정 시간 내 백업이 마스터 승격, 가상 IP 트래픽 무단선 |
| VRRPv3 | keepalived | 인증/버전 협상(IPv4/IPv6), VRRPv2 폴백 장비와 혼재 | 프로토콜 버전별 정상 동작, 혼재 환경 오류 없음 |

비고: 각 행은 가능한 한 F-카탈로그(F01~F20) 항목에 매핑하여 관리하며, selftest
모듈 그룹에 대응하는 자가 점검 케이스가 없는 기능 영역은 외부 검증에 투입하지
아니한다.

## 3. 검증 기록 양식

매트릭스의 각 행(기능 영역 × 대상 상대)은 아래 템플릿으로 검증 결과를 기록한다.
필수 필드: 검증일, 대상 버전, 결과. 빈 행은 새 검증 시 복제하여 사용한다.

| 검증일 (YYYY-MM-DD) | 기능 영역 | F-카탈로그 항목 | 대상 상대/버전 | 시나리오 ID | 결과 (PASS/PARTIAL/FAIL/NA) | 수용 기준 충족 여부 | 수행 환경 (빌드/커밋) | 재현 스크립트 (ngfw-tgen 케이스 등) | 비고/로그 링크 |
|---|---|---|---|---|---|---|---|---|---|
| YYYY-MM-DD | IPsec IKEv2 | F__ | strongSwan vX.Y.Z | IPSEC-REKEY-01 | PASS | Y/N | commit/hash | ngfw-tgen case id | |
| YYYY-MM-DD | WireGuard | F__ | wireguard-tools vX.Y.Z | WG-ROAM-01 | | | | | |
| YYYY-MM-DD | syslog | F__ | rsyslog vX.Y.Z | SYS-TLS-01 | | | | | |
| YYYY-MM-DD | IPFIX/NetFlow | F__ | nfcapd vX.Y.Z | IPFIX-TPL-01 | | | | | |
| YYYY-MM-DD | SNMP | F__ | net-snmp vX.Y.Z | SNMP-V3-01 | | | | | |
| YYYY-MM-DD | HTTP/TLS 검사 | F__ | (대상/버전) | TLS-MITM-01 | | | | | |
| YYYY-MM-DD | DHCP/DNS | F__ | dnsmasq vX.Y.Z | DNS-TUNNEL-01 | | | | | |
| YYYY-MM-DD | BGP/OSPF | F__ | FRR vX.Y.Z | BGP-FLAP-01 | | | | | |
| YYYY-MM-DD | VRRPv3 | F__ | keepalived vX.Y.Z | VRRP-FAILOVER-01 | | | | | |

기록 규칙:

- `PARTIAL`은 수용 기준의 일부만 충족한 경우이며, 반드시 비고에 미충족 항목을
  명시하고 버그 트래커 링크를 남긴다.
- 대상 버전은 대상 소프트웨어 버전뿐 아니라 NgFW 측 빌드(커밋 hash)도 함께 기록한다.
- 검증에 사용한 ngfw-tgen 시나리오/스크립트는 재현 가능하도록 저장소에 커밋한다.

## 4. Suricata 규칙 호환 검증 방법

NgFW는 Suricata 시그니처와 **부분 호환**을 목표로 한다(R11). 검증 절차:

1. **대상 규칙 세트 선정**: 공개 규칙 세트(예: ET Open, 규칙 수가 큰 세트)에서
   카테고리별·시그니처 키워드별로 대표성 있는 서브셋을 추출한다. 서브셋 선정
   기준(카테고리 커버리지, 사용 키워드 커버리지)은 문서화한다.
2. **로드→컴파일**: 서브셋을 NgFW 규칙 로더에 입력하고 컴파일 결과를 수집한다.
   - 측정 지표: 총 규칙 수, 컴파일 성공 수, 실패 수 및 실패 사유 분류
     (미지원 키워드 / 파서 오류 / 의미 검증 오류).
   - 산출물: **컴파일 성공률(%)** = 성공 / 총 규칙 수. 목표치는 별도 지표 정의
     문서에서 관리하며, 미지원 키워드 목록은 호환성 목록에 누적한다.
3. **탐지 재현**: 컴파일에 성공한 규칙에 대해 대응하는 공격 트래픽(공개 pcap 또는
   ngfw-tgen 합성 트래픽)을 주입하고 탐지 여부를 확인한다.
   - 측정 지표: **탐지 재현율(%)** = 정상 탐지 / 컴파일 성공 규칙 수.
   - 오탐(false positive)도 함께 기록: 정상 트래픽에 대해 탐지가 발생하면 규칙 ID와
     트래픽 특성을 기록한다.
4. **반복 수행**: 규칙 파서·엔진 변경 시 동일 서브셋으로 재측정하여 성공률/재현율
   추이를 비교한다. 결과는 검증 기록 양식(섹션 3)에 `SURICATA-COMPILE-xx`,
   `SURICATA-DETECT-xx` 시나리오 ID로 기록한다.

주의: 규칙 세트의 라이선스 조건을 확인하고, 재배포가 제한된 세트는 검증 스크립트에
규칙 본문을 포함하지 않는다(다운로드 스크립트만 저장).

## 5. 실패 시 절차

검증이 수용 기준을 충족하지 못한 경우(결과 FAIL 또는 PARTIAL):

1. **버그 트래커 등록**: 실패 시나리오 ID, 대상 상대/버전, NgFW 빌드 정보, 재현
   단계, 캡처(로그/pcap)를 첨부하여 버그 트래커에 등록한다. 매트릭스 행의 비고에
   버그 ID를 역링크한다.
2. **영향도 평가**: 해당 기능 영역이 F-카탈로그의 어떤 항목에 해당하는지 확인하고,
   보안 우회 가능성(정책 우회, 탐지 누락)이 있는지 판단한다. 보안 영향 시 즉시
   릴리스 블로커로 승격한다.
3. **재검증**: 수정 후 동일 시나리오(동일 대상 버전, 동일 ngfw-tgen 케이스)로
   재검증하고, 검증 기록 양식에 새 행을 추가한다(기존 행은 덮어쓰지 않는다).
4. **회귀 테스트 승격**: 실패→수정→재검증이 완료된 시나리오는 회귀 테스트 세트에
   추가(승격)하여 이후 모든 릴리스 빌드에서 자동 수행되도록 한다. selftest 모듈
   그룹에 대응 케이스가 없는 경우 신규 selftest 케이스로 등록한다.
5. **대상 측 원인 판별**: 원인이 NgFW가 아닌 대상 구현/환경에 있는 것으로 판명된
   경우에도 결과는 FAIL/PARTIAL로 기록하고, 대상 측 이슈 링크를 비고에 남긴다.
   상호운용 검증은 "누구 탓인가"가 아니라 "함께 동작하는가"를 기록한다.

## Change log

- 2026-10-23: 초판 작성.
