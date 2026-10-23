# 08. VPN

libngfw `vpn` 서브시스템 + 커널 xfrm/WireGuard 연계. 원칙: 데이터 플레인은 커널 기능 활용(R01:
커널은 허용 의존), 컨트롤 플레인은 자체 구현(ADR-004).

## 1. 기능 총괄

| 기능 | 컨트롤 플레인 | 데이터 플레인 | 상태 |
|---|---|---|---|
| IPsec(site-to-site) | 자체 IKEv2(RFC 7296) | 커널 xfrm/ESP(RFC 4303) | M2 |
| IPsec(remote access) | IKEv2 EAP/EAP-TLS(자체) | xfrm policy | M3 |
| NAT-T | RFC 3947 감지/캡슐 | UDP 4500 | M2 |
| WireGuard | 커널 WireGuard 구성(netlink) | 커널 WG | M2 |
| SSL VPN | 자체 TLS 1.3 서버 + 자체 터널 프로토콜 | TUN | M3 |
| GRE/L2TP | 자체 컨트롤 | 커널 | M3 |
| IKEv1 | 지원하지 않음(신규 사이트 요구 시 IKEv2 사용) | - | - |

## 2. IKEv2 구현 설계

- libngfw `netproto/ikev2`: 메시지 인코더/디코더(스냅샷 표준 준수, RFC 7296+7383+7427 부분).
- 상태머신: INIT→AUTH→CHILD→ESTABLISHED, 리타이밍(지수 백오프), DPD(RFC 3706 유사 유무인
  알림), MOBIKE(RFC 4555, M4).
- 암호 스위트: AES-GCM-128/256, ChaCha20-Poly1305, SHA-2, DH=P-256/Curve25519(자체 crypto).
  PSK/인증서(자체 X.509 파서, `crypto` 서브시스템) 인증.
- SA 수명/리키: 세션 키 재협상 자동, 자식 SA 수명 추적, 중복 제거.
- xfrm 연계: `kapi`가 netlink xfrm(XFRM_MSG_NEW/DEL/UPDSA, NEWPOLICY)으로 정책/SA 주입.
  정책 우선순위는 ngfw 정책 artifact와 충돌 없도록 mark 전용 비트 사용(문서화).
- 세션 통합: VPN 세션도 ngfw 세션 테이블에서 동일 정책 적용(ESP 복호화 후 재진입 흐름).

## 3. WireGuard 연계

- 커널 WireGuard 사용: 인터페이스 생성/피어/키 구성은 `ngfwd`가 netlink(RTNL)로 수행.
- 키 저장: 설정 암호화 저장소(`18` §4). 정책에서 zone 매핑(WG 인터페이스→zone).
- 로밍/keepalive/한도는 커널 구현 따름 — 문서는 구성 의미론만 정의.

## 4. SSL VPN

- 전송: TLS 1.3(자체 스택) + 자체 터널 프레임 프로토콜(TLV, 시퀀스/ACK 없음 — 신뢰성은 TCP).
- 인증: 사용자 인증 프레임워크 재사용(`10`).
- 클라이언트 호환: 자체 CLI 클라이언트(`ngfw-vpn-client`) 제공. 오픈VPN/기타 타사 프로토콜
  호환은 비목표(대신 표준 IPsec/WG로 상호운용).
- 성능: 유저랜드 복호화 비용 명시 — 대규모은 IPsec 권장(문서화).

## 5. GRE/L2TPv2

- GRE: 정적 터널, 커널 구현 구성. L2TPv2(UDP): 컨트롤 자체 구현(최소), 데이터 커널.
- 둘 다 zone 매핑 후 표준 정책 적용.

## 6. VPN 정책/가시성 통합

- VPN 터널 상태: `ngfw show vpn` (SA/피어/트래픽), IPFIX로 터널 플로우 익스포트(`12` §4).
- 실패 시나리오: IKE 실패/DPD 데드 → 이벤트+정책 라우트 재계산(`09` §2).

## 7. selftest 연계

`ngfw selftest vpn`: QEMU 토폴로지에서 IKEv2 핸드셰이크 왕복(두 인스턴스), NAT-T 사례,
xfrm 정책/SA 일치성, WG 구성, SSL VPN 데이터 왕복, 수명/리키 동작. `17` §5.

## Change log

- 2026-10-23: 초판 작성.
