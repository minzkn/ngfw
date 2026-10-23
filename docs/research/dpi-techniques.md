# DPI/애플리케이션 식별 기법 조사 (DPI / Application Identification Techniques)

본 문서는 ngfw의 APP-ID(category/app/subtype) 분류 파이프라인에 적용 가능한 DPI 기법을
조사·정리한 것이다. 가능한 한 RFC 원문에 근거해 서술하며, 원문 대조를 아직 수행하지 않은
세부 수치·상수에는 '(미검증)' 표기를 명시한다.

## 용어 (ngfw)

- fast path: 커널 세션 캐시(session)에서 5-tuple 히트로 즉시 포워딩하는 경로
- deep path: fast path 미스 시 유저랜드 DPI 파서로 심층 검사하는 경로
- APP-ID: 식별 결과. category/app/subtype 3단계 구조
- session: 5-tuple 커널 상태 (양방향 주소/포트/프로토콜)
- inspect-budget: deep path 검사 예산(패킷 수/바이트 수) — 초과 시 검사 포기 또는 캐시 보류

---

## 1. 포트 무관 식별 개요 (Port-Independent Identification)

well-known port 매핑(HTTP=80, TLS=443, DNS=53, QUIC=443/UDP)만으로는 식별이 불충분하다:

- 포트 스포핑/은닉: 비표준 포트 서비스(예: 8443 HTTPS), 터널링(DNS 터널, WebSocket)
- 동일 포트 다중 프로토콜: TCP/UDP 443에 HTTPS(TCP), QUIC(UDP), HTTP/2 prior-knowledge 공존
- 동적 포트: P2P, 게임, 메신저의 임시 포트 사용

따라서 식별은 포트 → 메타 필드 → 시그니처 → 상태머신 → 세션 캐시의
다층 증거 순서로 진행하며, 각 단계의 결과를 APP-ID 신뢰도 점수로 누적한다.

## 2. TLS SNI/암호스위트 메타 추출 (RFC 8446)

### 2.1 레코드/핸드셰이크 구조

- TLS record: ContentType(1B) + legacy_record_version(2B) + length(2B) 헤더
- handshake 메시지: msg_type(1B) + length(3B) + body
- ClientHello(msg_type=1) body: legacy_version(2B) + random(32B) +
  legacy_session_id(1+N) + cipher_suites(2+N) + compression_methods(1+N) + extensions(2+N)

### 2.2 SNI 추출 (extension_type=0)

- server_name extension(RFC 8446 §B.3.1.4, 원래 RFC 6066): host_name 타입 리스트
- 첫 번째 host_name만 유효 — 복수 존재 시 파서 오류로 처리
- SNI는 서버명 문자열이므로 도메인 기반 카테고리(category) 매핑의 1차 키가 된다
- ECH(Encrypted Client Hello) 적용 시 outer SNI는 client-facing 서버의 public name이므로
  목적지 앱 분류 정밀도가 떨어진다 — ALPN/cipher 등 부가 메타로 보완 필요

### 2.3 암호스위트/부가 메타

- cipher_suites: 2바이트 코드(RFC 8446 §B.4). 예: 0x1301 = TLS_AES_128_GCM_SHA256
- ALPN(extension_type=16): h2, http/1.1, h3 등 애플리케이션 프로토콜 협상 힌트
- supported_groups/key_share: 암호 강도 정책 점검에 사용 가능
- TLS 1.3에서 서버 인증서는 암호화되므로 인증서 기반 분류는 불가 — SNI/ALPN 중심으로 대체
- JA3 계열 클라이언트 fingerprint(cipher/groups/extensions 해시)는 서브타입(subtype)
  추정의 보조 증거로 유용하나 정밀도는 (미검증) 수준

### 2.4 검사 시점

- ClientHello는 연결 최초 1-2 패킷에 등장 — deep path 진입 직후 inspect-budget 내에서
  반드시 파싱이 끝나도록 우선순위 부여
- 0-RTT(early_data) 재접속에서 pre_shared_key extension이 보이면 세션 재사용 신호로 활용

## 3. QUIC 초기 패킷 처리 (RFC 9000)

### 3.1 초기 패킷 구조

- Long Header(버전 협상 전): Header Form(1bit)=1 + Fixed Bit(1) +
  Long Packet Type(2bit) + Reserved(2bit) + Packet Number Length(2bit) +
  Version(4B) + DCID len(1B) + DCID(0-20B) + SCID len(1B) + SCID(0-20B)
- Initial 패킷(type=0x0)은 CRYPTO 프레임으로 TLS ClientHello를 운반한다
- 복호화 순서: Header Protection(HP) 제거 → Payload Protection(PP) 제거

### 3.2 버전별 특정 솔트로 초기 키 도출

- 초기 키는 DCID와 버전 고정 솔트에서 도출한다 (HKDF 기반, TLS 1.3 레이블 체계):
  initial_secret = HKDF-Extract(salt, DCID)
  client/server secret = HKDF-Expand-Label(initial_secret, "client in"/"server in")
- key/IV/HP 키는 각각 HKDF-Expand-Label로 별도 도출
  (AEAD: AES-128-GCM 또는 ChaCha20-Poly1305)
- 솔트는 버전별로 다르며, Version 필드 값으로 선택해야 한다:
  - v1 (RFC 9000 §5.2) 고정 솔트 — 상수값/길이 대조는 원문 대조 전이므로 (미검증)
  - draft 버전(draft-27/29/32 등)은 상이한 솔트 사용 — v1과 호환 불가 (미검증)
  - 미지 버전: Version Negotiation 대상으로 분류하고 초기 키 시도를 생략 (deep path 탈출)

### 3.3 CID/SNI 추출

- DCID/SCID는 연결 식별자로, 동일 session(5-tuple) 내 패킷 상관과
  connection migration(주소 변경) 추적에 사용
- Initial 복호화 성공 시 CRYPTO 프레임에서 TLS ClientHello를 재사용 파싱(§2.2)해 SNI 획득
- Initial 이후(Handshake/1-RTT)는 앱 키로 암호화되어 DPI 불가 — 초기 단계에서
  SNI/CID를 반드시 세션 캐시에 반영해야 한다

## 4. HTTP/1.1·2·3 메타 (Host/SNI/authority)

### 4.1 HTTP/1.1

- request-line: METHOD SP request-target SP HTTP-version CRLF + 헤더 블록(CRLF 종료)
- Host 헤더(필수, RFC 9112 §3.2)가 호스트명의 1차 소스
- 파서는 CRLF 라인 분리 + 빈 줄로 헤더 종료를 검증 — 시그니처 매치 후
  상태머신으로 request-line/헤더 문법 정합성을 확인

### 4.2 HTTP/2 (RFC 9113)

- 연결 프리페이스(magic): "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n" (24바이트) —
  포트 무관 강력한 시그니처
- HEADERS 프레임의 HPACK 헤더에서 :authority 의사헤더(pseudo-header) 추출
- :authority ≈ HTTP/1.1 Host + :scheme 결합 개념
- HPACK 동적 테이블은 연결 단위 상태 공유 → 세션별 파서 상태 유지 필요
- prior-knowledge(h2c 직접)와 Upgrade 경로 모두 존재 — magic이 공통 관문

### 4.3 HTTP/3 (RFC 9114)

- QUIC 위에서 동작 → §3 초기 패킷 복호화가 전제
- HEADERS 프레임의 QPACK(RFC 9204) 인코딩 필드에서 :authority 추출
- QPACK은 HPACK과 유사하되 별도 encoder/decoder 스트림 상태 필요
- ALPN h3 확인 시 deep path 파서 선택을 단축할 수 있다

## 5. DNS 간접 식별

- DNS 질의 QNAME은 이후 접속 대상 호스트명의 사전 힌트 —
  응답 IP ↔ 후속 연결 목적지 IP 상관분석으로 APP-ID를 보강
- DoH/DoT/DoQ 암호화 DNS는 QNAME 미노출 → 간접 식별 불가.
  대신 암호화 DNS 트래픽 자체를 별도 APP-ID로 분류하는 것이 실용적
- DNS 터널 탐지: 비정상 QNAME 길이/라벨 수/질의 빈도 휴리스틱

## 6. 휴리스틱+상태머신 검증

- 시그니처 단독 매치는 오탐 위험(페이로드 내 우연한 매직 바이트) —
  파서 상태머신으로 후속 패킷이 프로토콜 문법/상태 전이를 따르는지 검증
- 위반 시 APP-ID 신뢰도 강등, 재분류 트리거
- 통계 휴리스틱: 패킷 크기 분포, 방향 비율, inter-arrival time, burst 패턴으로
  streaming/interactive/bulk 트래픽 클래스 추정 — APP-ID의 보조 증거
- 상태머신 상태는 deep path(유저랜드)에만 유지하고, 확정 결과(APP-ID)만
  커널 세션 캐시로 전달 — 커널 fast path는 파서 상태를 보관하지 않는다

## 7. 세션 캐시/학습 가속

- session(5-tuple 커널 상태)에 APP-ID(category/app/subtype), 프로토콜 버전,
  신뢰도 점수, 분류 근거(사용 기법)를 캐시
- 동일 5-tuple 재접속/재사용 시 fast path에서 즉시 APP-ID 적용 →
  deep path 진입 생략, inspect-budget 절약
- 재검사 트리거: 상태머신 위반, TTL/타임아웃 만료, 주소 변경(QUIC migration)
- 학습 가속 3단계: ① 첫 식별 성공 시 즉시 캐시 기록 ② 부분 식별은 확정 후 갱신
  ③ 실패/만료 시 재분류
- 캐시 키: 기본 5-tuple + (QUIC의 경우) DCID 보조 키로 migration 대응

## 8. 기법 정밀도/비용/프라이버시 비교표

| 기법 | 정밀도 | 검사 비용 | 프라이버시 침해도 | 비고 |
|------|--------|-----------|-------------------|------|
| 포트 기반 | 낮음 | 매우 낮음 (fast path) | 낮음 | 은닉 트래픽에 무력 |
| TLS SNI | 높음 | 낮음 (1-2 패킷) | 중 (호스트명 노출) | ECH 사용 시 정밀도 하락 |
| TLS cipher/ALPN | 중 | 낮음 | 중 | subtype 힌트 수준 |
| QUIC initial 복호화 | 높음 | 중 (HKDF+AEAD) | 중 | 버전별 솔트 관리 필요 |
| HTTP Host/:authority | 높음 | 낮음 | 중 | HPACK/QPACK 상태 필요 |
| DNS QNAME 상관 | 중 | 낮음 | 높음 (행동 프로파일) | 암호화 DNS 시 무력 |
| 페이로드 시그니처 | 중 | 중 | 중 | 오탐률 관리 필요 |
| 파서 상태머신 | 높음 | 중-높음 | 중 | deep path 상태 유지 비용 |
| 통계 휴리스틱 | 낮음-중 | 낮음 | 높음 (행동 프로파일) | 보조 증거로만 사용 |
| 세션 캐시 학습 | 최초 분류에 상속 | 매우 낮음 (재사용) | 낮음-중 | 히트율이 전체 비용 좌우 |

## 9. ngfw 분류 알고리즘과 대응표

ngfw의 5단계 분류 파이프라인과 본 문서 기법의 매핑:

| 단계 | 동작 | 대응 기법 | 실행 경로 | 비고 |
|------|------|-----------|-----------|------|
| 1. 포트 사전지식 | well-known port → APP-ID 후보 | 포트 기반 매핑 | fast path | 후보 확정 전 보류 상태 |
| 2. 메타 필드 | SNI/Host/:authority/QNAME 추출 | TLS SNI(§2), QUIC SNI(§3), HTTP(§4), DNS(§5) | deep path | inspect-budget 최우선 소비 |
| 3. 페이로드 시그니처 | 매직 바이트/프리페이스 매치 | HTTP/2 magic(§4.2), TLS record, 시그니처 DB | deep path | 오탐 시 단계 4로 위임 |
| 4. 파서 상태머신 검증 | 프로토콜 문법/상태 전이 준수 확인 | 상태머신 검증(§6) | deep path | 위반 시 재분류/강등 |
| 5. 세션 캐시 학습 | APP-ID 캐시/재사용/신뢰도 갱신 | 세션 캐시(§7) | fast path | 단계 1-4 결과의 자산화 |

단계별 흐름 요약:

```
패킷 수신 → session lookup (5-tuple)
  ├─ hit  → fast path: 캐시된 APP-ID 적용            (단계 5)
  └─ miss → deep path: inspect-budget 배정
        ├─ 포트 사전지식으로 후보 좁힘               (단계 1)
        ├─ 메타 필드 추출 → 확정 시 캐시 기록         (단계 2)
        ├─ 필요 시 페이로드 시그니처 매치             (단계 3)
        ├─ 파서 상태머신으로 검증/강등               (단계 4)
        └─ 예산 초과/검증 실패 → unknown 또는 휴리스틱 분류
```

- 단계 1-2는 TLS/QUIC/HTTP/DNS 등 주류 트래픽을 결정적으로 종결시킨다
- 단계 3-4는 비표준/커스텀 프로토콜의 잔여 분류를 담당한다
- 단계 5의 캐시 히트율이 전체 검사 비용과 deep path 부하를 좌우한다

## Change log

- 2026-10-23: 초판 작성.
