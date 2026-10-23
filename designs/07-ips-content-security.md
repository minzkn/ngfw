# 07. IPS/IDS 및 콘텐츠 보안

DPI 프레임워크(`06`) 위에서 동작하는 위협/콘텐츠 서브시스템 묶음: 시그니처 엔진, 프로토콜
분석기, URL 필터, TLS 검사, 파일 검사.

## 1. IPS/IDS 개요

- 모드: IDS(탐지만 경보) / IPS(차단 포함). 정책 profile에서 모드 지정.
- 실행 위치: `ngfw-engine` tap-in 스레드(재조립 후 스트림/패킷 단위 평가).
- 결과: 패킷/세션 verdict(alert/drop/reset) + 이벤트 발행(`12` §2). drop은 커널 세션에
  `threat-verdict` 기록으로 세션 전체 차단 가능(`04` §2.4).

## 2. 시그니처 엔진

### 2.1 규칙 형식(Suricata 부분 호환, R11)

문법 조사 상세는 docs/research/signature-formats.md. 지원 범위(1차 호환 목표):

```
action protocol src_ip src_port -> dst_ip dst_port (options)
action:   alert|drop|pass|reject
protocol: tcp|udp|icmp|http|tls|dns|smtp|ftp|ssh
options:  msg, sid, rev, content(+depth/offset/distance/within/nocase),
          http_uri|http_host|http_user_agent|http_method,
          tls.sni|tls.subject|tls.fingerprint,
          dns.query, pcre(제한 문법), threshold, flow(to_server|to_client|
          established|stateless), ttl, window, flags, id, detection_filter
```

- 미지원 키워드는 명시적 오류+이유 목록으로 거부(침묵 무시 금지, R06/R10).
- 컴파일러(`ngfw-ruleset`, libngfw/dpi 서브시스템)가 규칙→바이너리 시그니처 DB 변환, CRC/버전
  포함. DB 핫리로드는 RCU 포인터 교체(`06` §4).

### 2.2 매칭 구조

- 멀티패턴: Aho-Corasick(자체 구현, 최소 문자셋 최적화) + 규칙 후보 비트맵 → 후보 규칙 옵션 VM.
- 옵션 VM: content 위치 제약(depth/offset/distance/within)과 프로토콜 필드 버퍼(http_uri 등)에
  대한 순차 검사. pcre는 제한 문법만(백트래킹 상한, RE2급 선형 목표 — 자체 구현 서브셋 NFA).
- 성능 목표: 패턴 매칭은 스트림 바이트당 선형, 후보 평가는 평균 <8 규칙. 측정 절차는
  docs/research/performance-methods.md.

## 3. 프로토콜 분석기(anomaly + parsing)

파서 플러그인(`06` §6)이 제공하는 정규화 결과 위에서 동작:

| 분석기 | 검사 |
|---|---|
| HTTP | 요청/응답 필드 검증, 크기/헤더 수 한도, 이중 인코딩 탐지, 방법/스킴 정책 |
| TLS | 버전/암호스위트 정책, SNI-인증서 불일치, 자체서명 정책 |
| SMTP/FTP | 명령/응답 상태 검증, 명령 화이트리스트 정책 |
| DNS | qname 이상(길이/라벨 수/터널링 휴리스틱), 응답 레코드 정책 |
| SMB/SSH | 배너/버전 정책, 세션 한도 |

각 분석기는 이벤트 유형을 등록하고, 규칙에서 `anomaly:<type>` 조건으로 접근 가능하게 한다.

## 4. 임계치/이상탐지

- threshold: per-source/destination/port, count/seconds 기본 타입 + detection_filter(슬라이딩).
- 이상탐지(M3+): 플로우 메타 통계 기반(스캔/브루트포스 휴리스틱), 자체 배킹 통계(per-CPU 집계).
- 억제(suppression): sid+src 매칭, 유지 기간 설정.

## 5. URL 필터

- DB 포맷: 자체 형식(카테고리 ID ↔ 도메인/URL 접두사 trie, 버전/서명 포함) + 임포터 어댑터
  (서드파티 목록 CSV/JSON). DB는 `ngfwd`가 관리, 엔진은 RCU 읽기.
- HTTPS: SNI 기반 분류(복호화 없이). HTTP: Host/URL 전체.
- 카테고리 정책: allow/block/monitor + 경고 페이지 리다이렉션(HTTP만).
- DNS 연계: 내부 DNS 프록시 응답 필터(`09` §4).

## 6. 파일/콘텐츠 정책

- 스트림에서 파일 경계 추출(HTTP multipart/body, SMTP 첨부, FTP 전송).
- 1차: 확장자/MIME/매직넘버 정책, 파일 해시(SHA-256) 목록 대조(허용/차단 DB, 외부 피드 임포트).
- 2차(M4+): 아카이브 순회(자체 zip inflate, 중첩 한도) + 정적 서명(자체 YARA 유사 미니 문법) —
  성능 한계 명시적으로 문서화.

## 7. TLS 검사

| 모드 | 동작 |
|---|---|
| none | 메타만(SNI/버전/암호스위트) |
| inspect-sni | SNI 기반 URL 필터/정책만 적용(기본) |
| full-mitm | 자체 TLS 스택으로 종단 종료→재기원. 자체 CA 서명 인증서 배포 필요 |

- full-mitm 제약: 인증서 고정(pinning) 앱 탐지 시 우회 제외, 은행/의료 등 카테고리 제외 목록,
  세션 단위 감사 로그(무결성). 자체 CA 키는 하드닝 저장(`18` §4).
- 자체 TLS 1.2/1.3 클라이언트+서버 구현(`crypto` 서브시스템, ADR-005). 호환성 검증은
  docs/research/interop-matrix.md 절차.
- 복호화 스트림은 파서 재투입(APP-ID/IPS 재평가), 대역폭 예산(세션당 재인코딩 버퍼 한도).

## 8. 안티바이러스/멀웨어 경계

오프라인 자체 탐지만(클라우드 샌드박스 비목표, `01` §2). 파일 해시/시그니처 기반이며 DB 갱신은
관리 인터페이스로 임포트(`11` §5).

## 9. selftest 연계

`ngfw selftest ips|url|tls`: 골드 패킷 트레이스(공개 테스트 PCAP 대상 재현) — 시그니처 적중,
오탐 억제, URL 카테고리 판정, TLS 모드 전환. 트레이스 자산은 `tests/pcap/` 관리(`17` §5).

## Change log

- 2026-10-23: 초판 작성.
