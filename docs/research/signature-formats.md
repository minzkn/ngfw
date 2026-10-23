# 시그니처 규칙 문법 조사 (Suricata/Snort)

- 문서 목적: ngfw IPS 시그니처 엔진이 파싱·평가할 시그니처 규칙 문법을 정리하고, 1차 지원 키워드 범위 결정의 근거를 제공한다.
- 조사 기준: Suricata 공개 규칙 문서의 일반형을 기준으로 하고, Snort(2.x/3.x)와의 차이를 요약한다. 검증하지 못한 세부 차이는 '(미검증)'으로 표기한다.
- 엔진 전제: IPS 시그니처 엔진은 ngfw-engine의 tap-in 스레드에서 스트림 재조립 후 평가한다. 시그니처 DB는 Aho-Corasick(문자열 후보 규칙 추출) + 옵션 VM(후보 규칙의 옵션 평가) 구조이므로, 각 키워드가 "AC 필터링 조건"인지 "VM 평가 조건"인지 구분하는 것이 설계의 핵심이다.

## 1. Suricata 규칙 일반형

Suricata 규칙은 한 줄(single-line) 텍스트이며 다음 일반형을 따른다.

```text
action protocol src_ip src_port -> dst_ip dst_port (options)
```

| 항목 | 설명 |
|---|---|
| `action` | 적중 시 동작. `alert` / `pass` / `drop` / `reject`(세부 변형 `rejectsrc` 등, 미검증) |
| `protocol` | `tcp`, `udp`, `icmp`, `ip`. `ip`는 모든 IP 프로토콜 대상 |
| `src_ip` / `dst_ip` | 단일 주소, CIDR, 리스트 `[a,b,!c]`, 변수(`$HOME_NET`, `$EXTERNAL_NET`) |
| `src_port` / `dst_port` | 단일 포트, 범위(`1024:`), 리스트(`[80,8080]`), `any` |
| 방향 | `->` 단방향, `<>` 양방향(규칙 1개를 양방향 세션에 적용) |
| `(options)` | 세미콜론 구분 키워드 나열. `key:value;` 형태(`content:"GET";`)와 플래그형(`nocase;`)이 혼재 |

- 헤더부는 파싱 후 패킷 헤더 비교 조건으로, 옵션부는 키워드별 파서를 거쳐 옵션 VM 구조로 변환한다.
- 옵션 순서는 평가 의미에 영향을 주지 않는 것이 원칙이나, sticky buffer 키워드 뒤에 오는 `content`/`pcre`는 직전 버퍼에 한정되는 예외가 있다.
- 문자열 리터럴 내부 이스케이프: `\xHH`(바이트), `\\`, `\"`(미검증: 전체 이스케이프 집합은 문서 확인 필요).
- `sid`는 사실상 필수이며, 관례상 `msg` + `rev`를 함께 기술한다.

## 2. 주요 키워드

### 2.1 메타데이터 / 식별

| 키워드 | 형식 | 의미 | 비고 |
|---|---|---|---|
| `msg` | `msg:"text";` | 관리자에게 보이는 규칙 설명 | 알림 메시지로 노출 |
| `sid` | `sid:1000001;` | 규칙 고유 ID | 로컬 규칙은 1,000,000 이상 사용이 관례(미검증) |
| `rev` | `rev:2;` | 같은 sid의 개정 번호 | 시그니처 DB 갱신·비교에 사용 |
| `classtype` | `classtype:trojan-activity;` | 공격 분류 | classification.config 매핑(미검증) |
| `priority` | `priority:1;` | 우선순위 | 숫자가 작을수록 높음(관례) |

### 2.2 페이로드 매칭 (content 계열)

| 키워드 | 형식 | 의미 |
|---|---|---|
| `content` | `content:"User-Agent\x3a";` | 리터럴 + `\xHH` 바이트열 매칭. 여러 개 나열 시 순서 보장(연속 매칭) |
| `nocase` | `content:"GET"; nocase;` | 직전 `content`의 대소문자 무시 |
| `offset` | `offset:4;` | 버퍼 선두에서 지정 바이트만큼 건너뛴 위치부터 검색 |
| `depth` | `depth:16;` | 버퍼 선두 N바이트 이내로 매칭 제한 |
| `distance` | `distance:4;` | 직전 `content` 매칭 끝에서 상대 오프셋 |
| `within` | `within:16;` | 직전 `content` 매칭 끝으로부터 N바이트 이내로 제한 |

- `offset`/`depth`는 절대 오프셋, `distance`/`within`은 직전 content 기준 상대 오프셋이다.
- `start`/`endswith` 같은 신규 수식어가 존재하나 본 문서 범위 밖으로 한다(미검증).

### 2.3 애플리케이션 계층 버퍼 (HTTP/TLS/DNS)

파서가 채워 주는 이름 있는 버퍼(sticky buffer)에 `content`/`pcre`를 매칭하며, 다음 버퍼 전환 전까지 유효하다.

| 키워드 | 대상 버퍼 | 예 |
|---|---|---|
| `http.uri` / `http_uri` | 요청 URI | `http.uri; content:"/admin"; nocase;` |
| `http.host` / `http_host` | Host 헤더 값 | `http.host; content:"evil.example"; nocase;` |
| `http.user_agent` / `http_user_agent` | User-Agent | `http.user_agent; content:"curl";` |
| `http.method` / `http_method` | 요청 메서드 | `http.method; content:"POST";` |
| `tls.sni` | TLS SNI 확장 | `tls.sni; content:"evil.example"; nocase;` |
| `tls.subject` | 인증서 subject | `tls.subject; content:"CN=bad"; nocase;` |
| `tls.fingerprint` | 인증서 SHA-1 fingerprint | `tls.fingerprint; content:"\xab\xcd...";` |
| `dns.query` | DNS 질의 이름 | `dns.query; content:"evil.example"; nocase;` |

- 언더바 표기(`http_uri`)는 Snort 호환, 점 표기(`http.uri`)는 Suricata 신규 표기이며 양쪽을 모두 수용하는 구현이 일반적이다(미검증: 병행 지원 시기).
- `tls.sni`는 ClientHello 확장, `tls.subject`/`tls.fingerprint`는 서버 인증서 파싱 결과를 전제로 하므로 스트림 재조립과 TLS 핸드셰이크 파서가 선행되어야 한다.

### 2.4 흐름 / 상태

| 키워드 | 형식 | 의미 |
|---|---|---|
| `flow` | `flow:to_server,established;` | 방향(`to_server`/`to_client`)과 세션 상태(`established`, `stateless`, `only_stream`) 조건 |
| `threshold` | `threshold:type limit, track by_src, count 5, seconds 10;` | 알림 빈도 제어. `limit`(이후 무시), `threshold`(누적 도달 시 1회), `both` |
| `detection_filter` | `detection_filter:track by_src, count 10, seconds 60;` | 누적 카운트가 임계를 넘은 구간에서만 매칭(스캔/브루트포스) |
| `flowbits` | `flowbits:set,x;` / `flowbits:isset,x;` | 세션 단위 플래그 저장·조회(멀티패킷 상태) |

- `flow:to_server`는 클라이언트에서 서버로 향하는 패킷만, `flow:established`는 핸드셰이크 완료 세션만 대상으로 한다.
- `threshold`/`detection_filter`는 규칙 단독 판정이 불가하고 세션별 카운터 유지가 필요하다.

### 2.5 IP/TCP 헤더 필드

| 키워드 | 형식 | 의미 |
|---|---|---|
| `ttl` | `ttl:64;` / `ttl:>100;` | IP TTL. 관계 연산자 지원(미검증: 지원 연산자 집합) |
| `window` | `window:512;` | TCP window 필드 |
| `flags` | `flags:S;` / `flags:SA;` | TCP 플래그(`S`=SYN, `A`=ACK, `F`=FIN, `R`=RST 등, 미검증: `+`/`*` 수식 문법) |
| `id` | `id:31337;` | IP identification 필드 |

### 2.6 정규식

| 키워드 | 형식 | 의미 |
|---|---|---|
| `pcre` | `pcre:"/pattern/i";` | PCRE 정규식. 접미 플래그(`i`, `s`, `m` 등)와 버퍼 지정 접미사(`H`=Host 등, 미검증) |
| `pcre` (sticky) | `http.uri; pcre:"/x/i";` | 직전 버퍼에서만 평가 |

- 정규식은 역추적(backtracking) 비용이 있으므로 옵션 VM에서 별도 엔진으로 평가하거나, 안전한 하위 집합으로 컴파일하는 정책이 필요하다.

## 3. Snort와의 차이 요약

- 표기 체계: Snort 2.x는 `http_uri` 언더바 키워드 중심, Suricata는 `http.uri` 점 표기(sticky buffer) 중심. Snort 3.x는 sticky buffer를 도입하며 언더바 표기와 병행 호환(미검증).
- `http_method`: Snort 2.x에도 존재한다(미검증: 도입 버전). 양 진영 모두 HTTP 요청 라인 파싱을 전제로 한다.
- PCRE 버퍼 접미사(`H`, `U` 등): Snort 2.x에서 시작된 표기로 Suricata도 유지. 의미와 지원 집합은 구현별 차이 가능(미검증).
- 방향 연산자: 양쪽 모두 `->`, `<>` 지원(미검증: Snort 2.x의 `<>` 지원 시기).
- `flowbits`, `threshold`, `detection_filter`, `byte_test`, `byte_jump`: 양쪽 모두 존재하나 문법 세부와 기본값 차이 가능(미검증).
- Suricata 고유 영역: 멀티스레드 스냅샷 평가 모델, 애플리케이션 트랜잭션 단위 버퍼(예: `http.uri`의 request/response 구분, 미검증), `app-layer-protocol` 키워드.
- Snort 3.x 고유 영역: Lua 기반 검사, 설정 계열 키워드(미검증).
- 결론: content 계열 + 애플리케이션 버퍼 + 흐름/임계 계열은 양쪽에서 문법이 거의 동일하므로, Suricata 문법을 기준으로 파서를 두고 Snort 언더바 표기를 별칭으로 흡수하는 것이 비용 대비 합리적이다.

## 4. 구현 난이도 분류

분류 기준: (a) 옵션 VM에서 단순 비교/범위 검사로 종결되는가, (b) 애플리케이션 파서 수준의 버퍼 추출이 필요한가, (c) 세션 단위 상태(카운터/플래그)가 필요한가, (d) 정규식·역추적 엔진이 필요한가.

### 4.1 쉬운 키워드 (단순 문자열/헤더 필드, 1차 지원 후보)

| 키워드 | 이유 |
|---|---|
| `msg`/`sid`/`rev` | 파싱 후 메타데이터 저장뿐, 평가 로직 없음 |
| `content`(+`nocase`) | Aho-Corasick 후보 추출 + 옵션 VM 단순 비교로 완결 |
| `offset`/`depth`/`distance`/`within` | content 결과에 대한 정수 범위 판정 |
| `http_uri`/`http_host`/`http_user_agent`/`http_method` | HTTP 파서의 헤더 필드 추출 + AC 문자열 매칭 |
| `tls.sni`/`tls.subject`/`tls.fingerprint` | TLS 핸드셰이크 파서 필드 추출 후 문자열 비교 |
| `dns.query` | DNS 파서의 질의 이름 정규화 후 문자열 비교 |
| `flow`(to_server/to_client/established/stateless) | 스트림 재조립 결과가 이미 방향·상태를 보유, 단순 조건 검사 |
| `ttl`/`window`/`flags`/`id` | 헤더 필드 정수/비트 비교 |

### 4.2 어려운 키워드 (미지원 또는 후순위)

| 키워드 | 이유 |
|---|---|
| `pcre` 전체 | 정규식 역추적 비용과 안전성(ReDoS) 문제. 대안: 제한 정규식 컴파일 또는 content 분해 |
| `threshold`/`detection_filter` | 세션(트랙 키)별 카운터 테이블, 시간 창 관리, 메모리 수명 정책 필요 |
| `flowbits` | 세션 단위 플래그 저장소와 규칙 간 의존성(set에서 isset) 평가 순서 문제 |
| `byte_test`/`byte_jump` | 오프셋 연산 + 길이 기반 점프로 옵션 VM에 분기·반복 로직 필요 |
| `http.header`/`http.body` 계열 | 버퍼 경계·인코딩(chunked 등) 처리로 파서 복잡도 급증 |
| `isdataat`/`urilen`/`bsize` | 자체는 단순하나 버퍼 정의가 먼저 확정돼야 함(후순위) |

### 4.3 난이도 요약

| 등급 | 조건 | 대표 |
|---|---|---|
| 쉬움 | AC + VM 단순 비교로 종결 | content 계열, IP/TCP 헤더 필드, 버퍼 문자열 매칭 |
| 중간 | 세션 상태 필요 | `threshold`, `detection_filter`, `flow`의 established/stateless |
| 어려움 | 별도 엔진/트랜잭션 상태 필요 | `pcre` 전체, `flowbits`, `byte_test` 계열 |

## 5. ngfw 1차 지원 범위 제안

### 지원 (1차)

- content 계열: `content`, `nocase`, `offset`, `depth`, `distance`, `within`
- 애플리케이션 버퍼: `http_uri`/`http.uri`, `http_host`/`http.host`, `http_user_agent`/`http.user_agent`, `http_method`/`http.method`, `tls.sni`, `tls.subject`, `tls.fingerprint`, `dns.query`
- 흐름/임계: `flow`(to_server/to_client/established/stateless), `threshold`
- 메타데이터/헤더: `msg`, `sid`, `rev`, `ttl`, `window`, `flags`, `id`
- 동작: `alert`, `pass`, `drop` (reject 계열은 후순위)

### 미지원 키워드는 명시적 오류

- 정의되지 않은 키워드를 만나면 규칙 로드 시 파서가 오류(키워드명·오프셋 포함)를 내고 해당 규칙을 시그니처 DB에 넣지 않는다. 묵시적 무시(부분 평가)는 오탐·미탐의 원인이 되므로 금지한다.
- 오류 목록은 규칙 세트 배포 검증 단계에서 수집해 규칙 제작자에게 피드백한다.

### 근거

- ngfw-engine은 tap-in 스레드에서 스트림 재조립 후 평가하므로 방향/세션 상태(`flow`)와 재조립된 애플리케이션 버퍼(`http_*`/`tls.*`/`dns.query`)를 평가 시점에 안정적으로 얻을 수 있다.
- 시그니처 DB가 Aho-Corasick + 옵션 VM 구조이므로 content 계열은 "AC 후보 추출 후 VM 범위 검사"로 완결된다. 즉 가장 흔한 규칙 형태를 가장 적은 구현 비용으로 커버한다.
- 실무 규칙 세트의 대다수는 content + 소수 수식어 + 메타데이터로 구성된다(미검증: 자체 규칙 세트 통계로 확인 필요). 따라서 1차 범위만으로도 커버리지가 크다.
- `threshold`는 매칭 옵션이라기보다 알림 정책에 가깝고 세션 카운터 추가만으로 1차 범위에 포함 가능하다. `flowbits`/`pcre`는 별도 설계(세션 플래그 저장소, 정규식 엔진 정책)가 필요하므로 2차로 미룬다.

### 향후 확장 순서 (제안)

1. `detection_filter`, `flowbits` (세션 상태 저장소 확장)
2. `http.header`/`http.body` 계열 버퍼 (HTTP 파서 확장)
3. `pcre` (제한 정규식 또는 안전 모드 역추적)
4. `byte_test`/`byte_jump`/`isdataat` 등 VM 명령 확장

## Change log

- 2026-10-23: 초판 작성.
