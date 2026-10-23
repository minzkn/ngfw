# 11. 관리 (Management)

`ngfw` CLI / REST API / WebUI / 설정 관리. libngfw `mgmt` 서브시스템 + `ngfwd` 서버 구현.

## 1. 관리 평면 보안 기본

- 로컬: unix socket(파일 권한), 콘솔(직렬). 원격: HTTPS(TLS 1.3, 자체 스택) + SSH 대체 수단으로
  콘솔/CLI 제공 — 자체 SSH 서버는 구현하지 않고 원격 CLI는 HTTPS REST/웹터미널로 제공(범위 재정의
  기록: ADR-007).
- 인증: 로컬 계정/외부 인증(`10`) 재사용, RBAC 역할(admin/operator/auditor), 세션 타임아웃,
  2FA(M4, TOTP 자체 구현).

## 2. CLI (`ngfw`)

- 문법: `ngfw <object> <verb> [args]` (예: `ngfw interface set eth0 address 10.0.0.1/24`).
- 일관 규칙(R06): 모든 객체에 동일 동사 집합(show/set/add/delete/rename/test/clear),
  `?`/`help` 컨텍스트 도움말, 오류는 원인+해결 제안 1줄.
- 대화형 모드(셸 스타일) + 단발 명령 모드. 스크립트 친화적 `--format json|text`.
- 실시간 뷰: `ngfw top`(세션/CPU/큐), `ngfw show session [filter]`(`12` §7).

## 3. REST API

- OpenAPI 3.1 문서 제공(`docs/api/openapi.json` 생성 스크립트, `16` §7).
- 리소스 모델은 설정 JSON(`§4`)을 그대로 미러: `/config`, `/config/candidate`, `/config/commit`,
  `/policy`, `/session`, `/log`, `/metrics`, `/selftest` 등.
- 인증: 세션 토큰(TLS 상), API 토큰(해시 저장, 만료/스코프).
- 오류 응답: 표준 봉투 `{error: {code, message, detail[]}}`.

## 4. 설정 관리

| 요소 | 설계 |
|---|---|
| 포맷 | JSON + JSON Schema(스키마 버전 `schema_version`), ADR-006 |
| 저장 | 설정 파티션: running(활성) + candidate(편집) + 저널(롤백 포인트 N개) |
| 트랜잭션 | candidate 편집 → validate → commit(+confirm 옵션: 타임아웃 기본 10분 자동 롤백) |
| 롤백 | 저널 재생, `ngfw config rollback [n]` |
| diff | `ngfw config diff candidate` — 컴파일 영향 요약 포함 |
| 마이그레이션 | 스키마 버전 업그레이드 스크립트(하위 버전 읽기 보장) |
| 암호화 항목 | 시크릿은 암호화 저장소(`18` §4), 평문 백업 금지 |
| 백업/복원 | 전체 설정+인증서 패키지(서명), 복원 시 검증 |

- 설정 적용은 커널 genl 2단(POLICY_LOAD→ACTIVATE, `03` §7.1) + 커널 xfrm/qdisc/netlink 재구성
  순서화(실패 시 자동 이전 상태 복원).

## 5. 펌웨어/소프트웨어 업그레이드

- 패키지: 서명된 `.ngfwup` 아카이브(매니페스트+파일+버전/모델 호환성 정보, `16` §5).
- 어플라이언스: A/B 슬롯 부팅(부트로더 환경변수 전환), 실패 시 자동 롤백(부트 카운터).
- 범용 Linux: 패키지 설치+모듈 재적재(세션 유지, `03` §3 언로드 규칙).
- 업그레이드 중 관리 세션 지속성, 진행률 이벤트, 강제 동의 플래그.

## 6. WebUI

- 정적 SPA(빌드 산출물) + REST API 재사용. 별도 백엔드 로직 없음(중복 방지, R07).
- 필수 화면: 대시보드(세션/위협/자원), 정책 편집(검증 즉시), 세션 조회, 로그 검색, 설정 백업,
  펌웨어 업그레이드. 자체 프론트엔드(빌드 툴체인은 개발 호스트에서만 사용).

## 7. 사용자 경험 규칙(R06)

- 모든 파괴적 명령은 확인 프롬프트 + `--yes` 플래그.
- 설정 커밋은 기본 confirm 모드(위험 변경: 관리 접근 차단 위험 시 사전 경고).
- 도움말은 명령 자체로부터 생성(문서 중복 없음).

## 8. selftest 연계

`ngfw selftest mgmt`: CLI 문법 회귀, REST 엔드포인트 스모크, 트랜잭션/롤백/confirm, 업그레이드
패키지 서명 검증, RBAC 접근 제어. `17` §4.

## Change log

- 2026-10-23: 초판 작성.
