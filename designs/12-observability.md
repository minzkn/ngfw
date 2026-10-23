# 12. 관측성 (Logging / Monitoring)

libngfw `observ` 서브시스템. R04(가시성)의 실행 계층: 모든 단계(빌드→설치→실행→모니터링)의
진단 지점을 통일된 이벤트 체계로 제공.

## 1. 이벤트 버스

- 내부 단일 이벤트 모델: `{ts, source, category, severity, code, subject, kv...}`.
- 발행: 커널 genl 이벤트 → `ngfwd` 수집, 유저랜드 모듈 직접 발행, 엔진→공유 링 릴레이(`02` §6).
- 소비: 싱크(로컬 저널/syslog/원격/메트릭/HA 미러)는 구독자 모델. 발행-소비 분리로 빠른 경로
  영향 제거(레이트 리밋/집계 정책 공통, `03` §7.2).

## 2. 로깅

| 항목 | 설계 |
|---|---|
| 로컬 저널 | append-only 바이너리 저널(회전, 크기 한도), 변조 방지 해시 체인(감사 로그) |
| syslog | RFC 5424 클라이언트(RFC 6587 프레이밍, TLS 전송 옵션), 시설/심각 매핑 |
| 카테고리 | system/config/policy/session/threat/vpn/ha/identity/firmware/selftest |
| 세션 로그 | 시작/종료/차단, 필드: tuple, zone, app, user, rule, verdict, bytes |
| 위협 로그 | IPS/URL/TLS 이벤트, 시그니처 sid 포함, 익명화 옵션(`10` §5) |
| 레이트 리밋 | 카테고리별 초당 상한, 초과 시 집계 라인(`... +N suppressed`) |

## 3. 플로우 익스포트

- IPFIX(RFC 7011) 우선 + NetFlow v5/v9 호환 모드(상위 장비 통합).
- 템플릿 관리/내보내기 주기, 버퍼링/UDP 리트라이 옵션, ngfw 확장 IE(엔터프라이즈 PEN 등록 전용
  로컬 번호 + 문서) — app-id/user-id/threat 코드.
- sFlow: 비목표(요구 시 ADR).

## 4. SNMP

- 자체 에이전트(v2c/v3 최소: GET/GETNEXT/GETBULK, 트랩): MIB-2, IF-MIB, 엔터프라이즈 서브트리
  (세션/정책/HA 상태). MIB 파일은 `docs/mibs/` 제공.

## 5. 메트릭

- Prometheus 텍스트 익스포트(mgmt HTTPS `/metrics`) + 자체 JSON 스냅샷.
- 필수 메트릭: 세션 수/생성율, fast/deep 경로 비율, 드랍 원인 분포, 검사 지연 분포(히스토그램),
  큐 적체, 오프로드 비율, HA 상태, 설정 커밋 결과.

## 6. 정책/세션 조회

- `ngfw show policy [rule]`: 규칙+히트 카운터(`05` §9).
- `ngfw show session [filters]`: genl SESSION_DUMP 기반(`03` §7.1), 필터: zone/app/user/age.
- `ngfw trace` : 플로우 추적 모드(지정 5-tuple의 단계별 판정 로그, 임시 활성화, 자동 만료).

## 7. 헬스/진단 (`ngfw-doctor`)

| 점검 그룹 | 항목 예 |
|---|---|
| 빌드/설치 | 산출물 버전 일치(`20`), 모듈-데몬 genl 버전 호환 |
| 실행 | 설정 파티션 무결성, 정책 적재 상태/오류, tap 큐 상태, 엔진 알림 |
| 네트워크 | 인터페이스/zone 매핑, FIB 일치, HA 링크 |
| 보안 | 인증서 만료, 시크릿 저장소 상태, 펌웨어 서명 |
| 성능 | 큐 적체/드랍 추세, 오프로드 상태, 세션 한도 근접도 |

- 결과: 상태(OK/WARN/FAIL)+조치 제안. 부팅 시 스냅샷 저널 기록(`02` §8).

## 8. 부팅 자가진단(F15/R04)

`ngfw-init`이 단계별 결과를 저널에 기록하고, 실패 단계는 콘솔+경보. 재부팅 루프 감지(3회) 시
복구 모드(공장 기본 부팅 옵션) 제안.

## 9. selftest 연계

`ngfw selftest observ`: 이벤트 버스 왕복, 저널 무결성, syslog/IPFIX/SNMP 목표 수신 검증(테스트
수신기 내장), 메트릭 일관성. `17` §4.

## Change log

- 2026-10-23: 초판 작성.
