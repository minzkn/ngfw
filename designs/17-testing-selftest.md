# 17. 테스트/selftest 체계

## 1. 테스트 피라미드(R04, R13)

| 층 | 도구 | 실행 시점 |
|---|---|---|
| 유닛 | 자체 미니 프레임워크(헤더 1개+매크로), `tests/` | `make check` |
| 컴포넌트 selftest | `ngfw selftest <module>` (모듈 내장) | 설치 후/릴리스 |
| 시스템 | QEMU/KVM 부팅 + `ngfw-tgen` 트래픽 + 골드 시나리오 | `scripts/qemu-run.sh` |
| 이식 매트릭스 | Docker(멀티 배포판 빌드/유닛) | `scripts/docker-matrix.sh` |
| 퍼징 | 자체 퍼저(구조화 입력), sanitizer 빌드 | 지속(야간) |

## 2. 유닛 테스트 규약

- 테스트는 대상 모듈 옆 `tests/test_<name>.c`에 위치, 하나의 실행 파일로 여러 케이스.
- 케이스 명명: `case_<모듈>_<동작>`. 실패 출력: 케이스/파일:라인/기대값/실제값.
- 금지: 네트워크 접속 요구, 절대 경로, 실행 순서 의존(독립성).

## 3. 정적 검사

| 검사 | 도구/방법 |
|---|---|
| 레이어 include 규칙(`02` §7) | `scripts/check-layering.sh` |
| 스타일(유저랜드 GNU/커널) | 자체 스타일 스크립트(정규식 기반 최소 점검) + `clang-format`(선택) |
| 커널 스타일 | 커널 checkpatch 유사 자체 스크립트 |
| 컴파일 경고 | `-Wall -Wextra -Werror`(릴리스), sanitizer 옵션(`--enable-debug`) |

## 4. selftest 설계(F15)

- 명령: `ngfw selftest [all|<module>...] [-v] [-o json]`. 종료 코드 0/비0, 결과 JSON 제공.
- 각 selftest는: 의존성 선언 → 사전 상태 확인 → 수행 → 상태 복원(가능 시) → 결과 보고.
- 모듈 그룹: platform, core, crypto, netproto, policy, dpi, ips, url, tls, vpn, services,
  identity, mgmt, observ, ha, kernel, mgmt-ux, version, perf, doctor.
- 기준: 각 모듈 문서의 "selftest 연계" 섹션이 케이스 목록의 유일 출처(P-A) — 본 문서는 구조만 정의.

## 5. 시스템 테스트(QEMU/KVM)

- 토폴로지: QEMU VM 2~3대(virtio-net, tap 브리지), 이미지 부팅 → 정책 적용 → 트래픽 시나리오.
- 시나리오 자산: `tests/scenarios/*.yaml`(토폴로지/설정/트래픽/기대 로그), 골드 PCAP(`tests/pcap/`).
- KVM 있으면 KVM 가속, 없으면 TCG 폴백(느림 표기). 결과는 JUnit 유사 XML+로그 아카이브.

## 6. Docker 이용 범위

- 유저랜드 빌드/유닛(selftest 플랫폼 그룹)을 배포판 매트릭스로 수행.
- 커널 모듈 테스트는 Docker 부적합(호스트 커널 의존) → QEMU에서 수행(커널 버전별 이미지 준비).

## 7. 퍼징/보안 테스트

- 퍼저 대상: 패킷 파서, IKEv2/TLS 핸드셰이크, 설정 파서, 규칙 컴파일러, genl 속성 파싱.
- 입력: 코퍼스(골드 트레이스 변형) + 구조화 랜덤. sanitizer(ASan/UBSan) 빌드와 함께 실행.
- 크래시/한도 초과는 최소 재현 저장 + 회귀 유닛 테스트로 승격.

## 8. CI 운영(셸 스크립트 기반)

- 단계: 스타일 → 유닛(매트릭스) → 커널 빌드 매트릭스 → 시스템 스모크(QEMU) → 퍼징(야간).
- 모든 단계는 로컬 재현 가능(`scripts/ci-local.sh`).

## Change log

- 2026-10-23: 초판 작성.
