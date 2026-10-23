# 15. 플랫폼 이식성 (Portability)

## 1. 이식 계층 규칙

- 유일한 OS 의존 지점은 libngfw `platform` 서브시스템(`02` §2, R05). 다른 코드가 OS 헤더를 직접
  포함하면 레이어 위반(`17` §3 검사).
- libc 차이 흡수: glibc/musl/uClibc. 방법: (1) 표준 POSIX.1-2017 우선 사용, (2) 확장 기능은
  autoconf 탐지 후 feature macro(`HAVE_...`)로 분기, (3) 없는 기능은 platform 폴백 구현.
- 자주 문제되는 영역: `SO_REUSEPORT`, `epoll` vs `poll`, `memfd`, `getrandom`, `pthread`
  조인 의미론, 이름 해석(`/etc/hosts` 의존 금지 — 자체 리졸버 사용, `09` §4).

## 2. 대상 플랫폼 매트릭스

| 축 | 대상 | 비고 |
|---|---|---|
| 아키텍처 | x86_64(1순위), aarch64(2순위), riscv64(3순위 실험) | 빌드+테스트 매트릭스(`17` §6) |
| 커널 | Linux 6.12 이상 LTS/최신 | 커널 모듈 빌드 매트릭스 |
| libc | glibc, musl, uClibc | 유저랜드만 |
| 컴파일러 | GCC(≥12), Clang(≥16) | `-std=c11`, 경고 세트 동일(R02) |
| 배포판 | Debian/Ubuntu, Alpine(개발 매트릭스) | Docker 이미지(`17` §6) |
| 엔디언 | LE 기본, BE는 문서상 지원 선언만(테스트 비목표) | 자료구조 직렬화는 명시적 |

## 3. 플랫폼 API 표면(platform이 제공하는 것)

| 분류 | 함수군(개념) |
|---|---|
| 메모리 | mmap 큰 할당, 페이지 정렬, hugepages(선택) |
| 파일/저장 | 저널 안전 쓰기(fsync/fsync-dir), 파일 잠금 |
| 시간 | CLOCK_MONOTONIC/REALTIME 래퍼, NTP 연동 |
| 네트워크 | 소켓 추상화, 인터페이스 열거/속성 |
| 스레드/동기화 | 스레드, 락, RCURD(유저랜드 RCU 유틸) |
| 프로세스 | 데몬화, 권한 강하, seccomp 적용(`18`) |
| RNG | getrandom/폴백 |
| 오류 | errno 매핑+기호화 |

## 4. 빌드 탐지(Autotools와의 분담)

- autoconf: 존재/기능 탐지(`AC_CHECK_*`), 결과는 `config.h` + `platform`에서만 소비.
- 아키텍처별 어셈블리/내장 함수(예: AVX, NEON)는 선택 최적화(`--enable-simd`), 기본 빌드는
  순수 C11 이식 경로 유지(R02).
- 커널 모듈: 커널 빌드 시스템이 컴파일러/옵션 결정 — 유저랜드 옵션과 독립.

## 5. 이식 절차(신규 플랫폼 추가 시)

1. platform 폴백 구현 확인 → 2. 빌드 매트릭스 항목 추가 → 3. selftest 플랫폼 그룹 통과 →
4. 성능 기준선 재측정(`14` §2) → 5. 문서 매트릭스 갱신.

## Change log

- 2026-10-23: 초판 작성.
