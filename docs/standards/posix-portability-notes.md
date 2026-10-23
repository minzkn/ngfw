# POSIX 이식성 노트 (posix-portability-notes)

R05의 구체화. 유저랜드가 의존할 수 있는 플랫폼 API의 범위와 탐지/폴백 규칙.

## 1. 기준 표준

- POSIX.1-2017(IEEE Std 1003.1-2017) + C11. Linux 전용 확장은 `platform` 서브시스템에서만
  직접 사용하며, autoconf 탐지 후 폴백 경로를 반드시 제공한다.

## 2. 사용 허용 API 그룹

| 그룹 | 대표 함수 | 비고 |
|---|---|---|
| 프로세스 | fork/exec/wait, setsid, setuid/setgid/cap 감지 | 데몬화/권한 강하 |
| 스레드 | pthread_* | 단일 헤더 추상화 경유 |
| 소켓 | socket/bind/listen/accept/sendmsg/recvmsg | mmap 수신은 NFQUEUE 자체 매핑 |
| epoll/poll | epoll_create1 등 | Linux 필수, 폴백 poll 제공 |
| 파일 | open/read/write/fsync/flock | 저널 안전 쓰기 |
| mmap | mmap/munmap/msync | 공유 링/NFQUEUE |
| 시간 | clock_gettime(CLOCK_MONOTONIC) | 타이머 기반 |
| RNG | getrandom(2) → /dev/urandom 폴백 | - |
| 권한 | setresuid/setresgid, prctl(PR_SET_NO_NEW_PRIVS 등) | 샌드박싱(`designs/18`) |

## 3. 탐지/폴백 규칙

1. 기능은 `AC_CHECK_FUNCS`/`AC_CHECK_HEADERS`로 탐지 → `config.h` `HAVE_*` 매크로.
2. `platform`은 (a) 표준 경로 (b) Linux 확장 경로 (c) 폴백 경로 순으로 선택.
3. 폴백이 기능 손실을 유발하면(예: epoll 없음) 성능 영향을 문서에 명시하고 필수 기능인 경우
   지원 플랫폼에서 제외한다(매트릭스 `designs/15` §2).

## 4. 금지 사항

- glibc 전용 확장의 직접 사용(`__` 접두사 심볼, `*_r` 비표준 변형, `error.h` 등).
- `/proc` 직접 파싱의 무분별 사용 — 필요 시 platform 캡슐화 + 실패 허용.
- 셸 유틸리티 호출(`system("...")`) — 모든 외부 동작은 C 구현 또는 명시적 스크립트 레이어.

## 5. 검증

- 유닛: 플랫폼 그룹 selftest가 각 기능의 실제 동작(폴백 포함)을 확인.
- 이식 매트릭스 빌드(glibc/musl)에서 `HAVE_*` 조합별 컴파일 확인(`designs/17` §6).
