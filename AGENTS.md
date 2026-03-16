# AGENTS.md

## 프로젝트 개요

NGFW(차세대 방화벽)는 최소 외부 의존성을 가진 Linux Kernel 6.x용 C 기반 방화벽 프로젝트다.

- **언어**: ISO C99 (C11/C17 허용)
- **대상 커널**: Linux 6.x (6.0 ~ 6.14+)
- **빌드 시스템**: GNU Make, CMake, Autotools
- **아키텍처**: x86, ARM64, ARM32, RISC-V, MIPS, PowerPC64, s390x

---

## 빌드 명령어

### GNU Make

```bash
make                          # 기본 빌드
make ARCH=arm64              # ARM64 빌드
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- CC=aarch64-linux-gnu-gcc
make ENABLE_IPS=1 ENABLE_VPN=1
make clean && make distclean  # 빌드 정리
```

### CMake

```bash
mkdir -p build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release -DENABLE_IPS=ON
cmake --build . && cmake --build . --target test
```

### 빌드 타겟

| 타겟 | 설명 |
|------|------|
| `all` | 기본 빌드 |
| `clean` | 빌드 파일 삭제 |
| `test` | 단위 테스트 실행 |
| `check` | 빌드 및 테스트 실행 |
| `install` | 바이너리 설치 |

---

## 테스트 명령어

```bash
make test                              # 전체 테스트 실행
make test TESTS="crypto_test"          # 특정 테스트 스위트 실행
./build/tests/ngfw_test --run=crypto/aes_cbc_encrypt  # 단일 테스트
```

### 커스텀 테스트 프레임워크

외부 테스트 프레임워크 없이 자체 프레임워크 사용:

```c
TEST_ASSERT(condition, message)
TEST_ASSERT_EQUAL(expected, actual)
TEST_ASSERT_NULL(ptr)
TEST_ASSERT_NOT_NULL(ptr)
TEST_SUITE(suite_name)
TEST_CASE(case_name)
```

---

## 코드 스타일 가이드라인

### 명명 규칙

| 요소 | 규칙 | 예시 |
|------|------|------|
| 함수 | `module_action()` | `session_create()` |
| 구조체 | `struct name_t` | `session_t` |
| 열거형 | `ENUM_VALUE` | `SESSION_STATE_NEW` |
| 매크로 | `MODULE_MACRO` | `MAX_PACKET_SIZE` |
| 변수 | `snake_case` | `session_id` |
| 상수 | `UPPER_SNAKE` | `MAX_CONNECTIONS` |
| 파일 | `snake_case.c/.h` | `session.c` |

### 포맷팅
- 들여쓰기: 4 spaces (탭 불가)
- 줄 길이: 최대 100자
- 중괄호: K&R 스타일
- 인클루드: 시스템 먼저, 그 다음 로컬 (정렬)

```c
#include <stdint.h>
#include <string.h>

#include "ngfw/core.h"
#include "ngfw/network.h"
```

### 타입
- 고정폭 타입 사용: `uint8_t`, `uint16_t`, `uint32_t`, `uint64_t`
- `inttypes.h` 사용: `PRIu32`, `PRId64`
- 네트워크 코드에서 `long`, `int` 사용 금지

### 오류 처리
- 성공 시 0 반환, 실패 시 음수 오류 코드 반환
- 표준 코드 사용: `-EINVAL`, `-ENOMEM`, `-ENOBUFS`, `-EIO`
- 클린업에 goto 패턴 사용

```c
int module_init(module_t *mod)
{
    int ret;
    if (mod == NULL) return -EINVAL;

    ret = resource_alloc(mod);
    if (ret != 0) goto cleanup_alloc;

    ret = state_init(mod);
    if (ret != 0) goto cleanup_state;

    return 0;

cleanup_state:
    resource_free(mod);
cleanup_alloc:
    return ret;
}
```

### 주석
- **명시적으로 요구하지 않는 한 주석 추가 금지**
- 자기문서화 코드 사용

### 메모리
- `malloc()`/`free()` 사용 시 오류 검사
- 영 초기화: `memset(&struct, 0, sizeof(struct))`
- 역순으로 메모리 해제

### 헤더 파일
- 인클루드 가드: `#ifndef MODULE_H #define MODULE_H ... #endif`
- 공개: `include/ngfw/`, 내부: `src/`

---

## 프로젝트 구조

```
ngfw/
├── Makefile, CMakeLists.txt, configure.ac
├── src/  (core, network, security, crypto, web, cli, platform)
├── include/ngfw/  (공개 헤더)
├── tests/  (테스트 스위트)
├── scripts/  (유틸리티)
└── etc/  (설정 파일)
```

---

## 모듈 설정

| 모듈 | 변수 | 기본값 |
|------|------|--------|
| Core | `ENABLE_CORE` | ON |
| Network | `ENABLE_NETWORK` | ON |
| IPS | `ENABLE_IPS` | ON |
| VPN | `ENABLE_VPN` | OFF |
| URL Filter | `ENABLE_URLFILTER` | ON |
| Anti-Virus | `ENABLE_ANTIVIRUS` | OFF |
| QoS | `ENABLE_QOS` | ON |

---

## 중요 사항

- **모든 파일에 중문(중국어), 일본어 사용 금지**: 코드, 주석, 문서, 커밋 메시지 등 모든 파일에서 중문과 일본어 문자 사용을 금지한다. 한글과 영어를 사용한다.

1. 외부 테스트 프레임워크 없음 - `tests/`의 커스텀 프레임워크 사용
2. x86, ARM64, RISC-V 등에서 컴파일 가능해야 함
3. 커널 6.0 ~ 6.14+ 호환성 필수
4. 보안 우선: 모든 입력 검증, 버퍼 오버플로우 방지
5. 목표: 10Gbps 이상 패킷 처리량
