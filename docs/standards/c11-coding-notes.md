# C11 준수 노트 (c11-coding-notes)

R02의 구체화. 유저랜드 C 코드의 언어 표준 규칙이다(커널 모듈은 커널 빌드 규칙을 따름, `style-guides.md` §2).

## 1. 컴파일 기준

```
-std=c11 -pedantic-errors        (기본; 컴파일러 확장 금지)
-Wall -Wextra -Werror            (릴리스)
-fno-strict-aliasing             (패킷 구조 해석 안전성)
```

- 지원 컴파일러: GCC ≥ 12, Clang ≥ 16. 지원 범위 밖 컴파일러는 이식 매트릭스에서 제외.
- 특성 탐지는 표준 매크로(`__STDC_VERSION__`, `__has_include` GCC/Clang 공통 확장은 platform에서만).

## 2. 허용/금지 기능

| 기능 | 판정 | 비고 |
|---|---|---|
| `_Static_assert`, `_Alignas`, `_Alignof`, `_Noreturn` | 허용 | C11 표준 |
| 익명 구조체/공용체 | 허용 | C11 표준 기능 |
| VLA(가변 길이 배열) | 금지 | 스택 오버플로 위험, 임베디드 관행 정합 |
| `restrict` | 허용 | 성능 크리티컬 경로 위주 |
| 복합 리터럴, 지정 초기화자 | 허용 | C99 이래 표준 |
| `#pragma` | 금지(빌드 옵션으로 통일) | 코드별 컴파일러 분기 방지 |
| `inline` | 허용 | static inline 중심 |
| 어트리뷰트 확장(`__attribute__`) | platform/diag 헤더 매크로로만 추상화 | 컴파일러 차이 흡수 |

## 3. 헤더 사용 규칙

- 전역 공용: `<stdint.h>`, `<stdbool.h>`, `<stddef.h>`, `<string.h>`, `<limits.h>`, `<errno.h>`,
  `<assert.h>`(디버그) — 휘발성 표준 헤더는 자유 사용.
- OS 의존 헤더(`<sys/...>`, `<pthread.h>`, `<unistd.h>` 등): **platform 서브시스템만** 허용
  (`designs/15-portability.md` §1, 검사 스크립트로 강제).
- 프로젝트 헤더는 `include/ngfw/` 공개 헤더 + 자기 서브시스템 내부 헤더만 포함.

## 4. 정수/자료형 규칙

- 고정폭 타입(`uint32_t` 등) 사용, `long`/`int`의 플랫폼 차이 의존 금지.
- 오버플로 의심 산술은 명시적 폭 확장 또는 검사 유틸(platform 제공 `npx_add_ovf` 계열).
- 바이트 순서 의존 데이터는 명시적 변환 함수(`netproto` 제공) 사용.

## 5. 메모리/에러 규칙

- 동적 할당은 platform 래퍼만 사용(통계/한도/재시도 정책 통일).
- `strcpy/strcat/sprintf` 금지, `snprintf`/크기 인자 계열만.
- 오류 반환: `int`(0 성공/음수 errno음 부호화) + 필요 시 out-param. 예외 없음(C 프로젝트).

## 6. 검증

- `make check`가 경고 0 + 유닛 통과를 강제(`designs/17` §3).
- `-std=c11 -pedantic-errors` 위반 소스는 즉시 결함으로 분류한다.
