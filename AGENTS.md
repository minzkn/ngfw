# AGENTS.md — ngfw

에이전트(caglue 포함)가 이 저장소에서 작업할 때 따라야 할 프로젝트 규칙이다.
상위 근거는 `designs/00-principles.md`(요구 원칙 R01~R14, ADR)이며, 이 문서는 그 운영 요약이다.

## 프로젝트 개요

- Linux 6.12+ 기반 **자체 구현 NGFW**. 런타임 외부 라이브러리 금지 — 부트로더, Linux kernel,
  libc만 사용(R01). 유저랜드 공용 코드는 `libngfw` 단일 정적 라이브러리(ADR-003).
- 전부 C11. 진행 상태: M0(골격) 완료. 다음 작업은 루트 `TODO.md` 순서를 따른다.
- 설계 문서: `designs/`(23편, `designs/README.md`가 인덱스). 표준/조사 자료: `docs/`.

## 필수 규칙 (위반은 결함으로 취급)

1. **문서 선행 (P-F)**: 코드 변경 전에 해당 `designs/` 문서를 먼저 갱신한다.
   코드-문서 불일치는 결함이다. 인터페이스 계약(genl ops, TLV 타입, artifact 포맷 등)을
   바꾸면 계약 문서(`03` §7, `05` §8 등)와 소비자 문서를 함께 갱신한다.
2. **단일 출처 (P-A)**: 다음은 지정 문서 1곳에만 존재한다 — 제품명/버전(`VERSION` 파일,
   규칙 `20`), 기능 목록(`01` F-카탈로그), 모듈 맵(`02` §7), 각 인터페이스 계약(기술 문서).
   다른 곳에 복제/재서술하지 않고 참조만 한다.
3. **TODO.md 관리**: 구현이 완료되면(빌드 + `make check` + 해당 문서의 selftest 케이스 통과)
   `TODO.md`에서 해당 줄을 **즉시 삭제**한다. 체크만 남기지 않는다. 신규 항목은 designs/ 문서
   갱신 후 추가하고, 마일스톤 미배정이면 "미배정" 섹션에 둔다.
4. **언어/스타일**: 본문 문서·응답은 한국어, 기술 용어/식별자는 영문. **코드 주석·식별자는
   영문 전용(R02)**. 유저랜드는 GNU 코딩 스타일(공백 2칸 들여쓰기, 탭 금지), `kernel/`은
   Linux 커널 코딩 스타일. 요약: `docs/standards/style-guides.md`.
5. **계층 경계 (R08)**: OS/POSIX 헤더는 `src/lib/platform/` 만 직접 포함한다. libngfw 내부는
   `include/ngfw/` 공개 헤더 + 자기 서브시스템 헤더만. 커널 모듈(`kernel/`)은 커널 API만
   사용하고 libngfw에 의존하지 않는다.
6. **외부 의존 금지 (R01)**: 새 라이브러리/툴체인 의존을 추가하지 않는다. 빌드 타임 툴
   (autoconf/automake/make/sh)만 허용. 서드파티 백엔드(OpenSSL 등)는 `--enable-openssl-compat`
   로 검증용 옵트인만 가능(기본 off).
7. **C11 엄격**: `-std=c11 -pedantic-errors -Wall -Wextra -Werror`(기본). VLA 금지, `strcpy/
   strcat/sprintf` 금지, 동적 할당은 `npx_*` 래퍼 경유. 규칙 전문:
   `docs/standards/c11-coding-notes.md`.
8. **빌드 계약(구현에서 확정됨)**: (a) `config.h`를 사용하는 파일은 **가장 먼저** `#include
   "config.h"`(피처 매크로 선행). (b) 프로그램 소스 **디렉터리 이름 ≠ 산출물 이름**
   (automake 링크 규칙 `rm -f <program>` 충돌 — CLI 소스는 `src/cli/ngfw.c`).

## 빌드/테스트 명령

```sh
./bootstrap          # 최초 1회 또는 configure.ac/Makefile.am 변경 후 (autoreconf -fiv)
./configure          # 기본: -Werror on, --disable-werror로 해제
make                 # 빌드
make check           # 유닛 테스트(automake TESTS)
make selftest        # ./src/ngfw selftest all (런타임 selftest)
./src/ngfw selftest all -v   # 모듈 지정: platform|core|version|all
```

- 아웃오브트리(VPATH) 빌드 지원: `mkdir build && cd build && ../configure && make`.
  단, in-tree가 이미 configure된 상태에서는 먼저 `make distclean`.
- 커널 모듈(M1~)은 Kbuild로 별도 빌드(`16` §1). 컨테이너에서 커널 모듈 빌드/테스트 금지
  (호스트 커널 의존) — QEMU 사용(`17` §5~6).

## 검증 기준 (완료 보고 전 필수)

- `make check` 통과(0 실패) + 변경 대상 모듈의 `ngfw selftest <module>` 통과.
- 새 기능은 골드 케이스 + 실패 케이스(엣지/오류 입력)를 selftest에 포함(F15).
- 성능/메모리 수치는 `designs/14` §2 측정 절차의 산출물만 인용. 측정 전 수치는 "목표"로만
  표기(P-G). 확인 불가한 사실 주장은 "(미검증)" 표기.
- 빌드 산출물(`*.o`, `config.h`, `include/ngfw/version.h` 등)은 커밋 금지(`.gitignore` 유지).

## 코딩 관례

- 접두사: platform `npx_`, core `nfc_`, selftest `nst_`. 식별자 snake_case, 매크로/enum
  UPPER_SNAKE.
- 새 서브시스템/새 산출물 추가는 `02` §7 모듈 맵과 ADR(`00` §3~4)을 먼저 갱신한다.
  동일 목적의 중복 구현 생성 금지(R07) — 확장은 기존 서브시스템이 우선.
- 주석은 WHY(제약/근거/계약 참조)를 담는다. WHAT 재서술/데드 코드 금지.
- 설정 포맷은 JSON(ADR-006), 파서는 `src/lib/core/nfc_config.c`의 엄격 RFC 8259 구현을
  재사용한다(별도 파서 생성 금지).

## 금지 사항

- `docs/references/` 원문(RFC 사본) 편집/재포맷 금지.
- 소스에 버전/제품명 하드코딩 금지 — `include/ngfw/version.h`(생성물)만 사용(`20`).
- 커널 deprecated API, glibc 전용 확장의 직접 사용(`docs/standards/posix-portability-notes.md` §4).
- git commit/branch 조작, 파일 삭제, 시스템 설치 등 파괴적 동작은 사용자 명시 지시 없이 금지.
- `requirement.txt`, `designs/`, `docs/` 내용을 코드 사본으로 복제하지 않는다(참조만).

## 참조 문서

| 목적 | 문서 |
|---|---|
| 전체 인덱스/용어 | `designs/README.md` |
| 원칙/ADR | `designs/00-principles.md` |
| 남은 작업 | `TODO.md` |
| 빌드/배포 계약 | `designs/16-build-deploy.md` |
| 테스트/selftest 체계 | `designs/17-testing-selftest.md` |
| 이식성 규칙 | `designs/15-portability.md`, `docs/standards/posix-portability-notes.md` |
| 코딩 스타일 | `docs/standards/style-guides.md`, `docs/standards/c11-coding-notes.md` |
| 버전 규칙 | `designs/20-naming-versioning.md`, `docs/standards/semver-notes.md` |
