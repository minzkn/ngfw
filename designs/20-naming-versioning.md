# 20. 제품명/모델명/버전 관리 (R14)

## 1. 단일 출처 파일 `VERSION`

저장소 루트 `VERSION` 파일이 유일 출처이다. 형식(key=value 줄):

```
product=ngfw
model_series=VM,X
version=0.1.0
release=0
vendor=minzkn
```

- 모든 산출물(데몬/모듈/패키지/이미지/WebUI/about)은 빌드 시 이 파일에서 버전을 읽어 주입한다.
- 직접 하드코딩 금지: 소스에 버전 문자열을 박지 않는다(생성 헤더만 사용).

## 2. 버전 형식(SemVer 2.0.0)

- `MAJOR.MINOR.PATCH[-prerelease][+build]`:
  - MAJOR: ABI/설정 스키마/커널 genl 계약 파괴적 변경(마이그레이션 필요)
  - MINOR: 하위 호환 기능 추가(예: 신규 시그니처 키워드, genl cmd 추가)
  - PATCH: 결함 수정
  - build: `+<git-sha8>.<build-date>` (산출물 식별용, 의미 비교 제외)
- 사전 배포: `0.x.y`(초기), `-rc.N`, `-dev.N` 접미사.

## 3. 버전 주입 메커니즘

| 산출물 | 주입 방법 |
|---|---|
| 유저랜드 | configure.ac가 VERSION을 읽어 `AC_INIT`/config.h, `include/ngfw/version.h` 생성 |
| 커널 모듈 | 빌드 스크립트가 `-DMODULE_VERSION=` 전달, `MODULE_INFO` |
| 패키지/이미지 | `scripts/release.sh`가 VERSION 읽어 파일명/메타데이터 생성 |
| genl 계약 | 모듈과 데몬의 계약 버전 별도 관리(`family version`, `03` §7) — 제품 버전과 분리 |

- 일치성 검사: `ngfw selftest version`이 전 구성요소 버전(데몬/모듈/시그니처 DB/WebUI)을 수집
  비교, 불일치 시 FAIL(하드닝: 혼합 버전 운영 방지).

## 4. 모델명 규칙

- 형식: `ngfw-<series>[.variant]`. 시리즈는 `VERSION`의 `model_series`에서 관리(`01` §4).
- 모델별 활성 기능/한계는 설정 프로파일로 적용(빌드 분기 없음 — 단일 빌드 원칙).

## 5. 변경 절차

1. VERSION 수정 → 2. `designs/` 해당 문서 Change log 갱신 → 3. 릴리스 스크립트가 태그
  `v<version>` 생성 → 4. CI 게이트(`16` §6) 통과 후 산출물 게시.

## Change log

- 2026-10-23: 초판 작성.
