# SemVer 2.0.0 노트 (semver-notes)

R14 적용 요약. 원문: Semantic Versioning 2.0.0(semver.org).

## 1. SemVer 2.0.0 핵심 규칙 요약

- 형식: `MAJOR.MINOR.PATCH[-prerelease][+build]`.
- MAJOR: 하위 호환 없는 API 변경 시 증가. MINOR: 하위 호환 기능 추가 시. PATCH: 하위 호환
  결함 수정 시.
- 0.x.y: 초기 개발, 안정성 보장 없음(프로젝트 초기 단계 적용).
- prerelease(`-rc.1` 등)는 동일 버전 대 낮은 우선순위로 비교. build 메타(`+...`)는 비교 제외.

## 2. 프로젝트 적용(`designs/20-naming-versioning.md`와 정합)

| SemVer 요소 | ngfw에서의 의미 |
|---|---|
| MAJOR | 파괴적 변경: genl 계약/플러그인 ABI/설정 스키마 비호환, 마이그레이션 필요 |
| MINOR | 하위 호환 추가: 신규 genl cmd/attr(읽는 쪽 관대), 시그니처 키워드, REST 엔드포인트 추가 |
| PATCH | 결함 수정, 성능 개선(외부 계약 불변) |
| prerelease | `-rc.N`, `-dev.N` |
| build | `+<git-sha8>.<yyyymmdd>` — 산출물 추적용 |

## 3. 버전 비교 규칙(구현 시)

- 우선순위 비교는 SemVer 사양의 알고리즘 그대로 구현(`netproto` 유틸 `npro_semver_cmp`).
- 펌웨어 다운그레이드 방지(`designs/18` §6)에서는 MAJOR.MINOR.PATCH만 비교(build 제외).

## 4. 예시

```
0.1.0-dev.3+1a2b3c4d.20261023   # 개발 스냅샷
0.1.0                           # M1 기능 릴리스
1.0.0-rc.1                      # 첫 안정 후보
1.2.3+9f8e7d6c.20261023         # 유지보수 릴리스
```
