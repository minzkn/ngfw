# docs/ — 표준·조사·참조 자료

설계 문서(`designs/`)가 참조하는 표준 요약, 조사 노트, 원문 참조 파일의 모음이다.
여기의 문서는 **조사/요약이며 설계 결정은 `designs/`에만 둔다**(P-A).

## 구조

| 디렉터리/파일 | 내용 |
|---|---|
| `standards/standards-map.md` | 기능↔표준 매핑 총표(유일 출처, R10) |
| `standards/rfc-catalog.md` | 참조 RFC 카탈로그(번호/제목/사용 위치) |
| `standards/c11-coding-notes.md` | C11 준수 규칙(허용 기능/헤더/경고 세트) |
| `standards/style-guides.md` | GNU 코딩 스타일·커널 코딩 스타일 요약 및 적용 규칙 |
| `standards/posix-portability-notes.md` | POSIX.1-2017 사용 범위와 이식 원칙 |
| `standards/semver-notes.md` | SemVer 2.0.0 요약 및 프로젝트 적용 |
| `research/*.md` | 조사 노트(제품 비교, DPI 기법, 시그니처 문법, 오프로드, netlink, 성능 방법론, 검증 환경, 상호운용) |
| `references/` | 원문 표준 텍스트(RFC 등) 사본 + 출처 안내 |
| `benchmarks/` | 성능 측정 기록(`designs/14` §2 절차의 산출물, 측정 후 생성) |
| `mibs/` | SNMP MIB 파일(`designs/12` §4) |

## 규칙

- 조사 노트의 사실 주장은 가능한 출처(RFC 번호/URL/커널 문서 경로)를 명시한다.
- 확인 불가능한 주장은 "(미검증)"으로 표기하고 검증 방법을 적는다.
- `references/` 원문은 변경하지 않는다(사본 보존).
