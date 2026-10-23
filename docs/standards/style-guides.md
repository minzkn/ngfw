# 코딩 스타일 가이드 요약 (style-guides)

R02/R12 적용 요약. 원문: GNU Coding Standards(GNU 프로젝트), Linux kernel coding style
(`Documentation/process/coding-style.rst`, 커널 소스 트리 내 문서).

## 1. 유저랜드 — GNU 코딩 스타일

| 항목 | 규칙 |
|---|---|
| 들여쓰기 | 공백 2칸 |
| 중괄호 | GNU 스타일(함수는 열림 중괄호 줄 시작, 블록 내부는 줄 전환) |
| 식별자 | snake_case(함수/변수), 파일 접두사는 서브시스템(예: `npx_`, `nfc_`) |
| 매크로/enum | UPPER_SNAKE |
| 주석 | 영문(R02). `/* ... */` 기본, 필요 시 Doxygen 유사 태그. 코드가 말하는 것 재서술 금지 |
| 줄 길이 | 80 권장, 100 초과 금지 |
| 공백 | 키워드 뒤 공백(`if (x)`), 함수명 뒤 붙임(`foo(x)`) |
| 파일 구조 | 저작권/설명 헤더(저장소 규정) → include → 매크로 → 타입 → 전역 → 함수 |

GNU 스타일 예:

```c
int
nfc_ring_push (struct nfc_ring *ring, const void *item)
{
  if (ring == NULL || item == NULL)
    {
      return -1;
    }
  return 0;
}
```

## 2. 커널 모듈 — Linux kernel coding style

| 항목 | 규칙 |
|---|---|
| 들여쓰기 | 탭 1개(폭 8) |
| 중괄호 | K&R 스타일(함수 열림 중괄호는 줄 시작, 나머지는 끝에) |
| 줄 길이 | 80 컬럼 엄수 |
| 식별자 | snake_case, 커널 접두사 관행(`ngfw_`) |
| 오류 경로 | goto 기반 클린업 컨벤션 허용(커널 관행) |
| 주석 | 영문(R02), `/* ... */` 스타일 |
| API | 커널 제공 인프라 사용(요약: `designs/03` §11) |

커널 스타일 예:

```c
static int ngfw_hook_forward(void *priv, struct sk_buff *skb,
			     const struct nf_hook_state *state)
{
	struct ngfw_session *sess;

	sess = ngfw_session_lookup(skb);
	if (!sess)
		return ngfw_session_create(skb, state);
	return ngfw_verdict_apply(sess, skb);
}
```

## 3. 공통 규칙(두 스타일 공통)

- 주석/식별자/로그/문서 문자열은 영문(R02).
- 주석은 WHY(제약/근거)를 담는다. WHAT 재서술 금지. 규정(`designs/` 문서) 참조는 주석 대신
  문서 ID(예: `see designs/03 §5`) 허용.
- 데드 코드/주석 처리된 코드 커밋 금지.
- 함수는 단일 책임, 100줄 초과 시 분할 재검토(경고 수준).

## 4. 스타일 검사

- `scripts/check-style.sh`: 정규식 기반 최소 점검(탭/공백/줄길이/접두사) + 컴파일러 경고 정책.
- 완전 자동 검사는 한계가 있으므로 코드 리뷰 기준을 보조로 사용(`designs/17` §3).
