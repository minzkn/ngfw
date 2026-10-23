# 16. 빌드/설치/배포 (Build & Deploy)

## 1. 빌드 시스템(R03)

| 구성 | 도구 | 역할 |
|---|---|---|
| 유저랜드 | Autotools(autoconf/automake) + GNU Make | configure → Makefile 생성, `make`/`make check`/`make install` |
| 커널 모듈 | Kbuild(커널 빌드 시스템) | `make -C /lib/modules/$(uname -r)/build M=kernel modules` |
| 스크립트 | POSIX sh | QEMU/Docker/이미지/릴리스 보조 스크립트(`scripts/`) |
| 래퍼 | 최상위 GNU Make | 자주 쓰는 조합 래핑(all/check/selftest/qemu/release) |

- 규칙: autoreconf 산출물(generated)은 저장소 커밋 금지, `make dist`로 소스 배포본 생성.
- 아웃오브트리 빌드 지원(`../build/ngfw-<platform>`), `VPATH` 빌드 유지.

## 2. 빌드 설정(configure 옵션)

| 옵션 | 기본 | 설명 |
|---|---|---|
| `--enable-debug` | off | asserts/sanitizer 친화 빌드(개발) |
| `--enable-selftest` | on | selftest 코드 포함(릴리스 유지 — R04) |
| `--with-kernel=` | 시스템 | 커널 빌드 트리 경로 |
| `--enable-xdp` | off | eBPF 툴체인 의존 활성화(`04` §6) |
| `--enable-openssl-compat` | **off** | 서드파티 암호 백엔드(검증/상호운용 실험용, R01: 기본 비활성) |
| `--prefix`, `--sysconfdir` 등 | 표준 | 설치 경로 |

## 3. 산출물

| 산출물 | 내용 |
|---|---|
| `ngfwd`, `ngfw-engine`, `ngfw`, `ngfw-doctor`, `ngfw-init`, `ngfw-tgen`, `ngfw-image` | 실행 파일(정적 libngfw 링크) |
| `ngfw.ko` | 커널 모듈(MODULE_VERSION 주입, `20`) |
| `libngfw.a` | 내부 라이브러리(외부 배포 대상 아님) |
| `webui/` 자원, `docs/api/openapi.json` | 정적 자원/API 문서 |
| `.deb`/`.rpm`/`tarball` | 범용 Linux 배포 패키지 |
| `ngfw-<ver>-<model>.img` | 어플라이언스 이미지(`§5`) |

## 4. 설치(범용 Linux)

- `make install` 표준 경로 + 서비스 등록(systemd unit 제공, 옵션), 모듈 로드(helper).
- 권한: `ngfwd` 초기 root → 권한 강하, `ngfw-engine` 전용 사용자(`18` §3).
- 설정 파티션/디렉터리 생성, 기본 설정 시드, `ngfw-doctor` 초기 진단 실행.

## 5. 어플라이언스 이미지

- 빌더: `ngfw-image`(자체 구현) — 파티션 레이아웃(부트/설정/시스템 A/B/로그), 커널+initramfs
  +rootfs(squashfs) 조립, GRUB(x86_64)/U-Boot(aarch64) 설치.
- 부트 선택: 부트로더 환경변수(A/B 슬롯, 부트 카운터 → 펌웨어 롤백, `11` §5).
- 이미지 서명: 매니페스트 + 자체 서명(ed25519), 설치/업그레이드 검증(`18` §4).

## 6. 빌드 재현성/품질 게이트

- 버전/빌드 메타스탬프는 `VERSION`+git에서 자동 주입(`20` §3).
- 게이트 순서: 컴파일 0경고 → `make check`(유닛) → selftest(유저랜드) → 커널 모듈 빌드 매트릭스
  → 패키지/이미지 생성 → QEMU 시스템 스모크(`17` §5). 하나라도 실패하면 릴리스 금지(R04).

## 7. 문서 생성

- OpenAPI JSON(REST 명세 소스 주석에서 생성), MIB 검증, 매뉴얼(`ngfw help` 소스 기반).

## Change log

- 2026-10-23: 초판 작성.
