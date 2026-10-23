# 검증 환경(QEMU/KVM/Docker) 구성 노트

ngfw 프로젝트의 시스템 테스트(QEMU 부팅 + ngfw-tgen 트래픽 + 골드 시나리오 `tests/scenarios/*.yaml`)와
어플라이언스 이미지(`ngfw-image`: boot/config/system A/B/log 파티션) 검증을 위한
QEMU/KVM/Docker 실행 환경 구성 지침이다.

용어 정리:

- 시스템 테스트(system test): QEMU로 어플라이언스 이미지를 부팅하고 `ngfw-tgen` 트래픽을 인젝션한 뒤
  골드 시나리오(`tests/scenarios/*.yaml`)의 기대 결과와 비교하는 end-to-end 검증.
- 어플라이언스 이미지(appliance image): `ngfw-image` 툴이 생성하는 부팅 디스크.
  파티션 구성: boot / config / system A / system B / log.

## 1. QEMU 실행 구성

### 1.1 아키텍처별 바이너리

| 대상 | QEMU 바이너리 | 비고 |
| --- | --- | --- |
| x86_64 | `qemu-system-x86_64` | 호스트와 동종 아키텍처, KVM 사용 가능 |
| aarch64 | `qemu-system-aarch64` | `-M virt` 머신 + EDK2/U-Boot 펌웨어 필요 |

- x86_64는 SeaBIOS/UEFI(OVMF) 모두 동작한다. boot 파티션 검증이 목적이면 OVMF(UEFI) 경로를 기본으로 권장한다.
- aarch64는 `-M virt -cpu cortex-a57`(또는 `max`)에 EDK2 aarch64 펌웨어(`QEMU_EFI.fd`)를 붙여 부팅한다.

### 1.2 네트워킹: virtio-net + tap/브리지

패킷이 VM 간 실제 경로로 흘러야 하므로 user-mode networking(`-netdev user`)이 아니라
tap + 브리지를 기본으로 사용한다.

```sh
# 호스트 브리지 준비 (1회)
ip link add br-test0 type bridge
ip link set br-test0 up
ip tuntap add dev tap0 mode tap
ip link set tap0 master br-test0
ip link set tap0 up
```

VM 측 NIC은 항상 virtio-net(`virtio-net-pci`)을 사용한다. e1000은 폴백용으로만 허용한다.

```sh
qemu-system-x86_64 \
  -machine q35,accel=kvm -cpu host -smp 2 -m 1024 \
  -drive file=ngfw-image.img,if=virtio,format=raw \
  -netdev tap,id=net0,ifname=tap0,script=no,downscript=no \
  -device virtio-net-pci,netdev=net0,mac=52:54:00:aa:00:01 \
  -serial file:logs/dut-serial.log -display none -daemonize
```

### 1.3 2~3 VM 토폴로지 예시

기본 토폴로지는 "DUT(ngfw) 1 + 트래픽 생성기(ngfw-tgen) 1~2" 구조다.

- 2-VM: tgen-left — br-test0 — ngfw(ingress/egress) — br-test1 — tgen-right
- 3-VM: 위 구성에 관리용 br-mgmt(DUT의 세 번째 NIC)를 추가

예시(2-VM, 브리지 2개):

```sh
# DUT (ngfw appliance)
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 2 -m 1024 \
  -drive file=ngfw-image.img,if=virtio,format=raw \
  -netdev tap,id=n0,ifname=tap0,script=no -device virtio-net-pci,netdev=n0,mac=52:54:00:aa:00:01 \
  -netdev tap,id=n1,ifname=tap1,script=no -device virtio-net-pci,netdev=n1,mac=52:54:00:aa:00:02 \
  -serial file:logs/dut-serial.log -display none -daemonize -pidfile run/dut.pid

# tgen (ngfw-tgen): 좌/우 인터페이스를 브리지 2개에 각각 연결
qemu-system-x86_64 -machine q35,accel=kvm -cpu host -smp 1 -m 512 \
  -drive file=tgen-rootfs.img,if=virtio,format=raw \
  -netdev tap,id=n0,ifname=tap2,script=no -device virtio-net-pci,netdev=n0,mac=52:54:00:bb:00:01 \
  -netdev tap,id=n1,ifname=tap3,script=no -device virtio-net-pci,netdev=n1,mac=52:54:00:bb:00:02 \
  -serial file:logs/tgen-serial.log -display none -daemonize -pidfile run/tgen.pid
```

3-VM 토폴로지는 위 DUT 정의에 `-netdev tap,id=n2,ifname=tap4`(br-mgmt)를 추가하고
tgen VM을 좌/우 2개로 분리한 뒤 각각 tap0/tap1 계열에 물리면 된다.

## 2. KVM 가속 유무 분기

CI 러너/컨테이너에는 `/dev/kvm`이 없을 수 있으므로 실행 전에 반드시 분기한다.

```sh
if [ -c /dev/kvm ] && [ -w /dev/kvm ]; then
    ACCEL="kvm"
    CPU_ARGS="-cpu host"
else
    ACCEL="tcg"
    CPU_ARGS="-cpu max"
fi
qemu-system-x86_64 -machine "q35,accel=${ACCEL}" ${CPU_ARGS} ...
```

- `/dev/kvm`은 존재(`-c`)와 쓰기 가능(`-w`)을 모두 확인해야 한다. 존재만으로는 권한 문제로 실패할 수 있다.
- TCG 폴백 시 부팅이 수십 배 느려지므로 타임아웃 상수를 accel별로 분리하고, 테스트 수를 줄인 스모크 모드로 운영한다.
- aarch64의 `-accel kvm`은 호스트가 aarch64일 때만 유효하다. x86_64 호스트에서의 aarch64 게스트는 TCG가 기본이다.
- 2차 검증으로 `qemu-system-* -accel help` 출력을 파싱해 지원 accel을 확인하는 것을 권장한다.

## 3. 커널 모듈 테스트

### 3.1 커널 이미지 + vmlinuz/initramfs 준비

커널 모듈(.ko)은 빌드에 사용한 커널과 동일 버전/설정의 커널에서만 로드된다(vermagic 확인).

- 준비물: `vmlinuz`(bzImage/Image) + initramfs(모듈/busybox 포함) + 모듈 트리.
- initramfs에 ngfw 모듈과 `modprobe` 유틸리티를 넣어 부팅 직후 modprobe/insmod 검증이 가능하게 한다.

```sh
# initramfs에 모듈 포함 예시
mkdir -p initramfs/lib/modules/${KVER}
make -C linux modules_install INSTALL_MOD_PATH=$(pwd)/initramfs
find initramfs | cpio -o -H newc | gzip > initramfs-ngfw.cpio.gz
```

```sh
qemu-system-x86_64 -machine q35,accel=kvm -m 512 \
  -kernel vmlinuz -initrd initramfs-ngfw.cpio.gz \
  -append "console=ttyS0 nokaslr" \
  -netdev tap,id=n0,ifname=tap0,script=no -device virtio-net-pci,netdev=n0 \
  -serial file:logs/modtest-serial.log -display none
```

### 3.2 호스트 커널과의 일치 필요성

- 모듈은 호스트(WSL/CI 러너) 커널이 아니라 QEMU 게스트 커널에 로드한다. 따라서 "호스트 커널 버전 = 게스트 커널 버전"은
  요구사항이 아니며, 게스트 내부 일관성(빌드 커널 == 부팅 커널)만 맞으면 된다.
- 단, `modinfo`의 vermagic, `CONFIG_MODVERSIONS`, 심볼 CRC가 빌드 트리와 부팅 이미지 사이에서 일치해야 한다.
- 호스트에 직접 모듈을 올리는 방식은 커널 패닉 위험과 CI 격리 훼손 때문에 금지한다. 모듈 테스트는 항상 QEMU 게스트 안에서 수행한다.

## 4. Docker — glibc/musl 빌드 매트릭스

### 4.1 빌드 매트릭스

| 이미지 | libc | 용도 |
| --- | --- | --- |
| `ubuntu:24.04` 계열 | glibc | 주 타겟 빌드 + 유닛 테스트 |
| `alpine:3.x` | musl | libc 비의존성/정적 링크 확인 |

- 같은 소스 트리를 두 이미지에서 각각 빌드해 경고/에러 차이를 수집한다(컴파일러/공통 CMake flags는 동일하게 유지).
- musl에서만 나오는 대표 이슈: `strlcpy`, `<error.h>`, `qsort_r` 등 glibc 전용 확장 사용 여부.

### 4.2 컨테이너에서 유저랜드 유닛/selftest 실행

```sh
docker run --rm -v "$PWD":/src -w /src ubuntu:24.04 \
  sh -c "apt-get update && apt-get install -y build-essential cmake \
      && cmake -S . -B build && cmake --build build -j \
      && ctest --test-dir build --output-on-failure"
```

- 유저랜드 유닛 테스트와 `selftest`(호스트 프로세스 대상)는 컨테이너 실행에 적합하다. 파일시스템/프로세스 격리만으로 충분하기 때문이다.
- `ngfw-tgen` 자체 빌드와 루프백 대상 스모크 실행도 컨테이너에서 가능하다.

### 4.3 커널 모듈은 Docker 부적합

- 컨테이너는 호스트 커널을 공유한다. `insmod`는 호스트 커널 상태를 직접 변경하므로
  (1) 모듈이 호스트 커널 버전과 불일치해 로드에 실패하거나,
  (2) 로드되더라도 패닉 시 CI 러너 전체가 죽는다.
- 결론: 커널 모듈 검증은 §3의 QEMU 게스트 경로로만 수행하고, Docker는 유저랜드 전용으로 한정한다.

## 5. 부팅 자동화

### 5.1 직렬 콘솔 로그 캡처

- `-serial file:logs/<vm>.log`로 부팅/셧다운 전 과정을 캡처한다. `-nographic` + stdio 파이프보다 파일 분리가 CI 회수에 유리하다.
- 실시간 관찰이 필요하면 `-serial unix:run/<vm>-serial.sock,server,nowait` + `socat` 중계를 쓸 수 있지만, 기본은 파일 캡처다.

### 5.2 selftest 자동 실행 트리거

- 어플라이언스 이미지의 config 파티션에 `autostart` 마커를 심고, init 스크립트가 부팅 완료 직후 `ngfw selftest`를 실행해
  결과를 log 파티션과 직렬 콘솔 양쪽에 기록하게 한다.
- 게스트 완료 신호는 qemu-guest-agent 대신 직렬에 `SELFTEST-DONE rc=<n>` 라인을 출력하는 방식이 의존성이 적다.

### 5.3 결과 수집(JUnit 유사 XML)

- 호스트는 직렬 로그에서 `TEST <name> ... PASS/FAIL` 라인을 파싱해 JUnit 유사 XML로 변환한다.

```xml
<testsuite name="ngfw-selftest" tests="12" failures="1">
  <testcase name="pktbuf" classname="ngfw.selftest" time="0.3"/>
  <testcase name="flow-hash" classname="ngfw.selftest">
    <failure message="mismatch at case 7"/>
  </testcase>
</testsuite>
```

- CI(Jenkins/GitLab)는 이 XML을 바로 소비할 수 있다. 시나리오 레벨(`tests/scenarios/*.yaml`) 결과도 같은 스키마로 통일한다.

## 6. `scripts/qemu-run.sh` 구현 지침

역할: 토폴로지 yaml → 실행 → 검증 → 정리 사이클을 한 커맨드로 수행한다.

```
scripts/qemu-run.sh --topology tests/scenarios/topo-2vm.yaml \
                    --image out/ngfw-image.img \
                    --out results/20261023-01
```

동작 단계:

1. **토폴로지 파싱**: yaml에서 VM 목록(role: dut|tgen), 브리지/tap 이름, MAC, 메모리/CPU, 디스크 이미지, 시리얼 로그 경로를 읽는다.
   - bash만으로 yaml을 파싱하지 말고 `yq`(또는 python3 + PyYAML) 사용을 전제로 하고, 의존성을 문서화한다.
2. **자원 준비**: 브리지/tap 생성(존재하면 재사용), `$out/{run,logs}` 생성, pid/sock 경로 충돌 검사.
3. **실행**: accel 분기(§2)를 적용해 VM을 `-daemonize`로 기동하고 pid를 `$out/run/*.pid`에 저장한다.
4. **검증**: 직렬 로그 tail로 부팅 완료 마커 대기(타임아웃은 accel별 상수), ngfw-tgen 트래픽 인젝션,
   골드 시나리오(`tests/scenarios/*.yaml`) 기대값과 대조, §5.3 XML 생성까지 수행한다.
5. **정리**: SIGTERM → 유예 대기 → SIGKILL 순으로 VM 종료, tap/브리지 제거(재사용분 제외), 임시 파일 정리.
   - `trap cleanup EXIT INT TERM`으로 비정상 종료 시에도 정리가 실행되게 한다.
6. **반환 코드**: 테스트 실패와 환경 실패(부팅 타임아웃 등)를 구분한다(예: 0=pass, 1=test-fail, 2=env-fail).

주의:

- 데몬 VM은 `kill $(cat pid)` 후 `wait`가 불가하므로 pid 존재 폴링으로 종료를 확인한다.
- 같은 러너에서 병렬 실행 시 tap 이름 충돌을 피하려면 tap 인덱스를 `$out` 경로 해시에서 파생시킨다.

## Change log

- 2026-10-23: 초판 작성.
