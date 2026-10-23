#!/bin/sh
# Build/test matrix across container images (glibc and musl based).
# See designs/17-testing-selftest.md section 6. The kernel module is NOT built
# here because containers share the host kernel; module tests use QEMU.
set -eu
cd "$(dirname "$0")/.."

command -v docker >/dev/null 2>&1 || { echo "docker not found" >&2; exit 1; }

MATRIX="ubuntu:24.04 alpine:3.20"

for image in $MATRIX; do
	echo "== $image =="
	docker run --rm -v "$(pwd)":/src -w /src "$image" sh -c '
		set -eu
		if command -v apk >/dev/null 2>&1; then
			apk add --no-cache build-base autoconf automake
		elif command -v apt-get >/dev/null 2>&1; then
			apt-get update -qq
			DEBIAN_FRONTEND=noninteractive apt-get install -y -qq build-essential autoconf automake
		else
			echo "no supported package manager in $0 image" >&2
			exit 1
		fi
		./bootstrap
		./configure
		make
		make check
	'
done
