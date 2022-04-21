#!/bin/bash
#
# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Version 0.1.0

set -x

#
# Check if docker buildx is usable
#
function check_buildx() {
        if ! command -v docker >/dev/null 2>&1; then
                echo "Can't find docker. Install first!!" >&2
                return 1
        fi

        docker_version="$(docker version --format '{{.Server.Version}}')"
        if [[ "$(version "$docker_version")" < "$(version '19.03')" ]]; then
                error "docker $docker_version too old. Need >= 19.03"
                return 1
        fi

        docker_experimental="$(docker version --format='{{.Server.Experimental}}')"
        if [[ "$docker_experimental" != 'true' ]]; then
                export DOCKER_CLI_EXPERIMENTAL=enabled
        fi

        kernel_version="$(uname -r)"
        if [[ "$(version "$kernel_version")" < "$(version '4.8')" ]]; then
                echo "Kernel $kernel_version too old, need >= 4.8 to build with --platform." >&2
                return 1
        fi

        if [[ "$(mount | grep -c '/proc/sys/fs/binfmt_misc')" == '0' ]]; then
                echo "/proc/sys/fs/binfmt_misc not mounted." >&2
                return 1
        fi
        distro=$(cat /etc/os-release | grep "^ID=" | cut -d= -f2)
        if [[ "$distro" = "fedora" ]]; then
                if ! systemctl is-active --quiet systemd-binfmt ; then
                        echo "Service systemd-binfmt is not started"
                        return 1
                fi
        elif [[ "$distro" = "ubuntu" ]]; then
                if ! command -v update-binfmts >/dev/null 2>&1; then
                        echo "Can't find update-binfmts." >&2
                        return 1
                fi

                binfmt_version="$(update-binfmts --version | awk '{print $NF}')"
                if [[ "$(version "$binfmt_version")" < "$(version '2.1.7')" ]]; then
                        echo "update-binfmts $binfmt_version too old. Need >= 2.1.7" >&2
                        return 1
                fi
        fi

        if [[ ! -e '/proc/sys/fs/binfmt_misc/qemu-aarch64' ]]; then
                # Skip this test if QEMU isn't registered with binfmt_misc. It might
                # come from a docker image rather than the host file system.
                if [[ ! -e '/usr/bin/qemu-aarch64-static' ]]; then
                        echo "Missing QEMU."  >&2
                        return 1
                fi
        fi
        if [[ ! -e '/proc/sys/fs/binfmt_misc/qemu-aarch64' ]]; then
                echo "QEMU not registered in binfmt_misc." >&2
                return 1
        fi
        flags="$(grep 'flags:' /proc/sys/fs/binfmt_misc/qemu-aarch64 | cut -d' ' -f2)"
        if [[ "$(echo "$flags" | grep -c F)" == '0' ]]; then
                echo "QEMU not registered in binfmt_misc with fix-binary (F) flag." >&2
                return 1
        fi
}

if check_buildx ; then
	BUILDCMD+=("buildx" "build")
else
	BUILDCMD+=("build")
fi

if [ "${1}" == "merge" ] ; then
	if [[ "${TAGS}" != "" ]] ; then
		IFS="," read -r -a TAG_LIST <<< "${TAGS}"
		for i in "${TAG_LIST[@]}" ; do
			ARGS+=("--tag" "${i}")
		done
	fi
	docker "${BUILDCMD[@]}" --push -f Dockerfile "${ARGS[@]}" .
fi

#
# Used when building pull requests in github actions CI
#
if [ "${1}" == "pull-request" ] ; then
	if [[ "${TAGS}" != "" ]] ; then
		IFS="," read -r -a TAG_LIST <<< "${TAGS}"
		for i in "${TAG_LIST[@]}" ; do
			ARGS+=("--tag" "${i}")
		done
	fi
	docker "${BUILDCMD[@]}" -o type=oci,dest="${TAR_EXPORT}" -f Dockerfile "${ARGS[@]}" .
fi
