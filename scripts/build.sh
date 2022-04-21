#!/bin/bash
#
# Copyright (C) 2021 Intel Corporation
# SPDX-License-Identifier: Apache-2.0
#
# Version 0.1.0

set -x

if [ "${1}" == "merge" ] ; then
	if [[ "${TAGS}" != "" ]] ; then
		IFS="," read -r -a TAG_LIST <<< "${TAGS}"
		for i in "${TAG_LIST[@]}" ; do
			ARGS+=("--tag" "${i}")
		done
	fi
	docker build --push -f Dockerfile "${ARGS[@]}" .
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
	docker build -o type=oci,dest="${TAR_EXPORT}" -f Dockerfile "${ARGS[@]}" .
fi
