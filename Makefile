#Copyright (C) 2021 Intel Corporation
#SPDX-License-Identifier: Apache-2.0
#
# Version 0.1.0

.PHONY: docker
docker:
	docker build -f Dockerfile .

#
# Used when merging code in github actions CI
#
.PHONY: github-docker-merge
github-docker-merge:
	docker build --push -t "${TAGS}" -f Dockerfile .

#
# Used when building pull requests in github actions CI
#
.PHONY: github-docker-pull-request
github-docker-pull-request:
	docker build -t "${TAGS}" -o type=oci,dest="${TAR_EXPORT}" -f Dockerfile .
