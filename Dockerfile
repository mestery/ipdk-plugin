#Copyright (C) 2021 Intel Corporation
#SPDX-License-Identifier: Apache-2.0
#
# Version 0.1.0

# Build
FROM golang:1.18-buster AS build
LABEL maintainer="mestery@mestery.com"

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY *.go ./
COPY *.json /

RUN go build -o /ipdk-plugin

# Deploy
FROM gcr.io/distroless/base-debian11

WORKDIR /

COPY --from=build /ipdk-plugin /ipdk-plugin
COPY --from=build /ipdk.json /ipdk.json

EXPOSE 9075

ENTRYPOINT ["/ipdk-plugin"]
