# Copyright 2022 Adolfo García Veytia
# SPDX-License-Identifier: Apache-2.0

# 1.17.6-bullseye 17 jan 2022
FROM golang@sha256:9398cab51b551e0eb1b50a3e0478e0f9918ac892aa7d8d2341fb2cd299f4f513  as builder
WORKDIR /workspace
ADD . ./
ENV GOPROXY="https://proxy.golang.org|direct"
ENV CGO_ENABLED=0
RUN go env
RUN go build -ldflags '-s -w -buildid= -extldflags "-static"' -o acl ./cmd/acl/main.go

# static-debian11 distroless 17 jan 2022 
FROM gcr.io/distroless/gcr.io/distroless/static-debian11@sha256:03dcbf61f859d0ae4c69c6242c9e5c3d7e1a42e5d3b69eb235e81a5810dd768e
LABEL maintainers="Adolfo García Veytia"
LABEL description="Simple GitHub action that checks an access control list and fails if an actor is not in it"
WORKDIR /
COPY --from=builder /workspace/acl .
ENTRYPOINT ["/acl"]