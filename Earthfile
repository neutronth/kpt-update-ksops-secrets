VERSION 0.7

ARG --global IMAGE_TAG="dev"

source:
  FROM golang:1.22-bullseye
  ENV CGO_ENABLED=0

  WORKDIR /src

  COPY go.mod go.sum ./
  RUN go mod download -x

  COPY . .

build-sops:
  # The custom SOPS is required due to an incompatibility YAML indent spaces
  # which the Kpt/Kustomize is 2 spaces but the SOPS is 4 spaces.
  # The 2 spaces formatting of Kpt/Kustomize makes the
  # SOPS MAC (Message Authentication Code) invalid and error on decryption.
  # The custom SOPS is required during secrets encryption in Kpt pipeline only,
  # the generated encrypted files still compatible with the upstream binary.
  FROM golang:1.22-bullseye
  ENV DEBIAN_FRONTEND=noninteractive
  ENV CGO_ENABLED=0

  WORKDIR /src

  RUN apt update --yes \
    && apt install --yes git

  RUN git clone https://github.com/mozilla/sops.git \
    && cd sops \
    && git checkout v3.8.1 \
    && sed -i'' 's/e.SetIndent(4)/e.SetIndent(2)/g' stores/yaml/store.go \
    && go mod download -x \
    && go build -o /sops ./cmd/sops

  SAVE ARTIFACT /sops

lint:
  FROM +source

  RUN go install github.com/golangci/golangci-lint/cmd/golangci-lint@v1.52.0
  RUN golangci-lint run --verbose --timeout="5m" ./...

test:
  FROM +lint
  COPY +build-sops/sops /usr/local/bin/sops

  RUN gpg --import example/F532DA10E563EE84440977A19D0470BDA6CDC457.gpg \
    && gpg --import example/380024A2AC1D3EBC9402BEE66E38309B4DA30118.gpg
  RUN mkdir -p /testing/generated
  RUN go test -v ./...

build:
  FROM +test

  RUN go build -o kpt-update-ksops-secrets .
  SAVE ARTIFACT kpt-update-ksops-secrets

download-tools:
  FROM debian:bullseye-slim
  ENV DEBIAN_FRONTEND=noninteractive

  ARG KPT_VERSION="1.0.0-beta.51"
  ARG KPT_URL="https://github.com/GoogleContainerTools/kpt/releases/download/v${KPT_VERSION}/kpt_linux_amd64"

  ARG KUSTOMIZE_VERSION="5.4.2"
  ARG KUSTOMIZE_URL="https://github.com/kubernetes-sigs/kustomize/releases/download/kustomize%2Fv${KUSTOMIZE_VERSION}/kustomize_v${KUSTOMIZE_VERSION}_linux_amd64.tar.gz"

  ARG KSOPS_VERSION="4.3.1"
  ARG KSOPS_URL="https://github.com/viaduct-ai/kustomize-sops/releases/download/v${KSOPS_VERSION}/ksops_${KSOPS_VERSION}_Linux_x86_64.tar.gz"

  RUN apt update --yes \
    && apt install --yes curl

  RUN curl --location "$KPT_URL" -o kpt \
    && chmod +x kpt

  RUN curl --location "$KUSTOMIZE_URL" -o - | tar xzf - kustomize \
    && chmod +x kustomize

  RUN curl --location "$KSOPS_URL" -o - | tar xzf - ksops \
    && chmod +x ksops

  SAVE ARTIFACT kpt
  SAVE ARTIFACT kustomize
  SAVE ARTIFACT ksops

image:
  ARG IMAGE_TAG="${IMAGE_TAG}"

  FROM debian:bullseye-slim

  COPY +build/kpt-update-ksops-secrets /usr/local/bin/kpt-update-ksops-secrets
  COPY +build-sops/sops /usr/local/bin/sops

  ARG DEBIAN_FRONTEND=noninteractive
  RUN apt update --yes \
    && apt install --yes \
      ca-certificates \
      gnupg \
    && apt clean \
    && rm -rf /var/lib/apt/lists/*

  # The Kpt invokes function with user `nobody`
  # Prepare GPG home directory for following setting
  #   HOME=/nonexistent
  #   GNUPGHOME=~/.gnupg
  RUN mkdir /nonexistent \
    && chown nobody. /nonexistent \
    && su - nobody -s /bin/bash -c "gpg --list-keys"

  ENTRYPOINT ["kpt-update-ksops-secrets"]

  SAVE IMAGE --push ghcr.io/neutronth/kpt-update-ksops-secrets:${IMAGE_TAG}

image-all-platforms:
  BUILD --platform=linux/amd64 --platform=linux/arm64 +image

integration-base:
  ARG BASE_IMAGE
  FROM ${BASE_IMAGE}
  WORKDIR /testing
  ENV DEBIAN_FRONTEND=noninteractive

  RUN apt update --yes \
    && apt install --yes \
      git \
      tree

  ARG KUSTOMIZE_PLUGIN_DIR="/root/.config/kustomize/plugin"
  ARG SOPS_AGE_KEYS_DIR="/root/.config/sops/age"

  COPY +download-tools/kpt /usr/local/bin/kpt
  COPY +download-tools/kustomize /usr/local/bin/kustomize
  COPY +download-tools/ksops ${KUSTOMIZE_PLUGIN_DIR}/viaduct.ai/v1/ksops/ksops
  COPY example/Kptfile ./
  COPY example/update-ksops-secrets.yaml ./
  COPY example/unencrypted-secrets.yaml ./
  COPY example/unencrypted-secrets-config-txt.yaml ./
  COPY example/test-update-ksops-secrets.yaml ./
  COPY example/gpg-publickeys.yaml ./
  COPY example/age.key.txt ${SOPS_AGE_KEYS_DIR}/keys.txt
  COPY scripts/integration-test /usr/local/bin/integration-test

integration-test:
  FROM +integration-base --BASE_IMAGE=+image

  RUN --no-cache integration-test

integration-image-test:
  FROM +integration-base --BASE_IMAGE=earthly/dind:ubuntu-20.04

  WITH DOCKER --load=ghcr.io/neutronth/kpt-update-ksops-secrets:latest=+image
    RUN --no-cache \
      kpt fn eval --image=ghcr.io/neutronth/kpt-update-ksops-secrets:latest \
        --fn-config=update-ksops-secrets.yaml \
        --network \
        --truncate-output=false \
      && kpt pkg tree \
      && kustomize build --enable-alpha-plugins .
  END
