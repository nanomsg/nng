FROM ubuntu:16.04

RUN apt-get update -qq && apt-get install -y software-properties-common
RUN add-apt-repository ppa:ubuntu-toolchain-r/test
RUN apt-get update -qq && apt-get install -y \
    asciidoctor \
    build-essential \
    cmake \
    curl \
    g++-7 \
    gcc-7 \
    git \
    gzip \
    libmbedtls-dev \
    ninja-build \
    openssh-client
