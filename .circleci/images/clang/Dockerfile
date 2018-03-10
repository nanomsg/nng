FROM ubuntu:16.04

RUN apt-get update -qq && apt-get install -y software-properties-common
RUN apt-add-repository "deb http://apt.llvm.org/xenial/ llvm-toolchain-xenial-4.0 main"
RUN apt-get update -qq && apt-get install -y \
    asciidoctor \
    build-essential \
    clang-4.0 \
    clang++-4.0 \
    clang-format-4.0 \
    cmake \
    curl \
    git \
    gzip \
    libmbedtls-dev \
    ninja-build \
    openssh-client
