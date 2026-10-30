FROM debian:trixie-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get -o Acquire::Retries=8 update -qq && \
    apt-get -o Acquire::Retries=8 install -y -qq --no-install-recommends clang-19 lld-19 llvm-19 make flex bison bc python3 libelf-dev libssl-dev perl cpio kmod && \
    rm -rf /var/lib/apt/lists/*
