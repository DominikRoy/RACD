##############################################################################
# "Dockerfile"                                                               #
#                                                                            #
# Author: Michael Eckel <michael.eckel@sit.fraunhofer.de>                    #
# Date: 2019-06-26                                                           #
#                                                                            #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                  #
##############################################################################

FROM ghcr.io/tpm2-software/ubuntu-18.04:latest as base
MAINTAINER Michael Eckel <michael.eckel@sit.fraunhofer.de>

## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

## manual pages and Bash command completion
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    man-db \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*

## TPM2 TSS
RUN git clone --depth=1 -b '2.4.5' \
    'https://github.com/tpm2-software/tpm2-tss.git' /tmp/tpm2-tss
WORKDIR /tmp/tpm2-tss
ENV LD_LIBRARY_PATH /usr/local/lib
RUN git reset --hard \
    && git clean -xdf \
    && ./bootstrap \
    && ./configure --enable-integration --disable-doxygen-doc \
    && make clean \
    && make -j \
    && make install \
    && ldconfig

## make TPM Simulator the default for TCTI
RUN ln -sf 'libtss2-tcti-mssim.so' '/usr/local/lib/libtss2-tcti-default.so'

## remove TPM2-TSS source files
RUN rm -rf /tmp/tpm2-tss

## TPM2 tools
RUN git clone --depth=1 -b '5.0' \
    'https://github.com/tpm2-software/tpm2-tools.git' /tmp/tpm2-tools
WORKDIR /tmp/tpm2-tools
RUN ./bootstrap \
    && ./configure \
    && make -j \
    && make install
RUN rm -rfv /tmp/tpm2-tools


## libsodium
#RUN git clone 'https://github.com/jedisct1/libsodium' -b 'stable' /tmp/libsodium
RUN git clone --depth=1 -b '1.0.18' \
    'https://github.com/jedisct1/libsodium' /tmp/libsodium
WORKDIR /tmp/libsodium
RUN ./autogen.sh \
    && ./configure \
    && make -j \
    && make check \
    && make install
## libCoAP
# RUN git clone --depth=1 --recursive -b 'develop' \
#     'https://github.com/obgm/libcoap.git' /tmp/libcoap
# WORKDIR /tmp/libcoap
# RUN ./autogen.sh \
#     && ./configure --disable-tests --disable-documentation --disable-manpages --disable-dtls --disable-shared --enable-fast-install \
#     && make -j \
#     && make install
# RUN rm -rfv /tmp/libcoap

## mbedtls
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    python3-jinja2 \
    && rm -rf /var/lib/apt/lists/*
#RUN git clone --depth=1 --recursive -b 'v2.28.4' \
RUN git clone --depth=1 --recursive -b 'v2.25.0' \
    'https://github.com/Mbed-TLS/mbedtls' /tmp/mbedtls
WORKDIR /tmp/mbedtls
RUN make -j lib SHARED=true \
    && make install
RUN rm -rfv /tmp/mbedtls

## QCBOR
RUN git clone --depth=1 --recursive -b 'v1.1' \
    'https://github.com/laurencelundblade/QCBOR.git' /tmp/qcbor
WORKDIR /tmp/qcbor
RUN make -j all so \
    && make install install_so
RUN rm -rfv /tmp/qcbor

## t_cose
RUN git clone --depth=1 --recursive -b 'v1.0.1' \
    'https://github.com/laurencelundblade/t_cose.git' /tmp/t_cose
WORKDIR /tmp/t_cose
RUN make -j -f Makefile.psa libt_cose.a libt_cose.so \
    &&  make -f Makefile.psa install install_so
RUN rm -rfv /tmp/t_cose

## install debugging tools
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    clang \
    valgrind \
    && rm -rf /var/lib/apt/lists/*

## install sudo and gosu
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    gosu \
    sudo \
    && rm -rf /var/lib/apt/lists/*

## set default values
ARG user=bob
ARG uid=1000
ARG gid=1000

## create non-root user and grant sudo permission
RUN export user="$user" uid="$uid" gid="$gid" \
    && addgroup --gid "$gid" "$user" \
    && adduser --home /home/"$user" --uid "$uid" --gid "$gid" \
    --disabled-password --gecos '' "$user" \
    && mkdir -vp /etc/sudoers.d/ \
    && echo "$user     ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"$user" \
    && chmod 0440 /etc/sudoers.d/"$user" \
    && chown "$uid":"$gid" -R /home/"$user"

## set environment variables
ENV TPM2TOOLS_TCTI_NAME socket
ENV TPM2TOOLS_SOCKET_ADDRESS 127.0.0.1
ENV TPM2TOOLS_SOCKET_PORT 2321

## install TPM Simulator reset script
COPY "./docker/dist/usr/local/bin/tpm-reset" "/usr/local/bin/"

## install TSS compile script
COPY "./docker/dist/usr/local/bin/compile-tss" "/usr/local/bin/"

## Docker entrypoint
COPY "./docker/dist/usr/local/bin/docker-entrypoint.sh" "/usr/local/bin/"
## keep backwards compatibility
RUN ln -s '/usr/local/bin/docker-entrypoint.sh' /

## set environment variables
USER "$uid:$gid"
ENV HOME /home/"$user"
WORKDIR /home/"$user"/racd-poc

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]

