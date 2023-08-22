##############################################################################
# "Dockerfile"                                                               #
#                                                                            #
# Author: Michael Eckel <michael.eckel@sit.fraunhofer.de> 					 #
# Author: Dominik Roy George <d.r.george@tue.nl>							 #
# Date: 2023-08-22                                                           #
#                                                                            #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                  #
##############################################################################

FROM ghcr.io/tpm2-software/ubuntu-20.04:latest AS base


## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

## --- image specific arguments ------------------------------------------------

ARG user=bob
ARG uid=1000
ARG gid=1000


## -----------------------------------------------------------------------------
## --- pre-work for interactive environment ------------------------------------
## -----------------------------------------------------------------------------

## unminimize Ubuntu container image
RUN yes | unminimize

## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

## system reference manuals (manual pages)
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    man-db \
    manpages-posix \
    manpages-dev \
	p7zip-full \
    && rm -rf /var/lib/apt/lists/*

## Bash command completion
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*


## -----------------------------------------------------------------------------
## --- install dependencies ----------------------------------------------------
## -----------------------------------------------------------------------------

ENV LD_LIBRARY_PATH="$LD_LIBRARY_PATH:/usr/local/lib"

## TPM2 TSS
RUN git clone --depth=1 -b '3.2.1' \
	'https://github.com/tpm2-software/tpm2-tss.git' /tmp/tpm2-tss
WORKDIR /tmp/tpm2-tss
RUN git reset --hard \
	&& git clean -xdf \
	&& ./bootstrap \
	&& ./configure --enable-integration --disable-doxygen-doc \
	&& make clean \
	&& make -j \
	&& make install \
	&& ldconfig

## make TPM simulator the default for TCTI
RUN ln -sf 'libtss2-tcti-mssim.so' '/usr/local/lib/libtss2-tcti-default.so'

## remove TPM2-TSS source files
RUN rm -rf /tmp/tpm2-tss

## TPM2 tools
RUN git clone --depth=1 -b '5.2' \
	'https://github.com/tpm2-software/tpm2-tools.git' /tmp/tpm2-tools
WORKDIR /tmp/tpm2-tools
RUN ./bootstrap \
	&& ./configure \
	&& make -j \
	&& make install \
	&& ldconfig
RUN rm -rfv /tmp/tpm2-tools

## libcoap
RUN git clone --recursive -b 'v4.3.0' \
	'https://github.com/obgm/libcoap.git' /tmp/libcoap
# Usually the second git checkout should be enough with an added
# '--recurse-submodules', but for some reason this fails in the
# default docker build environment.
# Note: The checkout with submodules works when using Buildkit.
WORKDIR /tmp/libcoap/ext/tinydtls
RUN git checkout 290c48d262b6859443bd4b04926146bda3293c98
WORKDIR /tmp/libcoap
RUN git checkout ea1deffa6b3997eea02635579a4b7fb7af4915e5
COPY "./docker/dist/coap_tinydtls.patch" .
RUN patch -p 1 < coap_tinydtls.patch
RUN ./autogen.sh \
	&& ./configure --disable-tests --disable-documentation --disable-manpages --enable-dtls --with-tinydtls --enable-fast-install \
	&& make -j \
	&& make install \
	&& ldconfig
RUN rm -rfv /tmp/libcoap

## mbed TLS
RUN apt-get update \
	&& apt-get install --no-install-recommends -y \
	python3-jinja2 \
	&& rm -rf /var/lib/apt/lists/*
RUN git clone --recursive -b 'v3.2.1' \
	'https://github.com/ARMmbed/mbedtls.git' /tmp/mbedtls
WORKDIR /tmp/mbedtls
RUN make -j lib SHARED=true \
	&& make install \
	&& ldconfig
RUN rm -rfv /tmp/mbedtls

## QCBOR
RUN git clone --depth=1 --recursive -b 'v1.1' \
	'https://github.com/laurencelundblade/QCBOR.git' /tmp/qcbor
WORKDIR /tmp/qcbor
RUN make -j all so \
	&& make install install_so \
	&& ldconfig	
RUN rm -rfv /tmp/qcbor

## t_cose
RUN git clone --depth=1 --recursive -b 'v1.0.1' \
	'https://github.com/laurencelundblade/t_cose.git' /tmp/t_cose
WORKDIR /tmp/t_cose
RUN make -j -f Makefile.psa libt_cose.a libt_cose.so \
	&&  make -f Makefile.psa install install_so \
	&& ldconfig
RUN rm -rfv /tmp/t_cose

##libsodium
RUN git clone 'https://github.com/jedisct1/libsodium' --branch 'stable' /tmp/libsodium
WORKDIR /tmp/libsodium
RUN ./configure \
	&& make -j \
	&& make check \
	&& make install \
	&& ldconfig
RUN rm -rfv /tmp/libsodium
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

RUN git clone 'https://github.com/DominikRoy/RACD.git' /home/charra-racd
WORKDIR /home/charra-racd
RUN 7z x charra_adapted-time.7z\ 
 	&& 7z x racd-protocol.7z
#WORKDIR /home/charra-racd/charra_adapted-time
#RUN make

WORKDIR /home/charra-racd/ppra-protocol
RUN make -f Makefileclient clean\
	&& make -f Makefileserver clean\
	&& make -f Makefileclient \
	&& make -f Makefileserver 








## -----------------------------------------------------------------------------
## --- further configuration ---------------------------------------------------
## -----------------------------------------------------------------------------

## add 'tss' user and group
## see: <https://github.com/tpm2-software/tpm2-tss/blob/3.2.0/Makefile.am#L638>
RUN bash -c ' \
    if test -z "${DESTDIR}"; then \
        if type -p groupadd > /dev/null; then \
            id -g tss 2>/dev/null || groupadd --system tss; \
        else \
            id -g tss 2>/dev/null || \
            addgroup --system tss; \
        fi && \
        if type -p useradd > /dev/null; then \
            id -u tss 2>/dev/null || \
            useradd --system --home-dir / --shell `type -p nologin` \
                             --no-create-home -g tss tss; \
        else \
            id -u tss 2>/dev/null || \
            adduser --system --home / --shell `type -p nologin` \
                    --no-create-home --ingroup tss tss; \
        fi; \
    fi \
    '

## install jq tool for JSON manipulation
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    jq \
    && rm -rf /var/lib/apt/lists/*

## configure TSS FAPI to not check EK certificates since we use a TPM simulator
RUN jq --argjson ekCertLess '{"ek_cert_less":"yes"}' '. += $ekCertLess' \
    '/usr/local/etc/tpm2-tss/fapi-config.json' \
    > '/tmp/fapi-config.json' \
    && cat '/tmp/fapi-config.json' \
        > '/usr/local/etc/tpm2-tss/fapi-config.json' \
    && rm -f '/tmp/fapi-config.json'


## -----------------------------------------------------------------------------
## --- install tools -----------------------------------------------------------
## -----------------------------------------------------------------------------

## install debugging tools
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    clang \
    clang-tools \
    cgdb \
    gdb \
    tmux \
    valgrind \
    && rm -rf /var/lib/apt/lists/*


## -----------------------------------------------------------------------------
## --- setup user --------------------------------------------------------------
## -----------------------------------------------------------------------------

## install sudo and gosu
RUN apt-get update \
	&& apt-get install --no-install-recommends -y \
	gosu \
	sudo \
	&& rm -rf /var/lib/apt/lists/*

## create non-root user and grant sudo permission
RUN export user="$user" uid="$uid" gid="$gid" \
	&& addgroup --gid "$gid" "$user" \
	&& adduser --home /home/"$user" --uid "$uid" --gid "$gid" \
	--disabled-password --gecos '' "$user" \
	&& mkdir -vp /etc/sudoers.d/ \
	&& echo "$user     ALL=(ALL) NOPASSWD: ALL" > /etc/sudoers.d/"$user" \
	&& chmod 0440 /etc/sudoers.d/"$user" \
	&& chown "$uid":"$gid" -R /home/"$user"


## -----------------------------------------------------------------------------
## --- configuration -----------------------------------------------------------
## -----------------------------------------------------------------------------

## set environment variables
ENV TPM2TOOLS_TCTI_NAME socket
ENV TPM2TOOLS_SOCKET_ADDRESS 127.0.0.1
ENV TPM2TOOLS_SOCKET_PORT 2321

## install TPM simulator reset script
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
WORKDIR /home/charra-racd/ppra-protocol/example


## -----------------------------------------------------------------------------
## --- postamble ---------------------------------------------------------------
## -----------------------------------------------------------------------------

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]
