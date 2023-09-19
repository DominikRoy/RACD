################################################################################
# Copyright 2023, Fraunhofer Institute for Secure Information Technology SIT.  #
# All rights reserved.                                                         #
# ---------------------------------------------------------------------------- #
# Main Dockerfile for RACD ProVerif.                                           #
# ---------------------------------------------------------------------------- #
# Author:        Michael Eckel <michael.eckel@sit.fraunhofer.de>               #
# Author:        Dominik Roy George <d.r.george@tue.nl>                        #
# Date Modified: 2023-09-19T16:49:11+23:00                                     #
# Date Created:  2023-08-23T13:37:42+02:00                                     #
# ---------------------------------------------------------------------------- #
# Hint: Check your Dockerfile at https://www.fromlatest.io/                    #
################################################################################


## -----------------------------------------------------------------------------
## --- preamble ----------------------------------------------------------------
## -----------------------------------------------------------------------------

## --- set base image(s) -------------------------------------------------------

FROM ubuntu:20.04 AS base

## --- global arguments --------------------------------------------------------

ENV TZ=Europe/Amsterdam

## --- metadata ----------------------------------------------------------------

LABEL org.opencontainers.image.authors="michael.eckel@sit.fraunhofer.de"

## --- image specific arguments ------------------------------------------------

ARG user=bob
ARG uid=1000
ARG gid=1000


## -----------------------------------------------------------------------------
## --- pre-work for interactive environment ------------------------------------
## -----------------------------------------------------------------------------

## copy configs
COPY "./docker/dist/etc/default/keyboard" "/etc/default/keyboard"

## timezone
ENV TZ=Europe/Amsterdam
RUN ln -snf "/usr/share/zoneinfo/${TZ}" /etc/localtime \
    && echo "${TZ}" > /etc/timezone

## Bash command completion
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    bash-completion \
    && rm -rf /var/lib/apt/lists/*


## -----------------------------------------------------------------------------
## --- install dependencies ----------------------------------------------------
## -----------------------------------------------------------------------------

## ProVerif dependencies
RUN apt-get update \
    && apt-get install --no-install-recommends -y \
    build-essential \
    cmake \
    g++ \
    git \
    iputils-ping \
    liblablgtk2-ocaml-dev \
    make \
    nano \
    net-tools \
    ocaml \
    ocaml-compiler-libs \
    ocaml-findlib \
    tar \
    wget \
    && rm -rf /var/lib/apt/lists/*

## ProVerif
RUN git clone --depth=1 -b 'v2.04' -c http.sslVerify=false \
    'https://gitlab.inria.fr/bblanche/proverif.git' /opt/proverif
WORKDIR /opt/proverif/proverif
RUN ./build
RUN ln -sf '/opt/proverif/proverif/proverif' '/usr/local/bin/proverif'


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

## Docker entrypoint
COPY "./docker/dist/usr/local/bin/docker-entrypoint.sh" "/usr/local/bin/"
## keep backwards compatibility
RUN ln -s '/usr/local/bin/docker-entrypoint.sh' /

## set environment variables
USER "$uid:$gid"
ENV HOME /home/"$user"
WORKDIR /home/"$user"/racd-proverif/


## -----------------------------------------------------------------------------
## --- postamble ---------------------------------------------------------------
## -----------------------------------------------------------------------------

ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["/bin/bash"]

