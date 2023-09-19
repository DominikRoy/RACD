# Remote Attestation with Constrained Disclosure (RACD) -- Proof-of-Concept Implementation

We provide the instructions to verify our [ProVerif](#racd-proverif-proof) code w.r.t. our paper "Remote Attestation with Constrained Disclosure", accepted for publication at the [Annual Computer Security Applications Conference (ACSAC) 2023](https://www.acsac.org/).

In the follwing, we provide the proof-of-concept (PoC) implementation of our [RACD Protocol](#racd-protocol-poc-implementation), where we provide instructions to compile and run the code.

## RACD ProVerif Proof

This is the source code used to verify some of the security properties of the Remote Attestation with Constrained Disclosure (RACD) protocol.

The `ProVerif` folder contains the ProVerif code (`racd.pv`) and the ProVerif Windows executable (`proverif.exe`).

`racd.pv`: The code is meant to verify the secrecy of the randomness used to blind the template hashes (*x_i*) from the adversary.
Moreover, we verify if the attacker is able to brute-force/guess *x_i*.
We verify with ProVerif if the adversary is able to retrieve the values *ri* and *vi* through the entire process of the involved entities.

### RACD ProVerif Proof Instructions for Docker

1. Make sure [Docker](https://docs.docker.com/engine/install/) is installed on your system.
   Under Ubuntu, make sure you are a member of the `docker` group (and either re-login or restart the system after executing the command):

   ```bash
   sudo usermod -aG docker "${USER}"
   ```

1. Clone this Git repository ([RACD](https://github.com/DominikRoy/RACD.git)):

   ```bash
   git clone 'https://github.com/DominikRoy/RACD.git'
   ```

1. Change to the `ProVerif` folder

   ```bash
   cd ./ProVerif/
   ```

1. Build the Docker image:

   ```bash
   ./docker/build.sh
   ```

1. Either run the RACD ProVerif code *non-interactively* with:

   ```bash
   ./docker/run.sh proverif racd.pv
   ```

   or *interactively* with:

   ```bash
   ./docker/run.sh
   ```

   and then inside the container:

   ```bash
   proverif racd.pv
   ```

### RACD ProVerif Proof Instructions for Linux (Ubuntu 20.04)

Make sure the following packages are installed:

* [ocaml](https://packages.ubuntu.com/search?suite=default&section=all&arch=any&keywords=ocaml&searchon=names)
* [ocaml-compiler-libs](https://packages.ubuntu.com/search?keywords=ocaml-compiler-libs)
* [LablGTK2](https://packages.ubuntu.com/search?suite=default&section=all&arch=any&keywords=LablGTK2&searchon=names)

Install them with:

```bash
sudo apt-get install -y ocaml ocaml-compiler-libs ocaml-findlib liblablgtk2-ocaml-dev
```

1. Download the source of ProVerif for [Linux](https://bblanche.gitlabpages.inria.fr/proverif/proverif2.04.tar.gz)

1. Extract the archive:

  ```properties
  tar -xf proverif2.04.tar
  ```

1. Navigate to the folder and build the program:

   ```bash
   cd proverif2.04
   ./build
   ```

1. Clone this Git repository into the current folder where the command above was executed.

1. RACD ProVerif code executing the command for Linux:

  ```properties
  ./proverif RACD/ProVerif/racd.pv
  ```

### RACD ProVerif Proof Instructions for Windows

1. Download the ProVerif binary for [Windows](https://bblanche.gitlabpages.inria.fr/proverif/proverifbin2.04.tar.gz)

1. Clone this Git repository or uncompress the archive.

1. Change to `ProVerif` folder.

1. Run our protocol by executing the command for Windows:

   ```properties
   proverif.exe racd.pv
   ```

## RACD Protocol PoC Implementation

We provide instructions to emulate our PoC in Docker with a TPM Simulator.
In addition, we describe the commands to deploy our PoC on a real hardware, a Raspberry Pi 3 Model B, and with a real hardware TPM that we used in our experiment evaluation.

### RACD Protocol PoC Instructions for Docker

1. Make sure [Docker](https://docs.docker.com/engine/install/) is installed on your system.
   Under Ubuntu, make sure you are a member of the `docker` group (and either re-login or restart the system after executing the command):

   ```bash
   sudo usermod -aG docker "${USER}"
   ```

1. Clone this Git repository ([RACD](https://github.com/DominikRoy/RACD.git)):

   ```bash
   git clone 'https://github.com/DominikRoy/RACD.git'
   ```

1. Change to the `racd-protocol` folder

   ```bash
   cd ./racd-protocol/
   ```

1. Build the Docker image:

   ```bash
   ./docker/build.sh
   ```

1. Run the RACD container *interactively* with:

   ```bash
   ./docker/run.sh
   ```

1. Continue with the steps described in [Run the RACD Protocol PoC](#run-the-racd-protocol-poc)

### RACD Protocol PoC Instructions for Raspberry Pi 3 Model B with LetsTrust TPM 2.0

We need to install an operating system on the Raspberry Pi and configure the TPM.
Further, we need to install all dependencies for the RACD Protocol PoC implementation.
Finally, we install the RACD Protocol PoC code and set TPM permissions accordingly.

#### Basic Raspberry Pi Setup

First, we need to prepare the SD card for the Raspberry Pi.

1. Download Raspberry Pi OS:

   ```bash
   wget 'https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-11-08/2021-10-30-raspios-bullseye-armhf-lite.zip'
   ```

1. Unzip the image:

   ```bash
   unzip 2021-10-30-raspios-bullseye-armhf-lite.zip
   ```

1. Flash the image:

   ```bash
   sudo dd if=2021-10-30-raspios-bullseye-armhf-lite.img of=/dev/sdX status=progress ; sync
   ```

1. Mount the SD card.

1. Enable SSH by creating an empty file `ssh` in the boot partition.

1. Enable Wifi in the Pi by adding the file `wpa_supplicant.conf` to the boot partition with the following content:

   ```text
   country=DE
   ctrl_interface=DIR=/var/run/wpa_supplicant GROUP=netdev
   update_config=1
   network={
          ssid="wifi-name"
          psk="password"
          key_mgmt=WPA-PSK
   }
   ```

1. Enable the TPM by editing the `config.txt` of the boot partition (cf. <https://letstrust.de/archives/20-Mainline.html>):

   * Uncomment the line `dtparam=spi=on`.

   * Add the line `dtoverlay=tpm-slb9670` at the end of the file.

Next, we startup and configure the Raspberry Pi.

1. Insert the SD card into the Raspberry Pi and start it, SSH into it, and run `sudo raspi-config`.
   Change hostname (`racd-pi`), locales, timezone, expand filesystem, etc.

1. Copy a SSH public key from you local machine to the Raspberry Pi:

   ```bash
   ssh-copy-id -i ~/.ssh/id_rsa.pub pi@racd-pi

   ## or
   ssh-copy-id -o PreferredAuthentications=password -o PubkeyAuthentication=no -i ~/.ssh/id_rsa.pub pi@racd-pi

   ## or forcing, in case only the public key is available
   ssh-copy-id -o PreferredAuthentications=password -o PubkeyAuthentication=no -f -i some-pub-key.pub pi@racd-pi
   ```

1. Disable password login in the `/etc/ssh/sshd_config` file:

   * Change the line `#PasswordAuthentication yes` to `PasswordAuthentication no`

   * Optional: change the line `Port 22` to `Port 2784` (or another port)

   * Restart SSH with `sudo systemctl restart ssh.service`

#### Install Dependencies

1. Update the package database:

   ```bash
   sudo apt update && sudo apt dist-upgrade
   ```

1. Install TPM2 TSS dependencies:

   ```bash
   sudo apt -y install \
       autoconf \
       autoconf-archive \
       automake \
       acl \
       build-essential \
       doxygen \
       gcc \
       git \
       iproute2 \
       libcmocka0 \
       libcmocka-dev \
       libcurl4-openssl-dev \
       libini-config-dev \
       libjson-c-dev \
       libltdl-dev \
       libssl-dev \
       libtool \
       pkg-config \
       procps \
       uthash-dev
   ```

1. TPM2 TSS: Downlaod, compile, and install:

   ```bash
   ## clone Git repo
   git clone --depth=1 -b '3.1.0' \
       'https://github.com/tpm2-software/tpm2-tss.git' ~/tpm2-tss

   ## compile
   cd ~/tpm2-tss
   export LD_LIBRARY_PATH=/usr/local/lib
   git reset --hard \
       && git clean -xdf \
       && ./bootstrap \
       && ./configure --disable-doxygen-doc \
       && make clean \
       && make -j

   ## install
   sudo make install \
       && sudo ldconfig
   ```

1. libCoAP: Downlaod, compile, and install:

   ```bash
   ## clone Git repo
   git clone --recursive -b 'develop' \
       'https://github.com/obgm/libcoap.git' ~/libcoap
   cd ~/libcoap
   git checkout f681525272c1ab2d1abbeed0cfb03edba23d8936
   #git checkout ea1deffa6b3997eea02635579a4b7fb7af4915e5

   ## compile
   ./autogen.sh \
       && ./configure --disable-tests --disable-documentation --disable-manpages --disable-dtls --disable-shared --enable-fast-install \
       && make -j

   ## install
   sudo make install \
       && sudo ldconfig
   ```

1. mbed TLS: Downlaod, compile, and install

   ```bash
   ## clone Git repo
   git clone --depth=1 --recursive -b 'v2.25.0' \
       'https://github.com/ARMmbed/mbedtls.git' ~/mbedtls
   cd ~/mbedtls

   ## compile
   make -j lib SHARED=true

   ## install
   sudo make install \
       && sudo ldconfig
   ```

1. QCBOR: Downlaod, compile, and install

   ```bash
   ## clone Git repo
   git clone --depth=1 --recursive -b 'v1.1' \
       'https://github.com/laurencelundblade/QCBOR.git' ~/qcbor
   cd ~/qcbor

   ## compile
   make -j all so

   ## install
   sudo make install install_so \
       && sudo ldconfig
   ```

1. t_cose: Downlaod, compile, and install

   ```bash
   ## clone Git repo
   git clone --depth=1 --recursive -b 'v1.0.1' \
       'https://github.com/laurencelundblade/t_cose.git' ~/t_cose
   cd ~/t_cose

   ## compile
   make -j -f Makefile.psa libt_cose.a libt_cose.so

   ## install
   sudo make -f Makefile.psa install install_so \
       && sudo ldconfig
   ```

1. Libsodium: Downlaod, compile, and install

   ```bash
   ## download
   mkdir libsodium
   cd libsodium/
   wget 'https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz'
   tar xzf libsodium-1.0.18.tar.gz
   cd libsodium-1.0.18/

   ## compile
   ./configure
   make -j

   ## install
   sudo make install \
       && sudo ldconfig
   ```

#### Prepare RACD Protocol PoC

1. Clone this Git repository ([RACD](https://github.com/DominikRoy/RACD.git)):

   ```bash
   git clone 'https://github.com/DominikRoy/RACD.git' ~/racd-poc
   ```

1. Change to the RACD Protocol PoC folder:

   ```bash
   cd ~/racd-poc/racd-protocol/
   ```

#### Adjust TPM Permissions

Set permissions on TPM device:

```bash
sudo chmod 777 /dev/tpm*
```

Continue with the steps described in [Run the RACD Protocol PoC](#run-the-racd-protocol-poc)

### Run the RACD Protocol

1. Compile:

   ```bash
   ## clean up
   make -f Makefileclient clean
   make -f Makefileserver clean

   ## build client (verifer)
   make -f Makefileclient

   ## build server (attester)
   make -f Makefileserver
   ```

1. Run and collect time information:

   ```bash
   ## change folder
   cd example

   ## remove log files
   rm -v pcr0.log ppra_attester_50_local_new.csv ppra_verifier_50_new.csv

   ## export
   export ASAN_OPTIONS=verify_asan_link_order=0

   ## run attester (wait for the output "Waiting for a remote connection ...")
   ../output/attestor server_name=localhost \
       server_port=4433 ca_file=my_ca_localhost.crt \
       crt_file=prover_localhost.crt key_file=prover_key.key \
       programs_file=programs250.cbor &

   ## run verifier in a loop
   for i in {1..100}; do ../output/verifier server_name=localhost \
       server_port=4433 ca_file=my_ca_localhost.crt \
       crt_file=verifier_localhost.crt key_file=verifier_key.key \
       swSelection_file=programs50.cbor; done
```

