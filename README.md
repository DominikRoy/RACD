# Remote Attestation with Constrained Disclosure ProVerif

This is the source code used to verify some of the security properties of the Remote Attestation with Constrained Disclosure protocol.

The folder contains the ProVerif code and the executable for ProVerif.

- racd.pv 
The code is meant to verify the secrecy of the randomness used to blind the template hashes (x_i) from the adversary. 
Moreover, we verify if the attacker is able to brute-force/guess x_i. 
We verify with ProVerif if the adversary is able to retrieve the values ri and vi through the entire process of the involved entities.

### Instructions for Windows:
- download the ProVerif binary for [Windows](https://bblanche.gitlabpages.inria.fr/proverif/proverifbin2.04.tar.gz)
- clone the git repository or uncompress the archive
- go to ./ProVerif/
- run our protocol by executing the command for Windows:
```properties
 ./proverif.exe racd.pv 
```  

### Instructions for Linux (Ubuntu 20.04):
- make sure the packages: [ocaml](https://packages.ubuntu.com/search?suite=default&section=all&arch=any&keywords=ocaml&searchon=names), [ocaml-compiler-libs](https://packages.ubuntu.com/search?keywords=ocaml-compiler-libs) and [LablGTK2](https://packages.ubuntu.com/search?suite=default&section=all&arch=any&keywords=LablGTK2&searchon=names) are installed:

```
sudo apt-get install -y ocaml ocaml-compiler-libs ocaml-findlib liblablgtk2-ocaml-dev 
```
- download the source of ProVerif for [Linux](https://bblanche.gitlabpages.inria.fr/proverif/proverif2.04.tar.gz)
- extract archive:
```properties
 tar -xf proverif2.04.tar
```
- navigate to the folder and build the program:
```properties
 cd proverif2.04
 ./build
```
- clone the git repository into the current folder where the command above was executed
- run our protocol by executing the command for Linux:
```properties
 ./proverif /PPRA-ProVerif/ProVerif/racd.pv
```
### Instructions for Docker:
- make sure [docker](https://docs.docker.com/engine/install/) is installed
- clone the git repository of PPTM
- the repository contains a `Dockerfile`, which builds the docker image. Therefore, execute following command to create the docker image:
```
sudo docker build -t proverif .                                                                              
```
- after building the docker image execute following command to execute pptm proverif code:
```
sudo docker run -it proverif:latest ./proverif2.04/proverif /home/proverif/proverif2.04/PPRA-ProVerif/ProVerif/racd.pv
```

# Remote Attestation with Constrained Disclosure Protocol

## Setup Docker with TPM Simulator


## Setup Raspberry Pi 3 with LetsTrust TPM 2.0

1. Download Raspberry Pi OS:

   ```bash
   wget 'https://downloads.raspberrypi.org/raspios_lite_armhf/images/raspios_lite_armhf-2021-11-08/2021-10-30-raspios-bullseye-armhf-lite.zip'
   ```

2. Unzip the image:

   ```bash
   unzip 2021-10-30-raspios-bullseye-armhf-lite.zip
   ```

3. Flash the image:

   ```bash
   sudo dd if=2021-10-30-raspios-bullseye-armhf-lite.img of=/dev/sdX status=progress ; sync
   ```

4. Mount the SD card.

5. Enable SSH by creating an empty file `ssh` in the boot partition.

6. Enable Wifi in the Pi by adding the file `wpa_supplicant.conf` to the boot partition with the following content:

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

7. Enable the TPM by editing the `config.txt` of the boot partition (cf. <https://letstrust.de/archives/20-Mainline.html>):
   * Uncomment the line `dtparam=spi=on`.
   * Add the line `dtoverlay=tpm-slb9670` at the end of the file.

8. Start the Raspberry Pi, SSH into it, and run `sudo raspi-config`.
   Change hostname (`ppra-pi`), locales, timezone, expand filesystem, etc.

   * user: `pi` \
     password: `eberhard23#`

9. Copy a SSH public key from you local machine to the Raspberry Pi:

   ```bash
   ssh-copy-id -i ~/.ssh/id_rsa.pub pi@ppra-pi
   ## or
   ssh-copy-id -o PreferredAuthentications=password -o PubkeyAuthentication=no -i ~/.ssh/id_rsa.pub pi@ppra-pi
   ## or forcing, in case only the public key is available
   ssh-copy-id -o PreferredAuthentications=password -o PubkeyAuthentication=no -f -i some-pub-key.pub pi@ppra-pi
   ```

10. Disable password login in the `/etc/ssh/sshd_config` file:
   * Change the line `#PasswordAuthentication yes` to `PasswordAuthentication no`
   * Optional: change the line `Port 22` to `Port 2784` (or another port)
   * Restart SSH with `sudo systemctl restart ssh.service`


### Update Packages

```bash
sudo apt update && sudo apt dist-upgrade
```

### Install TPM2 TSS Dependencies

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

### TPM2 TSS: Downlaod, Compile, and Install

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

### libCoAP: Downlaod, Compile, and Install

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

### mbed TLS: Downlaod, Compile, and Install

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

### QCBOR: Downlaod, Compile, and Install

```bash
## clone Git repo
git clone --depth=1 --recursive -b 'master' \
	'https://github.com/laurencelundblade/QCBOR.git' ~/qcbor
cd ~/qcbor

## compile
make -j all so

## install
sudo make install install_so \
	&& sudo ldconfig
```

### t_cose: Downlaod, Compile, and Install

```bash
## clone Git repo
git clone --depth=1 --recursive -b 'master' \
	'https://github.com/laurencelundblade/t_cose.git' ~/t_cose
cd ~/t_cose

## compile
make -j -f Makefile.psa libt_cose.a libt_cose.so

## install
sudo make -f Makefile.psa install install_so \
	&& sudo ldconfig
```

### Prepare [CHARRA](https://github.com/Fraunhofer-SIT/charra)

1. Create folder `/home/pi/charra-racd`:

   ```bash
   mkdir -vp /home/pi/charra-racd
   ```

2. Copy over this folder to Raspberry Pi in `/home/pi/charra-racd`

3. Install 7z:

   ```bash
   sudo apt install -y p7zip-full
   ```

4. Change to `/home/pi/charra-racd`:

   ```bash
   cd /home/pi/charra-racd
   ```

5. Unzip *CHARRA* and *CHARRA RACD*:
   ```bash
   7z x charra_adapted-time.7z
   7z x racd-protocol.7z
   ```

### TPM Permissions

Set permissions on TPM device:

```bash
sudo chmod 777 /dev/tpm*
```

## Test CHARRA

Change to `/home/pi/charra-racd/charra_adapted-time`:

   ```bash
   cd /home/pi/charra-racd/charra_adapted-time
   ```

Compile:

```bash
make
```

Run and collect time information:

```bash
## export
export ASAN_OPTIONS=verify_asan_link_order=0

## run attester
bin/attester &

## run verifier in a loop
for i in {1..100}; do bin/verifier; done
```

### CHARRA RACD

Change to `/home/pi/charra-racd/racd-protocol`:

   ```bash
   cd /home/pi/charra-racd/racd-protocol
   ```

#### Prerequitsies

```bash
sudo apt install -y clang
```

#### Libsodium

From: <https://forums.raspberrypi.com/viewtopic.php?t=203662>

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

#### Test CHARRA RACD

```bash
cd racd-protocol
```

Compile:

```bash
##step3
make -f Makefileclient clean

##step4
make -f Makefileserver clean

##step5
make -f Makefileclient

##step6
make -f Makefileserver
```
Generate self-signed certificates:

```bash
##Generate CA
./cert_write selfsign=1 issuer_key=ca_key.key issuer_name=CN=localhost,O=localhost,C=DE is_ca=1 max_pathlen=0 output_file=my_ca_localhost.crt 

##Generate Server csr
./cert_req filename=prover_key.key subject_name=CN=localhost,O=Prover,C=DE output_file=prover_localhost.csr

##Generate Client csr
./cert_req filename=verifier_key.key subject_name=CN=localhost,O=Verifier,C=DE output_file=verifier_localhost.csr

##Generate Server cert from csr with openssl
openssl x509 -req -in prover_localhost.csr -CA my_ca_localhost.crt -CAkey ca_key.key -CAcreateserial -out prover_localhost.crt -days 5000 -sha256

##Generate Client cert from csr with openssl with selfsigned CA
openssl x509 -req -in verifier_localhost.csr -CA my_ca_localhost.crt -CAkey ca_key.key -CAcreateserial -out verifier_localhost.crt -days 5000 -sha256
```
Run and collect time information:

```bash
## change folder
cd example

## remove log files
rm -v  pcr0.log ppra_attester_50_local_new.csv ppra_verifier_50_new.csv

## export
export ASAN_OPTIONS=verify_asan_link_order=0

## run attester
../output/attestor server_name=localhost server_port=4433 ca_file=my_ca_localhost.crt crt_file=prover_localhost.crt key_file=prover_key.key programs_file=programs250.cbor &

## run verifier in a loop
for i in {1..100}; do ../output/verifier server_name=localhost server_port=4433 ca_file=my_ca_localhost.crt crt_file=verifier_localhost.crt key_file=verifier_key.key swSelection_file=programs50.cbor; done
```
