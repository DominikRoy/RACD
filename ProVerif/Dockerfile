FROM ubuntu:20.04
ENV TZ=Europe/Amsterdam
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone
## manual pages and Bash command completion
WORKDIR /home/proverif/
RUN apt-get clean && apt-get -y update && apt-get install -y git
#RUN mkdir osboxes
#WORKDIR home/osboxes/
RUN apt-get install -y \
    net-tools\
    iputils-ping\
    nano\
    g++ make cmake \
    tar \
    ocaml \
    ocaml-compiler-libs \
    ocaml-findlib \
    liblablgtk2-ocaml-dev \
    wget 
RUN wget https://bblanche.gitlabpages.inria.fr/proverif/proverif2.04.tar.gz && tar -xf proverif2.04.tar.gz -C /home/proverif/ && cd /home/proverif/proverif2.04/ && ./build
#RUN ./build
RUN cd /home/proverif/proverif2.04 && git clone https://github.com/DominikRoy/RACD.git
