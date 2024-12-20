FROM ubuntu:latest

LABEL maintainer="wellingtonresende15@gmail.com"

COPY . .

RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y \
    curl \
    wget \
    vim \
    nano \
    hping3 \
    hydra \
    nmap \
    gnupg \
    git && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

RUN curl https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && \
    chmod 755 msfinstall && \
    ./msfinstall

RUN wget https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt

CMD [ "bash" ]