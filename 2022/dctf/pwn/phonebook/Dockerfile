FROM ubuntu:20.04

EXPOSE 1337

RUN export DEBIAN_FRONTEND=noninteractive && \
    apt-get -y update && \
    apt-get -y upgrade && \
    apt-get -y install socat coreutils

COPY chall/flag.txt /
COPY chall/phonebook /

RUN chmod 555 /phonebook && \
    chmod 444 /flag.txt

CMD socat -T 30 \
    TCP-LISTEN:1337,nodelay,reuseaddr,fork \
    EXEC:"stdbuf -i0 -o0 -e0 /phonebook"
