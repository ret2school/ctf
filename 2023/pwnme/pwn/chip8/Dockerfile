FROM ubuntu:22.04

WORKDIR /app/

RUN apt-get update && apt-get install socat -y

COPY ./chall.patch /app/
COPY ./wrapper /app/
COPY ./c8emu /app/

RUN groupadd --system ctf && \
	useradd -M -d /app -g ctf player && \
	chmod u+s /app/wrapper

RUN chown player:ctf /app/wrapper
USER player

ENTRYPOINT ["socat", "TCP-LISTEN:3000,reuseaddr,fork", "EXEC:'/app/wrapper',stderr"]
