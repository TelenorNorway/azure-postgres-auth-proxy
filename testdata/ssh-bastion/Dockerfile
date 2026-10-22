FROM alpine:3.24

RUN apk add --no-cache openssh-server \
    && adduser -D sshuser \
    && echo 'sshuser:*' | chpasswd -e

COPY sshd_config /etc/ssh/sshd_config

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D", "-e"]
