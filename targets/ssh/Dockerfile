FROM alpine:3.20

RUN apk add --no-cache openssh \
    && ssh-keygen -A

COPY entrypoint.sh /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/bin/sh", "/entrypoint.sh"]
