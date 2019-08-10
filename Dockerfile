FROM golang:latest

RUN go get github.com/tomchop/unxor

WORKDIR /data
VOLUME ["/data"]

ENTRYPOINT [ "/go/bin/unxor" ]
