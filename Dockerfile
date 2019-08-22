FROM golang:latest as build
RUN go get github.com/tomchop/unxor

FROM scratch
COPY --from=build /go/bin/unxor /bin/unxor
WORKDIR /data
VOLUME ["/data"]
ENTRYPOINT ["/bin/unxor"]
