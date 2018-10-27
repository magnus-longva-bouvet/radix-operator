FROM golang:alpine3.7 as builder

RUN apk update && apk add git && apk add -y ca-certificates curl && \
    curl https://raw.githubusercontent.com/golang/dep/master/install.sh | sh
RUN mkdir -p /go/src/github.com/statoil/radix-operator/
WORKDIR /go/src/github.com/statoil/radix-operator/
COPY Gopkg.toml Gopkg.lock ./
RUN dep ensure -vendor-only
COPY ./radix-operator ./radix-operator
COPY ./pkg ./pkg
WORKDIR /go/src/github.com/statoil/radix-operator/radix-operator/

ARG date
ARG commitid
ARG branch

RUN CGO_ENABLED=0 GOOS=linux go build -ldflags "-s -w -X main.commitid=${commitid} -X main.branch=${branch} -X main.date=${date}" -a -installsuffix cgo -o ./rootfs/radix-operator
RUN adduser -D -g '' radix-operator

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /go/src/github.com/statoil/radix-operator/radix-operator/rootfs/radix-operator /usr/local/bin/radix-operator
USER radix-operator
ENTRYPOINT ["/usr/local/bin/radix-operator"]