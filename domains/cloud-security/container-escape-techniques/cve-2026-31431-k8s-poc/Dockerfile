FROM alpine:3.20 AS busybox
RUN apk add --no-cache busybox-static

FROM registry.k8s.io/kube-proxy:v1.35.2

COPY --from=busybox /bin/busybox.static /bin/busybox
RUN ["/bin/busybox", "--install", "-s", "/bin"]
COPY bin/copyfail /bin/copyfail
CMD ["/bin/copyfail"]