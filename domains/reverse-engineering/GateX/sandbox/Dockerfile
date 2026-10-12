# linux/amd64 cage for the untrusted 7350FH ELF.
# Ubuntu 24.04: glibc 2.39 (the Nuitka payload needs GLIBC_2.38).
# Built by GateX; not meant to be run by hand.
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends unzip coreutils ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --uid 65532 --create-home --home-dir /home/cage --shell /usr/sbin/nologin cage \
    && mkdir -p /home/cage/in \
    && chown -R cage:cage /home/cage

USER cage
WORKDIR /home/cage
ENV HOME=/tmp \
    TMPDIR=/tmp \
    TEMP=/tmp
# sleep infinity is supplied at `docker run` so the cage stays up for exec.
CMD ["sleep", "infinity"]
