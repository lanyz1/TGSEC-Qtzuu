#!/bin/bash
# maradb 13.0.1 release candidate, random root password
exec docker run --rm --name mdb-demo \
  -e MARIADB_ROOT_PASSWORD="$(head -c 100 /dev/urandom|base64)" \
  -e MARIADB_USER=example-user \
  -e MARIADB_PASSWORD=my_cool_secret \
  -e MARIADB_DATABASE=appdb \
  -p 127.0.0.1:3306:3306 \
  mariadb@sha256:ef34af04bda12e6c85395328af78d562176c34fb29ae52063a4eb0d68fa7b3e9
