# Authorization matrix / IDOR tester

## What this does

`idor_matrix.py` is a small, repeatable authorization-testing tool. It sends
the same request for the same object using multiple explicitly configured
identities, then compares the results.

For example, it can test whether:

* User B can read User A's profile or invoice
* A regular user can access an administrator's object
* Tenant B can access a resource belonging to Tenant A
* An API correctly rejects an object ID that does not belong to the current user

The tool records the HTTP status, response size, content type, and a short body
fingerprint. It reports **POTENTIAL IDOR** when a non-owner receives a
successful response for an object whose owner is known. This is a triage
signal, not proof: manually inspect the response and confirm that the data or
action is sensitive before reporting it.

## Why this belongs in a hunting repository

IDOR is not primarily a brute-force problem. The important question is whether
the server enforces authorization every time an object is accessed—not whether
an identifier can be guessed. A useful hunting workflow needs to:

1. Establish a baseline with the legitimate owner.
2. Replay the request as another authorized user.
3. Compare both responses and record evidence.
4. Repeat the check across object types, endpoints, HTTP methods, and roles.

Keeping this workflow in the repository turns a lab technique into a reusable
methodology. It also encourages structured evidence collection instead of
relying on a single interesting response seen in a proxy.

The same matrix approach applies beyond classic IDOR: horizontal privilege
escalation, vertical privilege escalation, tenant isolation failures, and
missing authorization checks on API endpoints.

## What it does not do

This tool does not prove exploitability or automatically produce a report. A
successful status code may still return an empty or public response, while a
denial may be represented by an application-specific `200` response. Always
review response content, business impact, and the target's program policy.
It also does not discover endpoints, obtain credentials, bypass authentication,
or brute-force identifiers.

## Authorized use only

Run this only against labs, bug-bounty targets whose policy permits it, or
systems where you have written authorization. Keep request volume low and
identify your test traffic where the program asks you to. Tokens are loaded
from environment variables so they do not need to be stored in the config.
Never commit real tokens, customer data, or generated target results.

## Usage

```powershell
$env:OWNER_TOKEN = "owner-token"
$env:OTHER_USER_TOKEN = "other-user-token"
python .\idor_matrix.py .\example-config.json --delay 0.25 --output results.json
```

The command exits with status `1` when at least one potential issue is found,
`0` when no potential issue is found, and `2` for an invalid configuration.

URLs and request bodies may use `{object_id}`. Headers defined for a request
are merged with the headers for each identity; identity headers take
precedence. Use `object_owners` to define which identity should own each
object. Never commit real tokens or target data.

## Configuration model

`example-config.json` defines:

* `identities`: the users or roles to test, with their request headers
* `requests`: named endpoint templates to replay
* `object_ids`: the objects to request
* `object_owners`: the expected owner of each object
* `denied_statuses`: statuses treated as an authorization denial

Identity-specific headers override request-level headers. This makes it
possible to reuse one endpoint definition across multiple sessions while
keeping credentials outside the repository.

## Responsible interpretation

An alert becomes a strong finding when you can demonstrate all of the
following:

* the object contains non-public data or performs a protected action;
* the requesting identity should not have access;
* the server returns the protected data or completes the action; and
* the behavior is reproducible with a minimal, harmless request.

Capture the owner request, unauthorized request, relevant response excerpts,
and impact while redacting tokens and personal data in your report.
