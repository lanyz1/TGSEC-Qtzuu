# This is not your password

A publicly advertised [GoFile](https://gofile.io) share, a TESO homage, two
locks, and a listing API that would rather you bought Premium. I treated
the first lock as OSINT plus documented HTTP. The share password stays
off this page; the hunt is still live.

This is the repo-side note for **GoFileX**. The canonical series lives on
the blog:

| | |
|---|---|
| **Name** | This is not your password |
| **Type** | OSINT / API client notes |
| **Disclosure** | public treasure-hunt; share password withheld |
| **Target** | `https://gofile.io/d/xxxxxxxx` |

Series:

The second lock — the gated binary — is a different problem. This note is
the first door.

---

## The post that wanted to be a dungeon

posted a treasure hunt. Treasure-hunt is their word. The prize was a
standalone build of **Fortinet Hunter 2026**, advertised as a TESO homage:
two protection layers, GoFile first, encrypted binary second. The GoFile
password was labelled *easily guessable*. The binary was labelled the
real challenge.

I do not hunt Fortinet appliances for sport, and I am not going to write
up a FortiOS kill chain because someone wrapped a zip in nostalgia. I
*do* hunt advertised locks when the lock is a public share and the owner
published the rules. A password on a GoFile folder is an access-control
check. The [documented REST API](https://gofile.io/api) exposes that
check as a parameter. If you are going to take the bait, you take it as
a client of the API, not as a browser monkey hammering a form.

The share was:

```
https://gofile.io/d/xxxxxxxx
```

Content id `xxxxxxxx`. Eight-character share code, the form GoFile issues
on new public folders. Mutations require UUIDs. Reads accept the code.
That distinction is in the [API page](https://gofile.io/api) and it is
the first useful fact.

A later reply on the same thread pointed at the public repo
[Yog-Sotho/Fortinet-Hunter-2026](https://github.com/Yog-Sotho/Fortinet-Hunter-2026).
I bookmarked it as context, not as a download. The zip was behind the
share. The share was behind a password. Start at the lock that is
actually in front of you.

## Read the API like it is hostile

[gofile.io/api](https://gofile.io/api) is unusually honest for a consumer
file host. Companion pages worth keeping open:

- [GoFile](https://gofile.io) itself
- [My profile / API token](https://gofile.io/myprofile) (Premium token lives here)
- [GoFile FAQ](https://gofile.io/faq) (rate limits, IP bans)
- [SHA-256](https://en.wikipedia.org/wiki/SHA-2) (the password parameter is a digest, not plaintext)

Rules that actually mattered:

- Every call is authenticated with an **account token**. Bearer header,
  query `token`, or JSON body. Same secret.
- Responses are `{ "status": "...", "data": { } }`. Branch on `status`,
  not only on HTTP. Historical endpoints have answered 200 with an error
  status.
- `GET /contents/{contentId}` is **Premium-badged**. Guests receive
  `error-notPremium`.
- The password parameter is not plaintext. It is the **SHA-256 hex** of
  the folder password. The web client hashes in the browser
  (`crypto.subtle`, UTF-8) and sends the digest.
- Rate limits are per endpoint, per IP and per account. Exact numbers
  are unpublished. `429` / `error-rateLimit` means back off. Repeatedly
  exceeding them may IP-ban you.

That last sentence is not decorative. I will come back to it after I
demonstrate that I can read.

A guest account is minted with an empty `POST /accounts`. No email. The
response is an id, a root folder UUID, `tier: guest`, and a 32-character
token. For guests that token is the only recovery key. The docs say mint
**one** and reuse it. I did.

`GET /accounts/getid` with that Bearer token returned the synthetic
address and confirmed `tier: guest`. So far, this is a polite client.

Then `GET /contents/xxxxxxxx`. Guest token. No extra headers.
`error-notPremium`. HTTP 401. The Premium badge is not a marketing lie.

## The website is not the REST docs

If Premium were required to *view* a public share, the download page
would be a paywall. It is not. The official web app lists public folders
for guests. It cheats, in the respectable sense: it sends headers the
REST docs do not advertise.

The listing call in their own `contents.js` is:

```
GET /contents/{id}?page=&pageSize=&sortField=&sortDirection=
Authorization: Bearer <account token>
X-Website-Token: <wt>
X-BL: <navigator.language>
```

`password`, when present, is still the SHA-256 hex.

`X-Website-Token` is produced by
[`/js/wt.obf.js`](https://gofile.io/js/wt.obf.js). The generator is
obfuscated and the salt rotates. After you peel the script, the current
formula is not mysterious:

```
window = floor(unix_time / 14400)          # 4-hour bucket
wt     = sha256(f"{userAgent}::{language}::{accountToken}::{window}::{salt}")
```

The salt is embedded in the obfuscated generator and is **not** printed
here. User-Agent and `X-BL` on the wire **must** match the strings hashed
into `wt`. Send a static leftover from `config.js` and the server answers
`error-notPremium` even when you are doing exactly what the website does.
That error is overloaded. It means “Premium required” *or* “your website
token is garbage.” Distinguishing those two is half the job.

Password gates are not HTTP errors. A 200 can carry
`data.canAccess === false` plus `password: true` and `passwordStatus` of
`passwordWrong` / `passwordOk`. You are supposed to render a form, not
throw. A wordlist client is the same loop with less chrome.

I also learned, the expensive way, that `GET /accounts/{uuid}` is a
different bucket from `GET /accounts/getid`, and that a handful of
back-to-back calls is enough to earn `error-rateLimit`. Exact quotas
unpublished. Observed behaviour: burst of a few requests, 429, then the
edge stops answering the IP entirely. Connect timeouts to both
`gofile.io` and `api.gofile.io`. The FAQ said that would happen. I had
treated the FAQ as flavour text.

That is the moment you stop improvising curl and write a client with a
limiter, or you go outside.

## GoFileX

IRC-style TUI that talks only to the documented API, sends the
website-token the official app sends, and treats 429 as law.

The TUI is [Textual](https://textual.textualize.io/). HTTP is
[httpx](https://www.python-httpx.org/). Sessions live in
`~/.gofilex/sessions/<name>.json`.

What it does, because the rest of the story is otherwise “I ran a
script”:

- One guest token, persisted, reused. No account-per-guess.
- Sequential `GET /contents/{id}?password=<sha256>`. No parallel workers.
  No “just one more retry” loop on the listing endpoint.
- Website-token computed locally. Salt refresh is *not* a probe. Hitting
  `wt.obf.js` is the same IP as the API.
- Sessions in `~/.gofilex/sessions/<name>.json`, atomic replace, mode
  0600. Per GoFile id: wordlist paths, line number, byte offset, last
  attempt, found password, listing snapshot. The token is
  session-global. Switching `xxxxxxxx` for another share does not wipe
  the first job. A crash restores the line. The guess loop does not
  auto-start after a reboot, because an IP that is still in the penalty
  box does not need my help.
- `/heartbeat`: exactly one listing GET, on demand. It counts toward the
  listing budget. If the slot is not free, it refuses to send. Success
  starts the cruise clock. That replaced the stupid advice of “open the
  site in a browser to see if the ban lifted.” The browser is the same
  IP.

Cruise ended at **3 seconds** per listing call, **1 second** global gap
so nothing bursts. Floor 1.5s. A 429 honours `Retry-After` if present,
otherwise exponential cooldown 15s, 30s, 60s, … cap 8 minutes, and
doubles cruise up to 20s. Pause after three consecutive 429s. A timeout
pauses and wants a single heartbeat when the slot is zero. I started
more conservative than that, because I had just watched the edge
black-hole the host. After the IP came back I loosened it. 3s is not
“fast.” It is “I would like to finish this decade.”

The TUI is unnecessary for the protocol and useful for not losing your
place. Elite Hacker Edition, because if you are going to sit in a
green-on-black box for a few hours you might as well admit it.

## The first lock is a person, not a dictionary

[RockYou](https://en.wikipedia.org/wiki/RockYou) still works on people
who use `123456`. The post said *easily guessable* and then spent its
entire word budget on TESO. That is not a rockyou problem. That is an
attribution problem.

I pulled public English lists anyway, because you do the cheap thing
first and because the client can queue them in order. GoFileX does not
ship those files. Fetch them from the original publishers; see
[wordlists/README.md](../wordlists/README.md).

Then I built a custom list from the hunt itself. The generator is not in
this repo.

### What the treasure-hunt post actually contains

The attached image is not Fortinet. It is the old **TESO** logo:
[`teso.scene.at`](https://web.archive.org/web/*/teso.scene.at), late-90s
demo-scene chrome, a block of binary, a `RMDE` mark in the corner. The
bits are:

```
1010011 1001111 1010100 1000101
```

That is **SOTE**, TESO rotated, which is either a joke or a password.
You put both in the list. You do not get religious about which.

The body copy is doing more work than the image:

- “the greatest Hacking Group ever existed **TEAM TESO**”
- “Do you remember **x2 exploit from TESO**?”
- two layers: GoFile password, binary password
- prize name: Fortinet Hunter 2026

TESO’s public fingerprint from the early 2000s is the **7350** prefix on
their exploits
([`7350wurm`](https://packetstormsecurity.com/files/24658/7350wurm.tgz.html)
for wu-ftpd 2.6.0/2.6.1, and friends). 7350 is leetspeak for TESO
(`T=7 E=3 S=5 O=0`). If you have ever read a TESO header you already
know that. If you have not, you learn it in twenty minutes of
[Packet Storm](https://packetstormsecurity.com/) archaeology and then
you put `teso` and `7350` at the top of the list, because “easily
guessable” from a TESO tribute is allowed to be `teso`.

### What the author’s other posts add

OSINT is not “stare at the one tweet until it confesses.” It is “read
the nearby tweets before you generate a million concatenations.”

On 13 August 2026 the same account talked about **7350wurm**, RedHat
7.0, wu-ftpd 2.6.0/2.6.1, and then asked, in public, *“When a song on x2
mass ssh rooter? Do you remember the password?”* So `x2` is not a
Fortinet CVE in this story. It is a TESO-era mass SSH rooter, and the
password is part of the in-joke.

Handles and crew tags on the profile:
pr0j3ctm4hy3m. THC had also stood up `free.team-teso.net` around the
same period. Lovecraft is in the username: Yog-Sothoth is the key and
the gate. That last one is optional colour. The public strings are not.

I treated those public strings as first-class tokens, next to TESO and
7350. When someone labels a lock *easily guessable*, you start with what
they have already put in public. You put that family near the top. I am
not quoting the winning line. The hunt is still running.

### How the custom list is actually built

A local token expander. It does not scrape. It does not call an LLM at
generation time.

1. **HIGH tokens**, in try-order: `teso`, `7350`, `teamteso`,
   `fortinethunter2026`, `thekeyandthegate`, TESO handles from 7350
   headers (`scut`, `lorian`, …). Clean forms first. No years yet. The
   first screenful of the file should be things a human might actually
   type.
2. **Case and leet** on those tokens. Lower, UPPER, Title, first-letter
   flip, and the usual `a4 e3 i1 o0 s5 t7` map. `teso` leets to `7350`,
   which is why that collision is a feature.
3. **Years and suffixes** only after the clean forms: 1999–2003 (TESO’s
   public years), 2010/2011, 2024–2026, then `!`, `123`, `x2`, `7350`.
4. **Pair concatenations** of a small head set (`teso`, `7350`, `x2`,
   `-`, `_`, `.`.
5. **MEDIUM tokens** (Fortinet product names, Fight Club / Project
   Mayhem, Italian food the account actually jokes about, scene URLs)
   get a thinner mutation pass so they cannot drown the HIGH list.
6. Filter to GoFile’s documented password length when *setting* a folder
   password: **4–100 characters**. Shorter strings never leave the
   machine. They would only waste listing calls.

Custom first in the TUI queue, then NordPass, then the larger breach
lists. GoFileX skips unusable lines locally. A skip is not an API call.

I am aware that a pile of `Team-Teso2026` concatenations looks like a
cargo cult. Most of it is ballast. The ballast is cheap if the top of
the file contains the public TESO and account strings that belong at the
front of a hunt like this.

## One listing at a time

With the IP speaking again: `/heartbeat`. One `GET /contents/xxxxxxxx`,
website-token on the wire, guest Bearer, no password parameter. That
call is the first listing request. It counts. The next guess waits the
cruise interval.

The 200 came back with the gate up: password-protected, `canAccess`
false. Good. The share exists. The lock is the one they advertised.

`/wl all` queued the custom file and the public lists. `/start`.
Sequential SHA-256, 3s cruise, session checkpoint after every attempt so
a dead battery does not cost a thousand lines.

The listing opened. SHA-256 of the guess, sent as `password=`,
`passwordStatus` came back `passwordOk`, `canAccess` true, children in
the listing, file links on the objects. Download is a GET of `item.link`
with the same account token as a cookie. Folder ZIP is Premium.
Individual files are not. I did not need Premium for this door.

The hit was in the custom OSINT list, not a NordPass celebrity, not the
NCSC 100k as the thing that mattered. I am not printing the string.
purpose. The dressing was real. Other people are still walking it.

## What I am not claiming

I am not claiming this is a GoFile vulnerability. The password parameter
is doing its job. The API behaved as documented: hash the guess, send
it, read `passwordStatus`. The share password stays off this page
because the challenge is still on for everyone else.

I am not publishing a walkthrough of Fortinet Hunter. The zip is someone
else’s toy. Opening a padlock they put on a public locker is not the
same as running the contents.

I am not recommending that you fire `GET /contents` in a tight loop
until the edge forgets your IP. The unpublished limit is real. The ban
is real. A limiter that refuses to burst, counts the heartbeat, and
backs off 15s/30s/60s on 429 is the difference between a client and a
tantrum. I am not publishing how many listing calls it took.

## Sequence, compressed

2. Read [gofile.io/api](https://gofile.io/api). Guest `POST /accounts`. One token, keep it.
3. Discover that listing is Premium-badged for raw REST and permitted for the web app via `X-Website-Token`.
4. Reverse [`wt.obf.js`](https://gofile.io/js/wt.obf.js). Hash `UA :: language :: token :: floor(t/14400) :: salt`. Match headers to the hash inputs.
5. Learn `password` is SHA-256 hex. Learn gates arrive as 200s.
6. Burst a few calls, collect 429s, collect an IP timeout. Believe the FAQ.
8. Pull public frequency lists. Do not pull 14 million RockYou lines. Do not commit them.
9. Build a TESO/x2-themed list from the post, the logo, 7350 leetspeak, and the author’s public posts.
10. Heartbeat. Gate confirmed. Start the custom list. Hash, send, checkpoint.
11. Listing opens. File links work. Premium still unused. Share password withheld.

The mystery was not the SHA-256. The rest was plumbing, and a hunt that
is still live.

---

