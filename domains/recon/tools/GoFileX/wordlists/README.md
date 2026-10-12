# Wordlists

GoFileX does **not** ship wordlists. Drop your own `.txt` files under
`wordlists/custom/` and `wordlists/public/` (or anywhere else) and queue
them with `/wl add` or `/wl all`.

GoFile folder passwords are documented as **4–100 characters** when you
[set a folder password](https://gofile.io/api). GoFileX skips shorter or
longer lines locally. A skip is not an API call.

## Queue them

```
/wl add ~/lists/high-signal.txt
/wl add ~/lists/nordpass-2025-top200.txt
/wl all
```

`/wl all` walks `wordlists/custom/` first, then `wordlists/public/`, then
any leftover `.txt` in those folders. Put the list you actually believe
in at the top.

## Public lists worth fetching yourself

These are well-known English frequency lists. Download them from the
original publishers. Do not commit them back to this repo.

| List | Why it exists | Source |
|---|---|---|
| NordPass yearly top 200 | Current breach / dark-web aggregate | [NordPass most common passwords](https://nordpass.com/most-common-passwords-list/) |
| SecLists password dumps | The usual CTF starter kit | [danielmiessler/SecLists Passwords](https://github.com/danielmiessler/SecLists/tree/master/Passwords) |
| SecLists 500-worst / 10k-most-common | Short, noisy, cheap | [Passwords/Common-Credentials](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials) |
| `rockyou-75.txt` | RockYou 2009, frequency cutoff. **Not** the 14 million line original | [SecLists rockyou-75](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Leaked-Databases/rockyou-75.txt) |
| Probable-Wordlists v2 top 12k | Combined-breach ranking, 2018 | [berzerk0/Probable-Wordlists](https://github.com/berzerk0/Probable-Wordlists) |
| Xato top 10k / 100k | Unique passwords from the 10-million dump | [SecLists xato](https://github.com/danielmiessler/SecLists/tree/master/Passwords/Common-Credentials) |
| UK NCSC “100k most used” | National-audit ranking | [NCSC password guidance](https://www.ncsc.gov.uk/collection/passwords) · [SecLists mirror](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/100k-most-used-passwords-NCSC.txt) |
| Huntress yearly shortlist | Tiny, current | [Huntress](https://www.huntress.com/) |

Full `rockyou.txt` (~14M lines) is a personality disorder at GoFileX’s
default **3s** listing interval. Do not queue it.

## Custom / OSINT lists

Build those from the target, not from a celebrity dump. For the TESO /
x2 treasure-hunt that this client was written against, the public
strings live in the author’s timeline — start there:

- Hint repo: [Yog-Sotho/Fortinet-Hunter-2026](https://github.com/Yog-Sotho/Fortinet-Hunter-2026)
- TESO scene: [teso.scene.at (archive)](https://web.archive.org/web/*/teso.scene.at)
- TESO exploit prefix `7350` (leetspeak for TESO): [Packet Storm 7350wurm](https://packetstormsecurity.com/files/24658/7350wurm.tgz.html)

I am not publishing the custom generator or the custom list. The hunt is
still live for other people. See
[the notes](../docs/this-is-not-your-password.md).
