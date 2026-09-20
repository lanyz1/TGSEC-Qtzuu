# ICMP Void LKM (post-exploit technique card)

Stealth Linux kernel-module backdoor using ICMP echo as C2, masquerading as ALSA HDA codec.

## When to use
- Authorized RT / KoTH / lab with **root already** (or ability to load LKM)
- Need covert C2 without open TCP/UDP ports

## Components
- `snd_hda_codec.c` — Netfilter ICMP hook + workqueue command exec
- `dev.injector.py` — attacker raw-socket client (Base64+XOR)
- `setup.sh` — build/load + log scrub on target

## Built-in ops (from upstream README)
sync / hide / unhide / ssh-key inject / rogue-user / chisel reverse

## Placement
`domains/linux-post/icmp-void-lkm/` — narrow post-exploit card, NOT a general pentest router.

## Safety
Authorized engagements only. Do not deploy outside RoE.
