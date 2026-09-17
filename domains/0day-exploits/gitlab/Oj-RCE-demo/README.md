# GitLab Oj RCE Demo

This repository contains a self-contained demo for the GitLab notebook-diff RCE chain described in our research. It starts a fresh GitLab 18.11.3 container, creates an ordinary user through the public HTTP interface, and runs the PoC against that instance.

Technical details: [Going depthfirst: Achieving GitLab RCE via Two Ruby Memory Corruption Vulnerabilities](https://depthfirst.com/research/going-depthfirst-achieving-gitlab-rce-via-two-ruby-memory-corruption-vulnerabilities)

## Requirements

- Linux on x86-64 (`amd64`)
- Docker Engine with Docker Compose v2
- Bash, Python 3, curl, Git, iproute2, and netcat

## Run the demo

First, build a fresh GitLab environment:

```sh
./setup_env.sh
```

This removes the previous demo container and its volumes, starts GitLab, waits for it to become ready, and provisions a normal user. A fresh GitLab boot can take several minutes.

Open two terminals. Start the callback listener in the first:

```sh
./run_poc.sh listen 4555
```

Run the exploit in the second:

```sh
./run_poc.sh exploit 4555
```

When the callback arrives, switch to the listener terminal and run commands such as `id` or `whoami`. The ASLR search time varies between runs.

![Successful demo run](image.png)

## How it works

GitLab renders Jupyter notebook diffs by passing repository-controlled JSON to Oj, a native Ruby JSON parser. The chain combines two parser bugs: one corrupts parser state and eventually controls a callback pointer, while the other discloses a heap pointer used to narrow the ASLR search. The PoC loads a precomputed lookup table, finds the matching library layout through normal GitLab HTTP requests, and makes the Puma worker connect back to the listener as the `git` user.

Use this demo only in the included local lab environment.
