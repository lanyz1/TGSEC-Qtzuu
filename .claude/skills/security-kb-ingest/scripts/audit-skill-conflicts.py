#!/usr/bin/env python3
"""Audit local security knowledge repos for cross-repo skill-name collisions.

Usage:
    python3 audit-skill-conflicts.py [repo_dir ...]

Defaults to the standard /root absorb paths. For each repo it parses ONLY the
first YAML frontmatter block of every SKILL.md (whole-file grep yields false
positives from example snippets in the body), collects skill `name:` values,
and reports duplicates across repos. Exit 0 always; prints report to stdout.
"""
import os, re, sys, glob

DEFAULT_REPOS = [
    '/root/hack-skills',
    '/root/SecAtlas',
    '/root/reverse-skill',
    '/root/AboutSecurity/skills',
    '/root/Claude-BugHunter/skills',
    '/root/Stopen',
    '/root/web-sec',
    '/www/wwwroot/skill',
]

NAME_RE = re.compile(r'^name:\s*(.+)$', re.M)


def frontmatter_names(path):
    """Return skill names from the FIRST frontmatter block only."""
    raw = open(path, encoding='utf-8', errors='ignore').read()
    m = re.match(r'^---\s*\n(.*?)\n---', raw, re.S)
    if not m:
        return []
    return [x.strip().strip('"\'') for x in NAME_RE.findall(m.group(1))]


def collect(root):
    found = {}
    for f in glob.glob(os.path.join(root, '**', 'SKILL.md'), recursive=True):
        for name in frontmatter_names(f):
            found.setdefault(name, []).append(os.path.relpath(f, root))
    return found


def main():
    repos = sys.argv[1:] or DEFAULT_REPOS
    per_repo = {}
    all_names = {}
    for repo in repos:
        if not os.path.isdir(repo):
            print(f'[skip] {repo} not found')
            continue
        names = collect(repo)
        per_repo[repo] = len(names)
        for n, paths in names.items():
            all_names.setdefault(n, []).append((repo, paths))

    print('=== Per-repo skill counts ===')
    for r, c in per_repo.items():
        print(f'  {r}: {c}')

    print()
    print('=== Cross-repo duplicate skill names ===')
    dups = {n: v for n, v in all_names.items() if len(v) > 1}
    if not dups:
        print('  none')
    for n, entries in sorted(dups.items()):
        repos = ', '.join(sorted({r for r, _ in entries}))
        print(f'  {n}: {repos}')

    print()
    print('NOTE: duplicates by name are NOT collisions unless loaded by bare name;'
          ' always access via absolute path. Bare-name lookups (skill_view) only see'
          ' curated router entries under ~/.hermes/skills/.')


if __name__ == '__main__':
    main()
