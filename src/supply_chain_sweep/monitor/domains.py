"""Domain helpers: registered domain (eTLD+1), lookalike detection, default allowlist."""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from pathlib import Path

PSL_URL = "https://publicsuffix.org/list/public_suffix_list.dat"

# Fallback when the Public Suffix List has not been downloaded: common multi-label suffixes.
_FALLBACK_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "ne.jp", "or.jp",
    "com.br", "com.cn", "net.cn", "com.tw", "co.kr", "co.in", "co.za", "com.mx", "com.sg", "com.hk", "com.tr",
    "github.io", "githubusercontent.com", "herokuapp.com", "appspot.com", "azurewebsites.net", "cloudfront.net",
    "vercel.app", "netlify.app", "pages.dev", "workers.dev", "s3.amazonaws.com", "blogspot.com", "fly.dev",
    "onrender.com", "ngrok.io", "ngrok-free.app", "duckdns.org", "trycloudflare.com",
}

# Registries and APIs package managers, interpreters and containers normally talk to (MON-15).
# Entries match the domain and all its subdomains.
DEFAULT_ALLOW = [
    # Python
    "pypi.org", "pythonhosted.org", "python.org", "pypa.io", "astral.sh", "anaconda.org", "anaconda.com",
    "anaconda.cloud", "conda-forge.org", "prefix.dev", "readthedocs.io", "readthedocs.org",
    # JavaScript
    "npmjs.org", "npmjs.com", "yarnpkg.com", "nodejs.org", "jsdelivr.net", "unpkg.com", "deno.land", "jsr.io",
    "bun.sh",
    # Source hosting
    "github.com", "githubusercontent.com", "githubassets.com", "gitlab.com", "bitbucket.org",
    # Containers
    "docker.io", "docker.com", "ghcr.io", "quay.io", "gcr.io", "pkg.dev", "mcr.microsoft.com", "amazonaws.com",
    # LLM and ML APIs
    "openai.com", "anthropic.com", "claude.ai", "googleapis.com", "mistral.ai", "cohere.com", "cohere.ai",
    "groq.com", "together.xyz", "huggingface.co", "hf.co", "replicate.com", "fireworks.ai", "openrouter.ai",
    "litellm.ai", "pytorch.org", "nvidia.com",
    # OS packages
    "debian.org", "ubuntu.com", "alpinelinux.org", "fedoraproject.org", "brew.sh",
]

# Vendor / package brands and the domains that legitimately carry them (MON-11).
BRANDS: dict[str, list[str]] = {
    "pypi": ["pypi.org", "pypi.io"],
    "pythonhosted": ["pythonhosted.org"],
    "npmjs": ["npmjs.org", "npmjs.com"],
    "yarnpkg": ["yarnpkg.com"],
    "github": ["github.com", "github.io", "githubusercontent.com", "githubassets.com", "githubapp.com"],
    "githubusercontent": ["githubusercontent.com"],
    "gitlab": ["gitlab.com", "gitlab.io"],
    "anaconda": ["anaconda.org", "anaconda.com", "anaconda.cloud"],
    "huggingface": ["huggingface.co"],
    "openai": ["openai.com", "oaiusercontent.com", "oaistatic.com"],
    "anthropic": ["anthropic.com"],
    "claude": ["claude.ai", "claude.com", "anthropic.com"],
    "litellm": ["litellm.ai"],
    "langchain": ["langchain.com", "langchain.dev"],
    "pytorch": ["pytorch.org"],
    "docker": ["docker.com", "docker.io"],
    "googleapis": ["googleapis.com"],
    "amazonaws": ["amazonaws.com"],
    "cloudflare": ["cloudflare.com", "cloudflare.net", "cloudflare-dns.com"],
    "mistral": ["mistral.ai"],
    "cohere": ["cohere.com", "cohere.ai"],
    "checkmarx": ["checkmarx.com", "checkmarx.net"],
    "aquasec": ["aquasec.com"],
    "jfrog": ["jfrog.io", "jfrog.com"],
    "sonatype": ["sonatype.com", "sonatype.org"],
}

_HOST = re.compile(r"^(?=.{1,253}$)([a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z0-9-]{2,63}$")


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


def valid_hostname(name: str) -> bool:
    return bool(_HOST.match(name.rstrip(".").lower()))


class Suffixes:
    """Public Suffix List rules (normal, wildcard and exception)."""

    def __init__(self, text: str | None = None) -> None:
        self.rules: set[str] = set()
        self.wild: set[str] = set()
        self.exceptions: set[str] = set()
        if text:
            for line in text.splitlines():
                line = line.strip().lower()
                if not line or line.startswith("//"):
                    continue
                if line.startswith("!"):
                    self.exceptions.add(line[1:])
                elif line.startswith("*."):
                    self.wild.add(line[2:])
                else:
                    self.rules.add(line)
        else:
            self.rules = set(_FALLBACK_SUFFIXES)

    @classmethod
    def load(cls, path: Path) -> Suffixes:
        try:
            return cls(path.read_text(encoding="utf-8"))
        except OSError:
            return cls()

    def registered(self, name: str) -> str:
        """eTLD+1 for a hostname ("a.b.example.co.uk" -> "example.co.uk"). IPs come back unchanged."""
        name = name.rstrip(".").lower()
        if is_ip(name):
            return name
        labels = name.split(".")
        if len(labels) < 2:
            return name
        suffix_len = 1
        for i in range(len(labels)):
            cand = ".".join(labels[i:])
            if cand in self.exceptions:
                suffix_len = len(labels) - i - 1
                break
            if cand in self.rules:
                suffix_len = len(labels) - i
                break
            if i + 1 < len(labels) and ".".join(labels[i + 1:]) in self.wild:
                suffix_len = len(labels) - i
                break
        if suffix_len >= len(labels):
            return name
        return ".".join(labels[-(suffix_len + 1):])


def matches_domain(name: str, rule: str) -> bool:
    name, rule = name.rstrip(".").lower(), rule.lstrip("*.").lower()
    return name == rule or name.endswith("." + rule)


@lru_cache(maxsize=65536)
def _distance(a: str, b: str) -> int:
    """Damerau-Levenshtein (optimal string alignment) distance."""
    if abs(len(a) - len(b)) > 2:
        return 3
    prev2: list[int] = []
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i] + [0] * len(b)
        for j, cb in enumerate(b, 1):
            cur[j] = min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb))
            if i > 1 and j > 1 and ca == b[j - 2] and a[i - 2] == cb:
                cur[j] = min(cur[j], prev2[j - 2] + 1)
        prev2, prev = prev, cur
    return prev[-1]


def lookalike(name: str, registered: str, brands: dict[str, list[str]] = BRANDS) -> str:
    """Why `name` looks like an impersonation of a known brand, or "" (MON-11)."""
    name = name.rstrip(".").lower()
    if is_ip(name) or registered == name and "." not in name:
        return ""
    for legit in (d for ds in brands.values() for d in ds):
        if matches_domain(name, legit):
            return ""
    label = registered.split(".")[0]
    tokens = re.split(r"[-_]", label)
    for brand, legit in brands.items():
        expected = ", ".join(legit)
        if label == brand:
            return f"uses brand '{brand}' on {registered} (expected {expected})"
        if brand in tokens and len(brand) >= 4:
            return f"embeds brand '{brand}' in {registered} (expected {expected})"
        for d in legit:
            if f".{d}." in f".{name}." and not matches_domain(name, d):
                return f"embeds {d} inside {name}"
        limit = 1 if len(brand) < 8 else 2
        if len(brand) >= 5 and label != brand and _distance(label, brand) <= limit:
            return f"'{label}' is one typo from brand '{brand}' (expected {expected})"
    return ""
