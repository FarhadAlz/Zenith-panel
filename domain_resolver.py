"""
domain_resolver.py — Resolve a domain name (given anywhere in the
operator's prompt) to the DirectAdmin account and webroot that host it
on *this* server.

WHY THIS FILE EXISTS:
    Previously, tools.py had a single domain (farhad20.ir) hardcoded into
    DEFAULT_WEBROOT and ALLOWED_LOG_PATHS. That meant every investigation
    — no matter which domain the operator actually asked about — always
    inspected farhad20.ir's webroot and log files.

    This module makes that dynamic: given ANY domain string, it looks the
    domain up on this server's real DirectAdmin filesystem layout and
    returns its webroot + per-domain log paths, or a clear, explicit
    error if the domain is not hosted on this server at all.

DESIGN PRINCIPLES (mirrors tools.py's existing safety model):
    - Read-only. This module never creates, modifies, or deletes anything
      on disk — it only looks paths up with os.path / glob.
    - Restricted to the same filesystem root tools.py already treats as
      safe (/home/), so it can never be used to probe arbitrary paths
      outside the hosting area.
    - Subdomain-aware: if the exact domain isn't itself a DirectAdmin
      domain, this walks up the label chain to find a parent domain that
      IS hosted here, then checks the standard DirectAdmin convention of
      subdomain webroots living under the parent's public_html/<label>.
    - Does not guess: if the domain (as given, or as a subdomain of a
      hosted parent) cannot be found on disk, resolution fails
      explicitly with an error rather than silently falling back to some
      assumed default domain.
"""

import glob
import os
import re

# Same webroot boundary tools.py's ALLOWED_FILE_ROOTS already trusts.
HOME_ROOT = "/home"

# DirectAdmin's per-user domain registry. Only consulted as a best-effort
# corroborating signal (its exact layout differs across DirectAdmin
# versions) — never required for a positive match.
DA_USERS_ROOT = "/usr/local/directadmin/data/users"

_DOMAIN_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$")


def _normalize_domain(raw: str) -> str:
    """
    Reduce a domain given as a bare domain, a full URL, or a domain with
    a trailing path/port/credentials into a plain lowercase hostname.
    """

    if not raw:
        return ""

    value = raw.strip().lower()

    # Strip a scheme, if the caller passed a full URL instead of a bare
    # domain (e.g. the LLM extracted "https://shop.example.com/cart").
    value = re.sub(r"^[a-z][a-z0-9+.-]*://", "", value)

    # Drop credentials, if someone pasted a user@host form.
    if "@" in value:
        value = value.rsplit("@", 1)[1]

    # Drop any path, query string, or fragment.
    value = value.split("/", 1)[0]

    # Drop a port, if present.
    value = value.split(":", 1)[0]

    # DirectAdmin treats "www." as an alias of the bare domain, not a
    # separate hosted domain/subdomain.
    if value.startswith("www."):
        value = value[4:]

    return value.strip(".")


def _is_valid_domain(domain: str) -> bool:
    if not domain or len(domain) > 253:
        return False

    labels = domain.split(".")

    if len(labels) < 2:
        return False

    return all(_DOMAIN_LABEL_RE.match(label) for label in labels)


def _owner_of(domain_dir: str) -> str:
    """
    Given .../home/<user>/domains/<domain>, return <user>.
    """

    parts = domain_dir.rstrip("/").split(os.sep)

    try:
        idx = parts.index("domains")
        return parts[idx - 1]
    except (ValueError, IndexError):
        return "unknown"


def _find_domain_dir(domain: str):
    """
    Look for /home/<any user>/domains/<domain> on disk.

    Returns the resolved (symlink-safe) directory path, or None.
    """

    pattern = os.path.join(HOME_ROOT, "*", "domains", domain)

    for candidate in glob.glob(pattern):
        if os.path.isdir(candidate):
            return os.path.realpath(candidate)

    return None


def _da_conf_exists(user: str, domain: str) -> bool:
    """
    Best-effort corroborating check against DirectAdmin's own per-user
    domain registry, when present on this server. This is extra
    confidence attached to the result — resolution never depends on it,
    since DA's data-directory layout is not identical across versions.
    """

    conf_path = os.path.join(DA_USERS_ROOT, user, "domains", f"{domain}.conf")
    return os.path.exists(conf_path)


def _build_result(
    domain: str,
    domain_dir: str,
    owner: str,
    is_subdomain: bool,
    parent_domain,
    webroot_override: str = None,
) -> dict:

    webroot = webroot_override or os.path.join(domain_dir, "public_html")

    if not os.path.isdir(webroot):
        return {
            "ok": False,
            "domain": domain,
            "owner_user": owner,
            "error": (
                f"Domain directory found ({domain_dir}) but its expected "
                f"webroot ({webroot}) does not exist or is not a "
                "directory."
            ),
        }

    # The vhost (and therefore the log files) a subdomain's traffic is
    # served under is, by default DirectAdmin convention, the PARENT
    # domain's vhost — a subdomain normally does not get its own error
    # log unless explicitly configured with one. We still try the
    # subdomain's own log naming FIRST (see log_paths below) and only
    # fall back to the parent's log (parent_log_paths, consumed by
    # tools.read_log) if that file doesn't exist — this covers both
    # layouts without guessing which one this server uses.
    primary_log_domain = domain
    parent_log_paths = None

    if is_subdomain:
        parent_log_paths = {
            "nginx_error": f"/var/log/nginx/domains/{parent_domain}.error.log",
            "httpd_error": f"/var/log/httpd/domains/{parent_domain}.error.log",
            "php_fpm": f"/var/log/httpd/domains/{parent_domain}.error.log",
        }

    return {
        "ok": True,
        "domain": domain,
        "is_subdomain": is_subdomain,
        "parent_domain": parent_domain,
        "owner_user": owner,
        "webroot": webroot,
        "log_paths": {
            "nginx_error": f"/var/log/nginx/domains/{primary_log_domain}.error.log",
            "httpd_error": f"/var/log/httpd/domains/{primary_log_domain}.error.log",
            # Documented the same way the original static config was:
            # on this DirectAdmin stack, PHP-FPM/application errors are
            # typically surfaced through the domain's Apache error log,
            # not a standalone FPM log.
            "php_fpm": f"/var/log/httpd/domains/{primary_log_domain}.error.log",
        },
        "parent_log_paths": parent_log_paths,
        "directadmin_conf_found": _da_conf_exists(owner, domain if not is_subdomain else parent_domain),
        "error": None,
    }


def resolve_domain(domain: str) -> dict:
    """
    Resolve a domain (or subdomain) to its webroot + log paths on this
    server.

    Returns a dict always containing "ok" and "domain". On success it
    also contains "webroot", "log_paths", "is_subdomain",
    "parent_domain", "owner_user". On failure it contains "error"
    explaining exactly what was checked.
    """

    normalized = _normalize_domain(domain)

    if not _is_valid_domain(normalized):
        return {
            "ok": False,
            "domain": domain,
            "error": (
                f"'{domain}' is not a valid domain name — cannot resolve "
                "a webroot for it."
            ),
        }

    # --- Attempt 1: domain is itself hosted directly on this server -------
    domain_dir = _find_domain_dir(normalized)

    if domain_dir:
        owner = _owner_of(domain_dir)
        return _build_result(
            domain=normalized,
            domain_dir=domain_dir,
            owner=owner,
            is_subdomain=False,
            parent_domain=None,
        )

    # --- Attempt 2: domain is a subdomain of a domain hosted here ---------
    labels = normalized.split(".")

    # Try progressively shorter suffixes as the candidate parent domain.
    # e.g. for "a.b.example.com": parent candidates are "b.example.com",
    # then "example.com". Whatever remains on the left is the subdomain
    # label DirectAdmin would have created under the parent's
    # public_html/.
    for split_index in range(1, len(labels) - 1):
        sub_label = ".".join(labels[:split_index])
        parent_candidate = ".".join(labels[split_index:])

        parent_dir = _find_domain_dir(parent_candidate)

        if not parent_dir:
            continue

        sub_webroot = os.path.join(parent_dir, "public_html", sub_label)

        if os.path.isdir(sub_webroot):
            owner = _owner_of(parent_dir)
            return _build_result(
                domain=normalized,
                domain_dir=parent_dir,
                owner=owner,
                is_subdomain=True,
                parent_domain=parent_candidate,
                webroot_override=os.path.realpath(sub_webroot),
            )

    # --- Not found on this server at all -----------------------------------
    return {
        "ok": False,
        "domain": normalized,
        "error": (
            f"Domain '{normalized}' was not found on this server. "
            f"Checked for it as a hosted domain under "
            f"{HOME_ROOT}/*/domains/{normalized}, and as a subdomain "
            "under every possible parent domain's public_html/. This "
            "agent only investigates domains that are actually hosted "
            "on this server."
        ),
    }