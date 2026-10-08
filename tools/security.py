"""Normalization and Security Engine for Layer 2 Tool Authorization.

Enforces SSRF prevention, IP classification, DNS validation, and canonical filesystem containment.
"""

import ipaddress
import os
from pathlib import Path
import socket
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse

from tools.schema import TaskExecutionContext

# Cloud metadata endpoints and dangerous subnets
METADATA_IPS = {"169.254.169.254"}
METADATA_HOSTS = {"metadata.google.internal", "metadata.azure.com", "instance-data"}


class SecurityValidationError(ValueError):
    """Raised when an argument fails security pre-validation or containment checks."""
    pass


def is_ip_private_or_restricted(ip_obj: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Check if an IP is private, loopback, link-local, multicast, or metadata."""
    if str(ip_obj) in METADATA_IPS:
        return True
    return (
        ip_obj.is_private
        or ip_obj.is_loopback
        or ip_obj.is_link_local
        or ip_obj.is_multicast
        or ip_obj.is_reserved
        or ip_obj.is_unspecified
    )


def normalize_and_validate_url(
    raw_url: str,
    tool_profile: Dict[str, Any],
    profile_name: str = "test",
) -> Dict[str, Any]:
    """
    Syntactically normalize and validate URL arguments against SSRF attacks.
    
    Performs:
    1. Scheme restriction (http/https).
    2. Userinfo rejection (no user:pass@host).
    3. Hostname normalization (lowercase, remove trailing dot).
    4. Exact hostname allowlist lookup against profile.
    5. Port enforcement.
    6. DNS resolution & IP address classification (blocks private/metadata IPs in production).
    """
    if not raw_url or not isinstance(raw_url, str):
        raise SecurityValidationError("Missing or non-string URL argument")

    # Reject embedded null bytes or control characters
    if "\x00" in raw_url or any(ord(c) < 32 for c in raw_url):
        raise SecurityValidationError("Malformed URL: contains illegal control characters")

    parsed = urllib.parse.urlsplit(raw_url)

    # 1. Reject credentials in userinfo
    if parsed.username or parsed.password:
        raise SecurityValidationError("URL contains forbidden userinfo credentials")

    # 2. Scheme check
    allowed_schemes = tool_profile.get("allowed_schemes", ["https"])
    if parsed.scheme.lower() not in allowed_schemes:
        raise SecurityValidationError(
            f"Scheme '{parsed.scheme}' not allowed. Must be one of: {allowed_schemes}"
        )

    # 3. Hostname check
    if not parsed.hostname:
        raise SecurityValidationError("URL missing hostname")

    norm_host = parsed.hostname.lower().rstrip(".")
    if norm_host in METADATA_HOSTS:
        raise SecurityValidationError(f"Access to cloud metadata host '{norm_host}' is blocked")

    allowed_hosts = tool_profile.get("allowed_hosts", [])
    if norm_host not in allowed_hosts:
        raise SecurityValidationError(
            f"Hostname '{norm_host}' not in allowed hosts: {allowed_hosts}"
        )

    # 4. Port check
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    port = parsed.port or default_port
    allowed_ports = tool_profile.get("allowed_ports", [443])
    if port not in allowed_ports:
        raise SecurityValidationError(
            f"Port '{port}' not in allowed ports for profile '{profile_name}': {allowed_ports}"
        )

    # 5. DNS resolution & IP validation (A and AAAA records)
    allow_private_ips = tool_profile.get("allow_private_ips", False)
    resolved_ips = []
    try:
        # Resolve both IPv4 and IPv6 addresses
        addr_info = socket.getaddrinfo(norm_host, port, family=socket.AF_UNSPEC, proto=socket.IPPROTO_TCP)
        for item in addr_info:
            sockaddr = item[4]
            ip_str = sockaddr[0]
            if ip_str not in resolved_ips:
                resolved_ips.append(ip_str)
    except socket.gaierror as e:
        # If host cannot be resolved, reject
        raise SecurityValidationError(f"DNS resolution failed for '{norm_host}': {e}")

    if not resolved_ips:
        raise SecurityValidationError(f"No IP addresses resolved for '{norm_host}'")

    # Classify EVERY resolved IP address: if any address is forbidden, reject request
    for ip_str in resolved_ips:
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            raise SecurityValidationError(f"Resolved invalid IP address: {ip_str}")

        # In all profiles, metadata IP is strictly blocked
        if str(ip_obj) in METADATA_IPS:
            raise SecurityValidationError(f"Resolved to forbidden cloud metadata IP '{ip_str}'")

        if not allow_private_ips and is_ip_private_or_restricted(ip_obj):
            raise SecurityValidationError(
                f"Resolved IP '{ip_str}' is private, loopback, or reserved, forbidden in profile '{profile_name}'"
            )

    primary_ip = resolved_ips[0]
    resolved_ip_is_public = not is_ip_private_or_restricted(ipaddress.ip_address(primary_ip))

    # Reconstruct normalized URL
    norm_netloc = norm_host
    if port != default_port:
        norm_netloc = f"{norm_host}:{port}"
    norm_path = parsed.path or "/"
    normalized_url = urllib.parse.urlunsplit(
        (parsed.scheme.lower(), norm_netloc, norm_path, parsed.query, "")
    )

    return {
        "valid": True,
        "normalized_url": normalized_url,
        "scheme": parsed.scheme.lower(),
        "host": norm_host,
        "port": port,
        "path": norm_path,
        "resolved_ips": resolved_ips,
        "primary_ip": primary_ip,
        "resolved_ip_is_public": resolved_ip_is_public,
        "ip_valid": True,
    }


def normalize_and_validate_path(
    user_supplied_path: str,
    allowed_roots: List[str],
) -> Dict[str, Any]:
    """
    Canonicalize and verify strict filesystem containment inside allowed roots.
    
    Guarantees:
    1. Resolves symlinks and relative traversals ('../').
    2. Rejects path prefix attacks (e.g. '/workspace-evil').
    3. Rejects sensitive root escapes (e.g. '/etc/shadow').
    """
    if not user_supplied_path or not isinstance(user_supplied_path, str):
        raise SecurityValidationError("Missing or non-string path argument")

    if "\x00" in user_supplied_path:
        raise SecurityValidationError("Path contains illegal null byte")

    # 1. Check direct resolution across all roots first (for absolute paths or paths relative to cwd)
    direct_cand = Path(user_supplied_path).resolve(strict=False)
    for root_str in allowed_roots:
        root_path = Path(root_str).resolve(strict=False)
        try:
            rel = direct_cand.relative_to(root_path)
            return {
                "valid": True,
                "canonical_path": str(direct_cand),
                "root": str(root_path),
                "relative_path": str(rel),
                "path_contained": True,
            }
        except ValueError:
            continue

    # 2. Check candidate joined relative to root (for pure relative paths like "test.txt" or "sub/file.txt")
    for root_str in allowed_roots:
        root_path = Path(root_str).resolve(strict=False)
        joined_cand = (root_path / user_supplied_path).resolve(strict=False)
        try:
            rel = joined_cand.relative_to(root_path)
            return {
                "valid": True,
                "canonical_path": str(joined_cand),
                "root": str(root_path),
                "relative_path": str(rel),
                "path_contained": True,
            }
        except ValueError:
            continue

    raise SecurityValidationError(
        f"Path '{user_supplied_path}' escapes authorized roots: {allowed_roots}"
    )


def validate_task_context(
    task_context: TaskExecutionContext,
    expected_agent: Optional[str] = None,
    secret_key: Optional[str] = None,
    expected_audience: str = "tool-gateway",
    expected_issuer: str = "ax-admission-pep",
    current_time: Optional[int] = None,
    required_epoch: Optional[int] = None,
) -> None:
    """Ensure caller presents a valid, cryptographically verified task execution context."""
    if not task_context or not isinstance(task_context, TaskExecutionContext):
        raise SecurityValidationError("Missing or invalid TaskExecutionContext")

    if not task_context.task_id or not task_context.task_id.strip():
        raise SecurityValidationError("TaskExecutionContext has empty task_id")

    if not task_context.tenant_id or not task_context.tenant_id.strip():
        raise SecurityValidationError("TaskExecutionContext has empty tenant_id")

    if not task_context.delegated_by or not task_context.delegated_by.strip():
        raise SecurityValidationError("TaskExecutionContext has empty delegated_by")

    # Verify signature if signature is present or secret_key is provided
    from tools.schema import DEFAULT_SIGNING_KEY
    key_to_use = secret_key or DEFAULT_SIGNING_KEY
    if not task_context.verify_signature(key_to_use):
        raise SecurityValidationError("TaskExecutionContext signature verification failed (forged or tampered)")

    # Expiration check
    if task_context.is_expired(current_time):
        raise SecurityValidationError(f"TaskExecutionContext has expired (expires_at={task_context.expires_at})")

    # Issuer check
    if task_context.issuer != expected_issuer:
        raise SecurityValidationError(f"Invalid context issuer '{task_context.issuer}', expected '{expected_issuer}'")

    # Audience check
    if task_context.audience != expected_audience:
        raise SecurityValidationError(f"Invalid context audience '{task_context.audience}', expected '{expected_audience}'")

    # Epoch check for active task revocation
    if required_epoch is not None and task_context.authorization_epoch < required_epoch:
        raise SecurityValidationError(f"Task authorization epoch {task_context.authorization_epoch} is revoked (required: {required_epoch})")

    # Agent binding check
    if expected_agent and task_context.agent_id != expected_agent:
        raise SecurityValidationError(
            f"Context agent_id '{task_context.agent_id}' does not match caller '{expected_agent}'"
        )
