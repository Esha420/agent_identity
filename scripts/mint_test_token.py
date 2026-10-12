#!/usr/bin/env python3
"""Utility to generate a test Auth0 OIDC JWT token offline for local manual testing."""

import argparse
import json
import os
import sys
import time

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ax.auth0_verifier import generate_test_keypair, create_test_auth0_token

TEST_KEY_FILE = os.path.join(os.path.dirname(__file__), "../workspace/.test_auth0_key.json")


def get_or_create_key():
    os.makedirs(os.path.dirname(TEST_KEY_FILE), exist_ok=True)
    if os.path.exists(TEST_KEY_FILE):
        try:
            with open(TEST_KEY_FILE, "r") as f:
                data = json.load(f)
            from cryptography.hazmat.primitives import serialization
            priv_key = serialization.load_pem_private_key(
                data["private_pem"].encode("utf-8"),
                password=None
            )
            return priv_key, data["kid"]
        except Exception:
            pass

    priv_key, pub_key, kid, jwk = generate_test_keypair(kid="local-dev-key-01")
    from cryptography.hazmat.primitives import serialization
    priv_pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode("utf-8")
    pub_pem = pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("utf-8")

    with open(TEST_KEY_FILE, "w") as f:
        json.dump({"private_pem": priv_pem, "public_pem": pub_pem, "kid": kid, "jwk": jwk}, f, indent=2)
    return priv_key, kid


def decode_and_print_token(token: str):
    """Decode a JWT without signature verification for human inspection."""
    import jwt
    try:
        header = jwt.get_unverified_header(token)
        payload = jwt.decode(token, options={"verify_signature": False})
        
        print("\n" + "=" * 65)
        print("          DECODED AUTH0 OIDC JWT TOKEN INSPECTION")
        print("=" * 65)
        print("[*] JOSE HEADER:")
        print(json.dumps(header, indent=4))
        print("\n[*] CLAIMS PAYLOAD:")
        print(json.dumps(payload, indent=4))
        print("\n[*] IDENTITY & SCOPE ANALYSIS:")
        print(f"  • Root Human Authority (sub):     {payload.get('sub')}")
        print(f"  • Tenant Boundary (org_id):       {payload.get('org_id')}")
        print(f"  • Target Admission Audience (aud):{payload.get('aud')}")
        print(f"  • OIDC OAuth2 Scopes (scope):     {payload.get('scope')}")
        print(f"  • Auth0 RBAC Permissions:         {payload.get('permissions', [])}")
        
        perms = payload.get('permissions', [])
        print("\n[*] ENFORCEMENT & ADMISSION PREVIEW:")
        if "agent:execute" in perms:
            print("  [ALLOW] Root admission permitted: 'agent:execute' present.")
        else:
            print("  [DENY]  Root admission BLOCKED: missing 'agent:execute'.")
            
        if "browser:read" in perms:
            print("  [ALLOW] Tool execution permitted: 'browser:read' present (fetch_url, browser_navigate).")
        else:
            print("  [DENY]  Tool execution restricted: 'browser:read' NOT present.")
            
        if "filesystem:read" in perms:
            print("  [ALLOW] Tool execution permitted: 'filesystem:read' present.")
        if "filesystem:write" in perms:
            print("  [ALLOW] Tool execution permitted: 'filesystem:write' present.")
        else:
            print("  [SHIELD] 'filesystem:write' NOT present -> Overwrite/Delete attacks BLOCKED!")
        print("=" * 65 + "\n")
    except Exception as e:
        print(f"[!] Error decoding JWT: {e}")


def main():
    # Load .env if present
    env_path = os.path.join(os.path.dirname(__file__), "../.env")
    if os.path.exists(env_path):
        with open(env_path, "r") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    k = k.strip()
                    v = v.strip().strip('"').strip("'")
                    if k not in os.environ:
                        os.environ[k] = v

    default_issuer = os.getenv("AUTH0_ISSUER", "https://dev-fj2vequ1z3jj2hbu.us.auth0.com/")
    default_audience = os.getenv("AUTH0_AUDIENCE", "https://agent-admission.example.com")

    parser = argparse.ArgumentParser(description="Mint and inspect an Auth0 test token for local CLI testing")
    parser.add_argument("--agent", choices=["browser-agent", "research-agent", "restricted-agent", "openclaw-incident", "no-perm"],
                        help="Preset permissions matching a specific agent scenario")
    parser.add_argument("--sub", default="auth0|user-123", help="Subject user ID")
    parser.add_argument("--org", default="org_demo", help="Auth0 Organization ID")
    parser.add_argument("--permissions", nargs="+", default=None, help="Explicit permissions list")
    parser.add_argument("--audience", default=default_audience, help="Target API Audience")
    parser.add_argument("--issuer", default=default_issuer, help="Issuer URL")
    parser.add_argument("--decode-token", help="Decode and inspect an existing JWT string")
    args = parser.parse_args()

    if args.decode_token:
        decode_and_print_token(args.decode_token)
        return

    # Determine permissions based on preset or explicit arg
    if args.permissions is not None:
        permissions = args.permissions
    elif args.agent == "browser-agent":
        permissions = ["agent:execute", "browser:read"]
    elif args.agent == "research-agent":
        permissions = ["agent:execute", "research:read", "filesystem:read"]
    elif args.agent == "restricted-agent":
        permissions = ["agent:execute"]
    elif args.agent == "openclaw-incident":
        # Simulates agent with read-only authority attempting write/delete
        permissions = ["agent:execute", "filesystem:read"]
    elif args.agent == "no-perm":
        permissions = []
    else:
        permissions = ["agent:execute", "browser:read"]

    priv_key, kid = get_or_create_key()
    token = create_test_auth0_token(
        private_key=priv_key,
        sub=args.sub,
        kid=kid,
        issuer=args.issuer,
        audience=args.audience,
        permissions=permissions,
        scope=" ".join(["openid", "profile"] + permissions),
        org_id=args.org,
        expires_in=3600,
    )

    print("\n" + "=" * 65)
    print("                 RAW ENCODED AUTH0 OIDC JWT")
    print("=" * 65)
    print(token)
    print("=" * 65)

    decode_and_print_token(token)

    print("Use this token directly with the Orchestrator CLI:")
    print(f'python3 orchestrator/orchestrator.py "Visit website and retrieve page title" --user-token "{token}"\n')


if __name__ == "__main__":
    main()
