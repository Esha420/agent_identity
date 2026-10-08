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


def main():
    parser = argparse.ArgumentParser(description="Mint an Auth0 test token for local CLI testing")
    parser.add_argument("--sub", default="auth0|user-123", help="Subject user ID")
    parser.add_argument("--org", default="org_demo", help="Auth0 Organization ID")
    parser.add_argument("--permissions", nargs="+", default=["agent:execute", "browser:read"], help="Permissions list")
    parser.add_argument("--audience", default="https://agent-admission.example.com", help="Target API Audience")
    parser.add_argument("--issuer", default="https://your-tenant.us.auth0.com/", help="Issuer URL")
    args = parser.parse_args()

    priv_key, kid = get_or_create_key()
    token = create_test_auth0_token(
        private_key=priv_key,
        sub=args.sub,
        kid=kid,
        issuer=args.issuer,
        audience=args.audience,
        permissions=args.permissions,
        scope=" ".join(["openid", "profile"] + args.permissions),
        org_id=args.org,
        expires_in=3600,
    )

    print("\n=== GENERATED TEST AUTH0 TOKEN ===")
    print(token)
    print("===================================\n")
    print(f"Subject:     {args.sub}")
    print(f"Org / Tenant:{args.org}")
    print(f"Permissions: {args.permissions}")
    print("\nYou can use this token with the Orchestrator CLI:")
    print(f'python3 orchestrator/orchestrator.py "Visit website and retrieve page title" --user-token "{token}"\n')


if __name__ == "__main__":
    main()
