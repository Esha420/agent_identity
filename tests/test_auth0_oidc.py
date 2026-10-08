"""Unit tests for Auth0 OIDC Token Verifier.

Tests cryptographic signature verification, JWKS handling, claim validation,
algorithm constraints, and fail-closed error behaviors.
"""

import time
import unittest
import jwt

from ax.auth0_verifier import (
    Auth0TokenVerifier,
    Auth0TokenError,
    Auth0ExpiredTokenError,
    Auth0InvalidSignatureError,
    Auth0InvalidIssuerError,
    Auth0InvalidAudienceError,
    Auth0MissingClaimError,
    Auth0MissingPermissionError,
    Auth0UnsupportedAlgorithmError,
    Auth0InvalidOrgError,
    Auth0RevokedUserError,
    generate_test_keypair,
    create_test_auth0_token,
)


class TestAuth0OIDCVerifier(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate primary trusted keypair
        cls.priv_key, cls.pub_key, cls.kid, cls.jwk = generate_test_keypair(kid="auth0-primary-key")
        # Generate secondary untrusted keypair (for signature forgery testing)
        cls.untrusted_priv, cls.untrusted_pub, cls.untrusted_kid, _ = generate_test_keypair(kid="attacker-key")

    def setUp(self):
        self.domain = "test-tenant.us.auth0.com"
        self.issuer = f"https://{self.domain}/"
        self.audience = "https://agent-admission.example.com"
        self.verifier = Auth0TokenVerifier(
            domain=self.domain,
            issuer=self.issuer,
            audience=self.audience,
            allowed_algorithms=["RS256"],
            required_scopes=["agent:execute"],
            local_public_keys={self.kid: self.pub_key},
            tenant_mapping={"org_demo": "tenant-demo", "org_acme": "tenant-acme"},
        )

    def test_01_valid_auth0_token_derives_user_principal(self):
        """Scenario: Valid Auth0 token -> User principal derived accurately."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            sub="auth0|user-123",
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
            permissions=["agent:execute", "browser:read"],
            scope="openid profile email agent:execute browser:read",
            org_id="org_demo",
        )
        user = self.verifier.verify_token(token)
        self.assertEqual(user["id"], "auth0|user-123")
        self.assertEqual(user["tenant_id"], "tenant-demo")
        self.assertEqual(user["organization_id"], "org_demo")
        self.assertIn("agent:execute", user["permissions"])
        self.assertIn("browser:read", user["permissions"])
        self.assertEqual(user["issuer"], self.issuer)

    def test_02_wrong_issuer_rejected(self):
        """Scenario: Wrong issuer -> Rejected with Auth0InvalidIssuerError."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            kid=self.kid,
            issuer="https://evil-untrusted-issuer.com/",
            audience=self.audience,
        )
        with self.assertRaises(Auth0InvalidIssuerError):
            self.verifier.verify_token(token)

    def test_03_wrong_audience_rejected(self):
        """Scenario: Wrong audience -> Rejected with Auth0InvalidAudienceError."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            kid=self.kid,
            issuer=self.issuer,
            audience="https://other-unrelated-api.example.com",
        )
        with self.assertRaises(Auth0InvalidAudienceError):
            self.verifier.verify_token(token)

    def test_04_expired_token_rejected(self):
        """Scenario: Expired token -> Rejected with Auth0ExpiredTokenError."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
            expires_in=-300,  # Expired 5 minutes ago
        )
        with self.assertRaises(Auth0ExpiredTokenError):
            self.verifier.verify_token(token)

    def test_05_invalid_signature_rejected(self):
        """Scenario: Invalid signature -> Rejected with Auth0InvalidSignatureError."""
        # Signed with attacker private key but claims to be kid of primary key
        forged_token = create_test_auth0_token(
            private_key=self.untrusted_priv,
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
        )
        with self.assertRaises(Auth0InvalidSignatureError):
            self.verifier.verify_token(forged_token)

    def test_06_unsupported_algorithm_rejected(self):
        """Scenario: Unsupported algorithm (e.g. HS256) -> Rejected."""
        # Attacker tries symmetric HS256 algorithm with public key as secret
        secret = "symmetric-secret-key-attacker"
        now = int(time.time())
        hs256_token = jwt.encode(
            {
                "iss": self.issuer,
                "sub": "auth0|attacker-123",
                "aud": self.audience,
                "exp": now + 3600,
                "permissions": ["agent:execute"],
            },
            secret,
            algorithm="HS256",
            headers={"kid": self.kid},
        )
        with self.assertRaises(Auth0UnsupportedAlgorithmError):
            self.verifier.verify_token(hs256_token)

    def test_07_missing_sub_rejected(self):
        """Scenario: Missing sub -> Rejected with Auth0MissingClaimError."""
        now = int(time.time())
        token = jwt.encode(
            {
                "iss": self.issuer,
                "aud": self.audience,
                "exp": now + 3600,
                "permissions": ["agent:execute"],
            },
            self.priv_key,
            algorithm="RS256",
            headers={"kid": self.kid},
        )
        with self.assertRaises(Auth0MissingClaimError):
            self.verifier.verify_token(token)

    def test_08_missing_required_permission_rejected(self):
        """Scenario: Missing required permission -> Rejected with Auth0MissingPermissionError."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
            permissions=["task:read"],  # Missing agent:execute
            scope="openid profile email task:read",
        )
        with self.assertRaises(Auth0MissingPermissionError):
            self.verifier.verify_token(token)

    def test_09_wrong_org_id_rejected(self):
        """Scenario: Wrong org_id -> Rejected with Auth0InvalidOrgError."""
        strict_verifier = Auth0TokenVerifier(
            domain=self.domain,
            issuer=self.issuer,
            audience=self.audience,
            required_org_id="org_demo",
            local_public_keys={self.kid: self.pub_key},
        )
        token = create_test_auth0_token(
            private_key=self.priv_key,
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
            org_id="org_other_rogue",
        )
        with self.assertRaises(Auth0InvalidOrgError):
            strict_verifier.verify_token(token)

    def test_10_multi_tenant_organization_mapping(self):
        """Scenario: Organization org_acme maps to tenant-acme."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            sub="auth0|acme-admin",
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
            org_id="org_acme",
        )
        user = self.verifier.verify_token(token)
        self.assertEqual(user["tenant_id"], "tenant-acme")
        self.assertEqual(user["organization_id"], "org_acme")

    def test_11_revoked_auth0_user_rejected(self):
        """Scenario: Revoked Auth0 user -> Rejected with Auth0RevokedUserError."""
        token = create_test_auth0_token(
            private_key=self.priv_key,
            sub="auth0|revoked-user-999",
            kid=self.kid,
            issuer=self.issuer,
            audience=self.audience,
        )
        self.verifier.revoke_subject("auth0|revoked-user-999")
        with self.assertRaises(Auth0RevokedUserError):
            self.verifier.verify_token(token)

    def test_12_malformed_token_rejected(self):
        """Scenario: Non-JWT or malformed string -> Rejected."""
        for malformed in ["", "not-a-jwt", "abc.def", None, 12345]:
            with self.assertRaises(Auth0TokenError):
                self.verifier.verify_token(malformed)


if __name__ == "__main__":
    unittest.main()
