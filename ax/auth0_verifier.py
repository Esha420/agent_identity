"""Compatibility re-export of Auth0TokenVerifier from auth.auth0_verifier."""

from auth.auth0_verifier import (
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
    request_auth0_m2m_token,
    generate_test_keypair,
    create_test_auth0_token,
)

__all__ = [
    "Auth0TokenVerifier",
    "Auth0TokenError",
    "Auth0ExpiredTokenError",
    "Auth0InvalidSignatureError",
    "Auth0InvalidIssuerError",
    "Auth0InvalidAudienceError",
    "Auth0MissingClaimError",
    "Auth0MissingPermissionError",
    "Auth0UnsupportedAlgorithmError",
    "Auth0InvalidOrgError",
    "Auth0RevokedUserError",
    "request_auth0_m2m_token",
    "generate_test_keypair",
    "create_test_auth0_token",
]
