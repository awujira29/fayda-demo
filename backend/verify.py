"""
Wallet proof-of-control.

Same shape on both chains — server issues a single-use nonce, the wallet signs a
structured message, the server checks the signature really came from the claimed
address. The cryptography differs:

  EVM     secp256k1. You *recover* the signer from the signature and compare it
          to the claimed address. EIP-191 personal_sign framing.
  Solana  ed25519. You *verify* against the public key directly, because on
          Solana the address IS the public key. Nothing to recover.

Neither path touches an RPC node. This is pure cryptography, so the demo needs
no testnet, no faucet and no chain config.
"""

import os
from urllib.parse import urlparse

import base58
import nacl.signing
import nacl.exceptions
from eth_account import Account
from eth_account.messages import encode_defunct

# The message's stated origin must match what the user's address bar and the
# wallet's origin check show — three mismatched origins at the moment of
# signing reads as phishing. Derived from the same env contract app.py uses:
# PUBLIC_URL is the browser-facing origin, BASE_URL the fallback.
URI = (os.getenv("PUBLIC_URL")
       or os.getenv("RENDER_EXTERNAL_URL")
       or os.getenv("BASE_URL", "http://127.0.0.1:8000")).rstrip("/")
DOMAIN = urlparse(URI).netloc or "fayda-registry.local"


def build_message(chain: str, address: str, nonce: str, issued_at: str,
                  expires_at: str, identity_label: str) -> str:
    """
    SIWE-style (EIP-4361). Human-readable on purpose: the user should be able to
    read in their wallet exactly what they are agreeing to before they sign.
    """
    chain_label = "Ethereum" if chain == "evm" else "Solana"
    return (
        f"{DOMAIN} wants you to bind this wallet to your Fayda-verified identity.\n"
        f"\n"
        f"{chain_label} address:\n{address}\n"
        f"\n"
        f"Identity: {identity_label}\n"
        f"\n"
        f"By signing you prove you control this wallet.\n"
        f"This does not grant any permission to move funds.\n"
        f"This binding will be listed in the public registry.\n"
        f"\n"
        f"URI: {URI}\n"
        f"Chain: {chain_label}\n"
        f"Nonce: {nonce}\n"
        f"Issued At: {issued_at}\n"
        f"Expiration Time: {expires_at}"
    )


def verify_evm(message: str, signature: str, claimed_address: str) -> tuple[bool, str]:
    try:
        recovered = Account.recover_message(
            encode_defunct(text=message), signature=signature
        )
    except Exception as e:
        return False, f"could not recover signer: {e}"
    if recovered.lower() != claimed_address.lower():
        return False, f"signature recovers to {recovered}, not {claimed_address}"
    return True, ""


def verify_solana(message: str, signature_b58: str, claimed_address: str) -> tuple[bool, str]:
    try:
        pubkey_bytes = base58.b58decode(claimed_address)
        if len(pubkey_bytes) != 32:
            return False, "address is not a 32-byte ed25519 public key"
        sig_bytes = base58.b58decode(signature_b58)
        nacl.signing.VerifyKey(pubkey_bytes).verify(message.encode(), sig_bytes)
        return True, ""
    except nacl.exceptions.BadSignatureError:
        return False, "signature does not match this public key"
    except Exception as e:
        return False, f"malformed address or signature: {e}"


def verify(chain: str, message: str, signature: str, address: str) -> tuple[bool, str]:
    if chain == "evm":
        return verify_evm(message, signature, address)
    if chain == "solana":
        return verify_solana(message, signature, address)
    return False, f"unsupported chain {chain}"


def looks_like_address(chain: str, address: str) -> bool:
    if chain == "evm":
        return address.startswith("0x") and len(address) == 42
    try:
        return len(base58.b58decode(address)) == 32
    except Exception:
        return False
