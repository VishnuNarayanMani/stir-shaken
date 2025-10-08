#!/usr/bin/env python3
import jwt
import datetime
import uuid
import argparse

def generate_passport(orig_tn, dest_tn, cert_url, private_key_path):
    with open(private_key_path, 'r') as f:
        private_key = f.read()

    # STIR/SHAKEN claims
    passport_payload = {
        "orig": {"tn": [orig_tn]},
        "dest": {"tn": [dest_tn]},
        "iat": int(datetime.datetime.utcnow().timestamp()),
        "attest": "A",  # Full attestation
        "origid": str(uuid.uuid4())  # Unique call ID
    }

    # JWT header
    jwt_headers = {
        "alg": "ES256",
        "ppt": "shaken",
        "typ": "passport",
        "x5u": cert_url  # URL to your public certificate
    }

    # Encode token
    token = jwt.encode(
        payload=passport_payload,
        key=private_key,
        algorithm="ES256",
        headers=jwt_headers
    )

    return token

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate STIR/SHAKEN Identity header.")
    parser.add_argument("--orig", required=True, help="Originating number (e.g., 12155551212)")
    parser.add_argument("--dest", required=True, help="Destination number (e.g., 12155551313)")
    parser.add_argument("--cert-url", required=True, help="Public cert URL (https://yourdomain.com/cert.pem)")
    parser.add_argument("--key", default="/etc/asterisk/703L-20250902.key", help="Path to private key file (PEM)")
    args = parser.parse_args()

    identity_token = generate_passport(args.orig, args.dest, args.cert_url, args.key)
    print("Identity: " + identity_token)
