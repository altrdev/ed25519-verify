"""
Makes the COSE messages of src/__tests__/fixtures/cose.ts again with pycose, the reference implementation, and compares them with
the fixtures byte for byte. Ed25519 is deterministic, so the same key and data give the same message. It also has pycose verify each
signature of each fixture (the other direction: what the page signs, and the messages the tests read, are accepted by pycose).

    pip install -r scripts/requirements.txt
    python scripts/check_cose_fixtures.py            # exits 1 when a fixture differs or does not verify
    python scripts/check_cose_fixtures.py --print    # the new values, to paste into the fixtures file when a change is intended

The keys are the tests 1, 2 and 3 of RFC 8032.
"""

import re
import sys
from pathlib import Path

import cbor2
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from pycose.algorithms import EdDSA
from pycose.headers import Algorithm, ContentType, KID
from pycose.keys import OKPKey
from pycose.messages import CoseMessage, Sign1Message, SignMessage
from pycose.messages.signer import CoseSignature

FIXTURES = Path(__file__).resolve().parent.parent / "src/__tests__/fixtures/cose.ts"
SEEDS = {
    1: "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
    2: "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
    3: "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
}
HELLO = b"hello world"


def key(n):
    seed = bytes.fromhex(SEEDS[n])
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    return OKPKey.from_dict({"KTY": "OKP", "CURVE": "ED25519", "D": seed, "X": public})


def sign1(payload, uhdr=None, phdr=None, aad=b"", tag=True, detached=False):
    message = Sign1Message(phdr=phdr or {Algorithm: EdDSA}, uhdr=uhdr or {}, payload=payload, external_aad=aad)
    message.key = key(1)
    encoded = message.encode(tag=tag)
    return nil_payload(encoded) if detached else encoded


def nil_payload(encoded):
    """The same message with the payload replaced by nil (the signature still covers the payload)."""
    decoded = cbor2.loads(encoded)
    if isinstance(decoded, cbor2.CBORTag):
        items = list(decoded.value)
        items[2] = None
        return cbor2.dumps(cbor2.CBORTag(decoded.tag, items))
    items = list(decoded)
    items[2] = None
    return cbor2.dumps(items)


def cwt(claims, uhdr=None):
    return cbor2.dumps(cbor2.CBORTag(61, cbor2.loads(sign1(cbor2.dumps(claims), uhdr=uhdr))))


def sign(signers, aad=b""):
    signatures = []
    for n, kid in signers:
        signature = CoseSignature(phdr={Algorithm: EdDSA}, uhdr={KID: kid} if kid else {}, key=key(n))
        signature.external_aad = aad
        signatures.append(signature)
    return SignMessage(phdr={}, uhdr={}, payload=HELLO, signers=signatures).encode(tag=True)


RFC8392_CLAIMS = {
    1: "coap://as.example.com", 2: "erikw", 3: "coap://light.example.com",
    4: 1444064944, 5: 1443944944, 6: 1443944944, 7: bytes.fromhex("0b71"),
}  # fmt: skip

# name in the fixtures file -> the message
MADE = {
    "COSE_ATTACHED": lambda: sign1(b"This is the content.", uhdr={KID: b"11"}, phdr={Algorithm: EdDSA, ContentType: 0}),
    "COSE_PLAIN": lambda: sign1(HELLO),
    "COSE_UNTAGGED_KID": lambda: sign1(HELLO, uhdr={KID: b"my-key"}, tag=False),
    "COSE_AAD": lambda: sign1(HELLO, aad=b"context"),
    "COSE_DETACHED": lambda: sign1(HELLO, detached=True),
    "COSE_DETACHED_AAD": lambda: sign1(HELLO, aad=b"context", detached=True),
    "CWT_RFC8392": lambda: cwt(RFC8392_CLAIMS, uhdr={KID: b"AsymmetricECDSA256"}),
    "CWT_LONG": lambda: cwt({1: "https://issuer.example", 2: "alice", 4: 4102444800, 6: 1700000000}),
    "COSE_MISC_CLAIMS": lambda: sign1(cbor2.dumps({1: "x", 4: 4102444800.5, 6: cbor2.CBORTag(1, 1700000000), "custom": [1, 2], -70000: b"zz"})),
    "SIGN_TWO": lambda: sign([(1, b"alice"), (2, b"bob")]),
    "SIGN_THREE": lambda: sign([(1, b"alice"), (2, b"bob"), (3, None)]),
    "SIGN_TWO_AAD": lambda: sign([(1, b"alice"), (2, b"bob")], aad=b"context"),
    "SIGN_TWO_AAD_DETACHED": lambda: nil_payload(sign([(1, b"alice"), (2, b"bob")], aad=b"context")),
}  # fmt: skip

# how to have pycose verify each: (the external data, the payload to give back when it is nil, the key of each signature)
VERIFY = {
    "COSE_ATTACHED": (b"", None, [1]),
    "COSE_PLAIN": (b"", None, [1]),
    "COSE_UNTAGGED_KID": (b"", None, [1]),
    "COSE_AAD": (b"context", None, [1]),
    "COSE_DETACHED": (b"", HELLO, [1]),
    "COSE_DETACHED_AAD": (b"context", HELLO, [1]),
    "CWT_RFC8392": (b"", None, [1]),
    "CWT_LONG": (b"", None, [1]),
    "COSE_MISC_CLAIMS": (b"", None, [1]),
    "SIGN_TWO": (b"", None, [1, 2]),
    "SIGN_THREE": (b"", None, [1, 2, 3]),
    "SIGN_TWO_AAD": (b"context", None, [1, 2]),
    "SIGN_TWO_AAD_DETACHED": (b"context", HELLO, [1, 2]),
}


def fixtures():
    text = FIXTURES.read_text()
    return {name: value for name, value in re.findall(r"export const (\w+) =\s*'([0-9a-f]+)'", text)}


def verifies(name, hex_message):
    aad, payload, keys = VERIFY[name]
    decoded = cbor2.loads(bytes.fromhex(hex_message))
    # pycose reads the tag 18 or 98, not the tag 61 of a CWT around it; an untagged Sign1 is given its tag
    if isinstance(decoded, cbor2.CBORTag) and decoded.tag == 61:
        decoded = decoded.value
    if not isinstance(decoded, cbor2.CBORTag):
        decoded = cbor2.CBORTag(18, decoded)
    data = cbor2.dumps(decoded)
    message = CoseMessage.decode(data)
    if isinstance(message, SignMessage):
        results = []
        for signature, n in zip(message.signers, keys):
            signature.key = key(n)
            signature.external_aad = aad
            results.append(signature.verify_signature(payload))
        return all(results)
    message.key = key(keys[0])
    message.external_aad = aad
    return message.verify_signature(payload)


def main():
    current = fixtures()
    failures = 0
    for name, make in MADE.items():
        made = make().hex()
        if "--print" in sys.argv:
            print(f"export const {name} =\n    '{made}';")
            continue
        if current.get(name) != made:
            print(f"DIFFERS   {name}: pycose makes a different message than the fixture")
            failures += 1
        elif name in VERIFY and not verifies(name, current[name]):
            print(f"REJECTED  {name}: pycose does not verify the fixture")
            failures += 1
        else:
            print(f"ok        {name}")
    sys.exit(1 if failures else 0)


if __name__ == "__main__":
    main()
