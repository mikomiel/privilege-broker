"""Exercise local authorization crypto only; never contact or mutate PVE."""

from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from privilege_broker.pve.authorization import CapabilityProfile, LeaseFactory, LeaseSigner, create_request
from privilege_broker.pve.common import load_policy


def main():
    policy = load_policy(Path(__file__).with_name("pve-policy.json"))
    signer = LeaseSigner.generate()
    ephemeral_public_key = (
        Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.OpenSSH, PublicFormat.OpenSSH).decode("ascii")
    )
    request = create_request(
        "ct.reboot",
        7001,
        "Synthetic local example",
        "example-agent",
        "198.51.100.88",
        "example-client",
        ephemeral_public_key,
        "example-node",
    )
    # This substitutes the host application's prior human approval for a local
    # example. The library factory does not itself perform a passkey ceremony.
    lease = LeaseFactory(signer, policy).create_lease(request, CapabilityProfile.OPERATE, ["ct.reboot"], [7001])
    claims = signer.verify_lease(lease, signer.private_key.public_key())
    assert claims["max_dispatches"] == 1
    assert claims["action_classes"] == ["ct.reboot"]
    print("PVE authorization example verified; no operation executed")


if __name__ == "__main__":
    main()
