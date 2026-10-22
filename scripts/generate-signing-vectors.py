"""Print shared vectors using hyperliquid-python-sdk 0.24.0, independently of Rust."""
import json

import msgpack
from eth_account.messages import encode_typed_data
from eth_utils import keccak
from hyperliquid.utils.signing import action_hash, construct_phantom_agent, l1_payload


order = {"a": 0, "b": True, "p": "100", "s": "0.01", "r": False,
         "t": {"limit": {"tif": "Gtc"}}}
actions = [
    ("limit", {"type": "order", "orders": [order], "grouping": "na"}),
    ("builder", {"type": "order", "orders": [order], "grouping": "na",
                 "builder": {"b": "0x0000000000000000000000000000000000000001", "f": 10}}),
    ("trigger-cloid", {"type": "order", "orders": [{**order,
        "t": {"trigger": {"isMarket": True, "triggerPx": "110", "tpsl": "tp"}},
        "c": "0x00000000000000000000000000000001"}], "grouping": "normalTpsl"}),
    ("cancel", {"type": "cancel", "cancels": [{"a": 0, "o": 42}]}),
    ("fast-cancel", {"type": "cancel", "cancels": [{"a": 0, "o": 42}], "f": True}),
    ("cloid", {"type": "cancelByCloid", "cancels": [
        {"asset": 0, "cloid": "0x00000000000000000000000000000001"}]}),
    ("fast-cloid", {"type": "cancelByCloid", "cancels": [
        {"asset": 0, "cloid": "0x00000000000000000000000000000001"}], "f": True}),
    ("schedule", {"type": "scheduleCancel", "time": 123456789}),
    ("unschedule", {"type": "scheduleCancel"}),
    ("leverage", {"type": "updateLeverage", "asset": 0, "isCross": True, "leverage": 3}),
]
vectors = []
for name, action in actions:
    for network in ("mainnet", "testnet"):
        for vault, expires in ((None, None),
                               ("0x0000000000000000000000000000000000000003", 999999)):
            connection = action_hash(action, vault, 123, expires)
            typed = l1_payload(construct_phantom_agent(connection, network == "mainnet"))
            message = encode_typed_data(full_message=typed)
            preimage = b"\x19" + message.version + message.header + message.body
            vectors.append({"name": name, "network": network, "action": action,
                            "nonce": 123, "vault_address": vault, "expires_after": expires,
                            "messagepack": msgpack.packb(action).hex(),
                            "action_hash": "0x" + connection.hex(),
                            "preimage": preimage.hex(), "hash": "0x" + keccak(preimage).hex()})
print(json.dumps(vectors, indent=2))
