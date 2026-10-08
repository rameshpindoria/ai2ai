"""A minimal non-IT use case (a bookkeeping ledger), used to prove the platform is generic: the edge, broker,
approvals, rollback and receipts work through the connector interface alone."""
import copy

from ai2ai_platform.connector import DEFAULT_CLASS, OpError
from ai2ai_platform.core.crypto import digest

CATEGORY_WORDS = {"books.ledger": ["invoice", "ledger", "reconcile", "bookkeeping"]}
DEFAULT_CATEGORY = "books.ledger"

OPS = {
    "ledger.read": ("read", "Read the ledger entries."),
    "ledger.note": ("reversible", "Add a note to a ledger entry."),
    "ledger.wipe": ("destructive", "Delete every ledger entry."),
}


class Ledger:
    def __init__(self, data=None):
        self.data = data if data is not None else {"entries": [{"id": "INV-1", "amount": "120.00", "note": ""}]}

    def snapshot(self):
        return copy.deepcopy(self.data)

    def digest(self):
        return digest(self.data)

    def restore(self, snap):
        self.data = copy.deepcopy(snap)


class ToyConnector:
    name = "toy_ledger"
    listing_id = "toy-ledger"

    def new_environment(self, data=None):
        return Ledger(data)

    def class_of(self, op):
        return OPS[op][0] if op in OPS else DEFAULT_CLASS

    def describe(self, op):
        return OPS[op][1] if op in OPS else f"Unknown operation {op}"

    def run(self, env, op, args):
        if op == "ledger.read":
            return copy.deepcopy(env.data["entries"])
        if op == "ledger.note":
            entry = next((e for e in env.data["entries"] if e["id"] == args.get("id")), None)
            if entry is None:
                raise OpError("no such entry")
            entry["note"] = str(args.get("note", ""))
            return {"ok": True}
        if op == "ledger.wipe":
            env.data["entries"] = []
            return {"ok": True}
        raise OpError(f"unknown operation {op}")

    def catalogue(self):
        return [{"name": n, "class": c, "description": d, "params": {}} for n, (c, d) in OPS.items()]
