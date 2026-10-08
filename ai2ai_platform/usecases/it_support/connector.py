"""IT support connector: the simulated small-business IT estate behind the generic connector interface."""
from . import ops
from .estate import Estate
from .scenarios import BY_ID, plant_injection
from ...connector import DEFAULT_CLASS


class ItSupportConnector:
    name = "it_support"
    listing_id = "it-sim"
    # demo/test controls (only exposed when the edge runs with sim_controls on)
    scenarios = BY_ID
    plant_injection = staticmethod(plant_injection)

    def new_environment(self, data: dict = None) -> Estate:
        return Estate(data)

    def class_of(self, op: str) -> str:
        return ops.CLASS_OF.get(op, DEFAULT_CLASS)

    def describe(self, op: str) -> str:
        spec = ops.OPS.get(op)
        return spec["description"] if spec else f"Unknown operation {op}"

    def run(self, env: Estate, op: str, args: dict):
        return ops.run(env, op, args)

    def catalogue(self) -> list:
        return ops.catalogue()
