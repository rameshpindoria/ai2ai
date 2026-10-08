"""The environment connector: the one seam between the generic platform and a use case.

The customer edge (broker, approvals, snapshots, receipts) knows nothing about any particular domain. Everything it
needs from the customer's environment goes through a Connector:

- an operation catalogue, where every operation has a broker-assigned class
  (read | reversible | security | destructive | egress). Unknown operations are always treated as destructive;
- a way to run one operation against an environment;
- an environment state that can be snapshotted, digested and restored, so every change can be rolled back and every
  receipt can name the exact before and after state.

The reference use case is IT support agents (`ai2ai_platform.usecases.it_support`), backed by an IT-estate simulator.
A new use case (bookkeeping, website admin, a real Microsoft Graph tenant...) implements this interface, adds a
vocabulary module for the centre's matching, and registers both in `ai2ai_platform.usecases.REGISTRY`. See
`tests/toy_usecase.py` for a minimal example."""
from typing import Any, Protocol

DEFAULT_CLASS = "destructive"  # spec Part 2, DX-X-1: unknown operations default to DESTRUCTIVE


class OpError(Exception):
    """A well-formed request that the environment cannot carry out (unknown user, bad value...)."""


class Environment(Protocol):
    def snapshot(self) -> dict: ...

    def digest(self) -> str: ...

    def restore(self, snap: dict) -> None: ...


class Connector(Protocol):
    name: str
    listing_id: str  # the connector name an agent must declare in its card (capabilities.connectors)

    def new_environment(self, data: dict = None) -> Environment:
        """A fresh environment, or one rebuilt from a stored snapshot."""

    def class_of(self, op: str) -> str:
        """The broker class of an operation. MUST return DEFAULT_CLASS for anything unknown."""

    def describe(self, op: str) -> str:
        """Plain-language description shown to the approving human (never agent-written text)."""

    def run(self, env: Environment, op: str, args: dict) -> Any:
        """Run one operation. Raise OpError for a request the environment cannot carry out."""

    def catalogue(self) -> list:
        """The agent-facing operation catalogue: name, class, description, params. No handlers."""
