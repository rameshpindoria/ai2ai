"""Use cases plugged into the generic platform.

Each use case registers two things:
- connector:  "module:attribute" of a zero-argument factory returning a Connector (see ..connector). Used by the
              customer edge only.
- vocabulary: a module with CATEGORY_WORDS ({category: [plain words]}) and DEFAULT_CATEGORY. Used by the centre to
              match a customer's request to a service category. It must not import the connector, so the centre never
              loads edge-side code."""
from importlib import import_module

REGISTRY = {
    "it_support": {"connector": "ai2ai_platform.usecases.it_support.connector:ItSupportConnector",
                   "vocabulary": "ai2ai_platform.usecases.it_support.vocabulary"},
}
DEFAULT = "it_support"


def load_connector(name: str = None):
    name = name or DEFAULT
    if name not in REGISTRY:
        raise ValueError(f"unknown use case {name!r}; registered: {sorted(REGISTRY)}")
    module, attr = REGISTRY[name]["connector"].split(":")
    return getattr(import_module(module), attr)()


def category_words() -> dict:
    """Matching vocabulary from every registered use case: {category: [words]}."""
    words = {}
    for entry in REGISTRY.values():
        words.update(import_module(entry["vocabulary"]).CATEGORY_WORDS)
    return words


def default_category() -> str:
    return import_module(REGISTRY[DEFAULT]["vocabulary"]).DEFAULT_CATEGORY
