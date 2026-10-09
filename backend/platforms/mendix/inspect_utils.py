"""Shared helpers for the Mendix model-inspection scripts."""

import json


def load_model(path="model.json"):
    """Load a JSON model from the inspection script's input path."""
    with open(path, "r", encoding="utf-8") as model_file:
        return json.load(model_file)


def walk(value):
    """Yield each nested dictionary in a model document."""
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)
