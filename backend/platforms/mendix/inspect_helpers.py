import json


def load_model(path: str = "model.json"):
    with open(path, "r", encoding="utf-8") as model_file:
        return json.load(model_file)


def walk(value):
    if isinstance(value, dict):
        yield value
        for child in value.values():
            if isinstance(child, (dict, list)):
                yield from walk(child)
    elif isinstance(value, list):
        for child in value:
            yield from walk(child)


def node_type(node):
    return str(node.get("$Type", "") or "")
