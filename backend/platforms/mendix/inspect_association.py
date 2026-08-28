import json


with open(
    "model.json",
    "r",
    encoding="utf-8"
) as f:
    data = json.load(f)


def walk(value):

    if isinstance(value, dict):

        yield value

        for child in value.values():

            if isinstance(child, (dict, list)):

                yield from walk(child)

    elif isinstance(value, list):

        for child in value:

            yield from walk(child)


found = []


for node in walk(data):

    if not isinstance(node, dict):
        continue

    node_type = str(
        node.get(
            "$Type",
            ""
        )
        or ""
    )

    if "DomainModels$Association" in node_type:

        found.append(node)

        if len(found) >= 3:
            break


print()
print("=" * 70)
print("ASSOCIATION EXAMPLES")
print("=" * 70)

for index, association in enumerate(found, 1):

    print()
    print(f"ASSOCIATION {index}")
    print("-" * 70)

    print(
        json.dumps(
            association,
            indent=2,
            ensure_ascii=False
        )
    )


print()
print(
    "Associations found:",
    len(found)
)