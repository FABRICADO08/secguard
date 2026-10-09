import json

from backend.platforms.mendix.inspect_utils import load_model, walk


data = load_model()


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