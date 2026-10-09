import json

from backend.platforms.mendix.inspect_utils import load_model, walk


data = load_model()


entities = []
attributes = []


for node in walk(data):

    if not isinstance(node, dict):
        continue

    node_type = str(
        node.get(
            "$Type",
            ""
        )
    )

    if node_type.endswith(
        "DomainModels$Entity"
    ):

        entities.append(node)

    elif node_type.endswith(
        "DomainModels$Attribute"
    ):

        attributes.append(node)


print()
print("=" * 70)
print("ENTITY STRUCTURE")
print("=" * 70)

if entities:

    entity = entities[0]

    print(
        json.dumps(
            entity,
            indent=2,
            ensure_ascii=False
        )
    )

    print()
    print("ENTITY KEYS:")
    print(
        list(entity.keys())
    )


print()
print("=" * 70)
print("ATTRIBUTE STRUCTURE")
print("=" * 70)

if attributes:

    attribute = attributes[0]

    print(
        json.dumps(
            attribute,
            indent=2,
            ensure_ascii=False
        )
    )

    print()
    print("ATTRIBUTE KEYS:")
    print(
        list(attribute.keys())
    )


print()
print("=" * 70)
print("COUNTS")
print("=" * 70)

print(
    "Entities:",
    len(entities)
)

print(
    "Attributes:",
    len(attributes)
)