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


microflows = []
pages = []


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

    if node_type == "Microflows$Microflow":

        microflows.append(node)

    elif node_type == "Pages$Page":

        pages.append(node)


print()
print("=" * 70)
print("MENDIX OBJECT INSPECTION")
print("=" * 70)

print()
print("Microflows:", len(microflows))
print("Pages:", len(pages))

print()
print("FIRST 10 MICROFLOWS")
print("-" * 70)

for node in microflows[:10]:

    print(
        node.get(
            "$QualifiedName",
            node.get(
                "name",
                "<unknown>"
            )
        )
    )

print()
print("FIRST 10 PAGES")
print("-" * 70)

for node in pages[:10]:

    print(
        node.get(
            "$QualifiedName",
            node.get(
                "name",
                "<unknown>"
            )
        )
    )