from backend.platforms.mendix.inspect_utils import load_model, node_type, walk


data = load_model()


microflows = []
pages = []


for node in walk(data):
    kind = node_type(node)

    if kind == "Microflows$Microflow":

        microflows.append(node)

    elif kind == "Pages$Page":

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