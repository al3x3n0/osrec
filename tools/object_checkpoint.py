"""Bounded typed object-graph validation, independent of host pointer values."""
from dataclasses import dataclass


@dataclass(frozen=True)
class Reference:
    target: str
    nullable: bool = False
    extent: int = 1


@dataclass(frozen=True)
class ObjectType:
    fields: dict | None = None  # None denotes a byte-buffer object.


def keys(value, expected, label):
    if not isinstance(value, dict) or set(value) != set(expected):
        raise ValueError(f"{label}: unexpected or missing fields")


def unsigned(value, bits, label):
    if type(value) is not int or not 0 <= value < (1 << bits):
        raise ValueError(f"{label}: expected an unsigned {bits}-bit integer")
    return value


def byte_string(value, label):
    if not isinstance(value, str) or len(value) % 2 or len(value) > 8192:
        raise ValueError(f"{label}: invalid bounded byte string")
    if any(character not in "0123456789abcdef" for character in value):
        raise ValueError(f"{label}: bytes must use lowercase hexadecimal")
    return bytes.fromhex(value)


def validate_graph(objects, roots, schemas, root_contracts):
    """Validate closed typed references; accept aliases/cycles and byte interiors.

    Typed struct references must point to object bases. Buffer extents are
    explicit contracts. No raw pointer bytes or implicit structure layouts.
    """
    if not isinstance(objects, list) or not 1 <= len(objects) <= 64:
        raise ValueError("checkpoint requires 1..64 objects")
    keys(roots, root_contracts, "roots")
    indexed = {}
    byte_total = 0
    for entry in objects:
        if not isinstance(entry, dict):
            raise ValueError("object must be a record")
        identifier = unsigned(entry.get("id"), 64, "object ID")
        kind = entry.get("type")
        if not identifier or identifier in indexed or not isinstance(kind, str) or kind not in schemas:
            raise ValueError("duplicate/null object ID or unknown schema")
        schema = schemas[kind]
        keys(entry, ("id", "type", "data" if schema.fields is None else "fields"), "object")
        if schema.fields is None:
            data = byte_string(entry["data"], "object buffer")
            if not data:
                raise ValueError("empty buffer object")
            byte_total += len(data)
        else:
            keys(entry["fields"], schema.fields, "object fields")
            for name, contract in schema.fields.items():
                if contract == "u32":
                    unsigned(entry["fields"][name], 32, name)
                elif not isinstance(contract, Reference):
                    raise ValueError("unknown scalar field contract")
        indexed[identifier] = entry
    if byte_total > 4096:
        raise ValueError("checkpoint buffer storage exceeds 4096 bytes")

    def reference(value, contract):
        keys(value, ("object", "offset"), "reference")
        identifier = unsigned(value["object"], 64, "reference object")
        offset = unsigned(value["offset"], 64, "reference offset")
        if not identifier:
            if offset or not contract.nullable:
                raise ValueError("invalid null reference")
            return 0
        target = indexed.get(identifier)
        if not target or target["type"] != contract.target:
            raise ValueError("dangling or incorrectly typed reference")
        if schemas[contract.target].fields is None:
            size = len(target["data"]) // 2
            if offset >= size or contract.extent > size - offset:
                raise ValueError("buffer reference extent is out of bounds")
        elif offset:
            raise ValueError("typed object reference requires a base address")
        return identifier

    edges = {}
    for identifier, entry in indexed.items():
        edges[identifier] = []
        schema = schemas[entry["type"]]
        for name, contract in (schema.fields or {}).items():
            if isinstance(contract, Reference):
                target = reference(entry["fields"][name], contract)
                if target:
                    edges[identifier].append(target)
    pending = [reference(roots[name], contract) for name, contract in root_contracts.items()]
    reached = set()
    while pending:
        identifier = pending.pop()
        if identifier and identifier not in reached:
            reached.add(identifier)
            pending.extend(edges[identifier])
    if reached != set(indexed):
        raise ValueError("checkpoint contains objects unreachable from its roots")
    return indexed
