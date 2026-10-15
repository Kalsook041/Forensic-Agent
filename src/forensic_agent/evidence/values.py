import re


def evidence_value(data, field):
    """Literal fields or bounded positive array indexes; never evaluates expressions."""
    if field in data:
        return data[field]
    match = re.fullmatch(r"(.+?)((?:\[[0-9]{1,6}\])+)", field)
    if not match or match.group(1) not in data:
        raise KeyError(field)
    value = data[match.group(1)]
    for index in re.findall(r"\[([0-9]+)\]", match.group(2)):
        if not isinstance(value, list) or int(index) >= len(value):
            raise KeyError(field)
        value = value[int(index)]
    return value


def supports_answer(step, row):
    # Legacy arbitrary SQL never gains trust merely because grounding was absent.
    if step["request"]["tool_id"] == "sqlite" and step["request"].get("params", {}).get("sql") is not None:
        return False
    return row.get("grounding", "evidence") in {"evidence", "derived"}
