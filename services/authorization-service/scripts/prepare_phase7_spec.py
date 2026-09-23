#!/usr/bin/env python3
"""Pre-process api/openapi.yaml for openapi-generator's python-legacy
target (see docs/python39-constraint.md). Two independent workarounds
for generator limitations, applied to a throwaway copy — never the
canonical spec:

1. python-legacy's regex-pattern postprocessor expects Perl-delimited
   /pattern/ syntax, not bare regex.
2. python-legacy fails to resolve $ref'd components.responses.* objects
   into response_types_map, leaving every generated call return None
   regardless of the actual response. Inlining each response ref's
   contents directly into the operation fixes it.

Usage: prepare_phase7_spec.py <input.yaml> <output.yaml>
"""

import re
import sys

import yaml

PATTERN_RE = re.compile(r"^\^(.*)\$$")


def fix_pattern_delimiters(node):
    if isinstance(node, dict):
        if "pattern" in node and isinstance(node["pattern"], str):
            m = PATTERN_RE.match(node["pattern"])
            if m:
                node["pattern"] = f"/^{m.group(1)}$/"
        for v in node.values():
            fix_pattern_delimiters(v)
    elif isinstance(node, list):
        for v in node:
            fix_pattern_delimiters(v)


def inline_response_refs(node, responses):
    if isinstance(node, dict):
        if set(node.keys()) == {"$ref"} and node["$ref"].startswith("#/components/responses/"):
            name = node["$ref"].rsplit("/", 1)[-1]
            return dict(responses[name])
        return {k: inline_response_refs(v, responses) for k, v in node.items()}
    if isinstance(node, list):
        return [inline_response_refs(v, responses) for v in node]
    return node


def main():
    src, dst = sys.argv[1], sys.argv[2]
    with open(src) as f:
        spec = yaml.safe_load(f)

    fix_pattern_delimiters(spec)

    responses = spec.get("components", {}).get("responses", {})
    for path_item in spec.get("paths", {}).values():
        for operation in path_item.values():
            if isinstance(operation, dict) and "responses" in operation:
                operation["responses"] = inline_response_refs(operation["responses"], responses)

    with open(dst, "w") as f:
        yaml.safe_dump(spec, f, sort_keys=False)


if __name__ == "__main__":
    main()
