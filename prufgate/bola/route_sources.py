"""Route paths from a developer's own API description (`prufgate bola --routes-from FILE`).

Reads OpenAPI 3.x / Swagger 2 (YAML or JSON), Postman collection v2.1 and HAR
files. Only the HTTP method and the URL path of each entry are read; hosts,
headers, cookies, bodies, query strings, auth blocks and variables are never
looked at. Only GET and HEAD entries are kept. A path parameter takes the
document's own `example` / `default`; without one it becomes `{tenant_id}`,
the placeholder source discovery uses.
"""

from __future__ import annotations

import json
import os
import re
import urllib.parse

import yaml

MAX_FILE_BYTES = 5 * 1024 * 1024
_KEEP = {"GET", "HEAD"}
_HTTP_METHODS = {"get", "head", "post", "put", "patch", "delete", "options", "trace"}
_SAFE_PATH_CHARS = "/{}%-._~:@!$&'()*+,;="


# Entries walked per file. Without YAML aliases a document has fewer nodes than
# bytes, so this only trips on input that would otherwise expand without bound.
MAX_NODES = MAX_FILE_BYTES


class RouteSourceError(Exception):
    """The file cannot be read, parsed or recognised: the run exits 2."""


class _NoAliasLoader(yaml.SafeLoader):
    """SafeLoader that refuses aliases: a few nested `*refs` expand to billions of nodes."""

    def compose_node(self, parent, index):  # type: ignore[no-untyped-def]
        if self.check_event(yaml.AliasEvent):
            raise yaml.composer.ComposerError(None, None, "YAML aliases are not allowed", self.peek_event().start_mark)
        return super().compose_node(parent, index)


def _clean_path(path: str) -> str:
    path = urllib.parse.quote(path.split("?", 1)[0].split("#", 1)[0].strip(), safe=_SAFE_PATH_CHARS)
    path = re.sub(r"//+", "/", "/" + path.lstrip("/"))
    return path


def _param_value(param: dict) -> object | None:
    if "example" in param:
        return param["example"]
    examples = param.get("examples")
    if isinstance(examples, dict):
        for ex in examples.values():
            if isinstance(ex, dict) and "value" in ex:
                return ex["value"]
    schema = param.get("schema") if isinstance(param.get("schema"), dict) else param
    for key in ("example", "default"):
        if key in schema:
            return schema[key]
    return None


def _resolve(doc: dict, item: object) -> object:
    ref = item.get("$ref") if isinstance(item, dict) else None
    if isinstance(ref, str) and ref.startswith("#/"):
        node: object = doc
        for part in ref[2:].split("/"):
            node = node.get(part.replace("~1", "/").replace("~0", "~")) if isinstance(node, dict) else None
        return node
    return item


def _openapi(doc: dict) -> tuple[list[str], int]:
    prefix = ""
    if isinstance(doc.get("basePath"), str):  # Swagger 2
        prefix = doc["basePath"]
    elif isinstance(doc.get("servers"), list) and doc["servers"] and isinstance(doc["servers"][0], dict):
        server_path = urllib.parse.urlsplit(str(doc["servers"][0].get("url", ""))).path
        prefix = "" if "{" in server_path else server_path
    paths, skipped = [], 0
    for raw_path, item in (doc.get("paths") or {}).items():
        item = _resolve(doc, item)
        if not isinstance(raw_path, str) or not isinstance(item, dict):
            continue
        shared = item.get("parameters") if isinstance(item.get("parameters"), list) else []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS:
                continue
            if method.upper() not in _KEEP:
                skipped += 1
                continue
            own = op.get("parameters") if isinstance(op, dict) and isinstance(op.get("parameters"), list) else []
            values: dict[str, object] = {}
            for p in [_resolve(doc, p) for p in shared + own]:
                if isinstance(p, dict) and p.get("in") == "path" and isinstance(p.get("name"), str):
                    value = _param_value(p)
                    if value is not None:
                        values[p["name"]] = value
            path = re.sub(
                r"\{([^}/]+)\}",
                lambda m, v=values: urllib.parse.quote(str(v[m.group(1)]), safe="") if m.group(1) in v else "{tenant_id}",
                prefix.rstrip("/") + "/" + raw_path.lstrip("/"),
            )
            paths.append(path)
    return paths, skipped


def _postman_path(url: object) -> str | None:
    if isinstance(url, dict):
        segs = url.get("path")
        if isinstance(segs, list):
            return "/" + "/".join(s if isinstance(s, str) else str((s or {}).get("value", "")) for s in segs)
        url = url.get("raw")
    if not isinstance(url, str):
        return None
    url = url.split("?", 1)[0].split("#", 1)[0]
    if "://" in url:
        return urllib.parse.urlsplit(url).path
    if not url.startswith("/"):  # `{{baseUrl}}/items` or `api.example.com/items`: drop the host part
        url = url.partition("/")[2]
    return "/" + url


def _postman(doc: dict) -> tuple[list[str], int]:
    paths, skipped = [], 0
    stack = list(doc.get("item") or [])
    stack.reverse()  # pop() from the end, in document order
    visited = 0
    while stack:
        visited += 1
        if visited > MAX_NODES:
            raise RouteSourceError(f"over {MAX_NODES} Postman entries")
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        if isinstance(node.get("item"), list):
            stack.extend(reversed(node["item"]))
            continue
        req = node.get("request")
        method = "GET"
        if isinstance(req, dict):
            method = str(req.get("method") or "GET").upper()
            url = req.get("url")
        else:
            url = req
        if method not in _KEEP:
            skipped += 1
            continue
        path = _postman_path(url)
        if path:
            path = re.sub(r"\{\{[^}]*\}\}|(?<=/):[A-Za-z_][A-Za-z0-9_]*", "{tenant_id}", path)
            paths.append(path)
    return paths, skipped


def _har(doc: dict) -> tuple[list[str], int]:
    paths, skipped = [], 0
    for entry in doc["log"].get("entries") or []:
        req = entry.get("request") if isinstance(entry, dict) else None
        if not isinstance(req, dict):
            continue
        if str(req.get("method", "")).upper() not in _KEEP:
            skipped += 1
            continue
        paths.append(urllib.parse.urlsplit(str(req.get("url", ""))).path)
    return paths, skipped


def load_route_paths(file_path: str) -> tuple[list[str], int]:
    """Return `(paths, skipped_non_get)` for one file, or raise RouteSourceError."""
    try:
        # A directory, FIFO or device (/dev/zero reports size 0) is not a route file.
        if not os.path.isfile(file_path):
            raise RouteSourceError(f"{file_path} is not a regular file")
        with open(file_path, encoding="utf-8") as fh:
            text = fh.read(MAX_FILE_BYTES + 1)
        if len(text.encode("utf-8")) > MAX_FILE_BYTES:
            raise RouteSourceError(f"{file_path} is over the 5 MB limit for --routes-from")
    except (OSError, UnicodeDecodeError) as exc:
        raise RouteSourceError(f"cannot read {file_path}: {exc}") from exc
    try:
        doc = json.loads(text)
    except ValueError:
        try:
            doc = yaml.load(text, Loader=_NoAliasLoader)  # noqa: S506 (a SafeLoader)
        except yaml.YAMLError as exc:
            raise RouteSourceError(f"cannot parse {file_path} as JSON or YAML : {getattr(exc, 'problem', None) or 'invalid YAML'}") from exc
    if not isinstance(doc, dict):
        raise RouteSourceError(f"{file_path} is not an OpenAPI, Swagger, Postman or HAR document")
    try:
        if "openapi" in doc or "swagger" in doc:
            paths, skipped = _openapi(doc)
        elif isinstance(doc.get("log"), dict) and "entries" in doc["log"]:
            paths, skipped = _har(doc)
        elif isinstance(doc.get("item"), list):
            paths, skipped = _postman(doc)
        else:
            raise RouteSourceError(f"{file_path} is not an OpenAPI, Swagger, Postman or HAR document")
    except (AttributeError, TypeError) as exc:
        raise RouteSourceError(f"{file_path} has an unexpected structure: {exc}") from exc
    return [_clean_path(p) for p in paths], skipped
