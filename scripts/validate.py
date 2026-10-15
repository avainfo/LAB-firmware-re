#!/usr/bin/env python3
"""Validate firmware lab submissions against keyed, unpublished answers.

Only the JSON submission is untrusted. Never execute participant artifacts.
"""

import argparse
import hashlib
import hmac
import json
import os
import re
import shlex
import sys
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

LAB = "01-firmware-image-triage"
SUBMISSION_PATH = f"labs/{LAB}/submission.json"
FIELDS = (
    "header.magic",
    "header.size",
    "payload.offset",
    "payload.format",
    "payload.sha256",
    "startup.command",
    "security.weaknesses",
)
MAX_SUBMISSION_BYTES = 16 * 1024


class SubmissionError(ValueError):
    pass


def require_string(value):
    if not isinstance(value, str):
        raise SubmissionError("Expected a string")
    value = value.strip()
    if not value:
        raise SubmissionError("Empty value")
    return value


def parse_number(value):
    if type(value) is int and value >= 0:
        return value
    if not isinstance(value, str):
        raise SubmissionError("Expected an integer or numeric string")
    value = value.strip()
    if re.fullmatch(r"0[xX][0-9A-Fa-f]+", value):
        return int(value, 16)
    if re.fullmatch(r"[0-9]+", value):
        return int(value, 10)
    raise SubmissionError("Invalid integer")


def parse_command(value):
    try:
        tokens = shlex.split(require_string(value), posix=True)
    except ValueError as e:
        raise SubmissionError("Invalid shell quoting") from e
    if not tokens or not tokens[0].startswith("/"):
        raise SubmissionError("Expected an absolute executable path")
    if any(x in {";", "&&", "||", "|", "$("} for x in tokens):
        raise SubmissionError("Expected a single command")
    options = []
    pos = 1
    while pos < len(tokens):
        token = tokens[pos]
        if not token.startswith("--") or not re.fullmatch(r"--[a-zA-Z][a-zA-Z0-9-]*(?:=.*)?", token):
            raise SubmissionError("Unexpected command argument")
        if "=" in token:
            flag, value = token.split("=", 1)
        elif pos + 1 < len(tokens) and not tokens[pos + 1].startswith("--"):
            flag, value = token, tokens[pos + 1]
            pos += 1
        else:
            flag, value = token, True
        if value == "":
            raise SubmissionError("Empty option value")
        options.append([flag, value])
        pos += 1
    if len({key for key, _ in options}) != len(options):
        raise SubmissionError("Duplicate option")
    return {"exe": tokens[0], "options": sorted(options, key=lambda x: x[0])}


def parse_weaknesses(value):
    if not isinstance(value, list) or len(value) != 2:
        raise SubmissionError("Expected exactly two weaknesses")
    answers = []
    for label in value:
        # Category identifiers rather than prose: ignore case and separators.
        normalized = re.sub(r"[^A-Z0-9]", "", require_string(label).upper())
        if not normalized:
            raise SubmissionError("Empty weakness")
        answers.append(normalized)
    if len(set(answers)) != 2:
        raise SubmissionError("Duplicate weakness")
    return sorted(answers)


def normalize(field, value):
    if field in ("header.size", "payload.offset"):
        return parse_number(value)
    if field == "header.magic":
        return require_string(value).upper()
    if field == "payload.format":
        fmt = require_string(value).lower().replace(" ", "")
        if fmt in {"gzip", "gz", "tar.gz", "tgz", "application/gzip"}:
            return "gzip"
        return fmt
    if field == "payload.sha256":
        digest = re.sub(r"^sha256:\s*", "", require_string(value), flags=re.I)
        if not re.fullmatch(r"[a-fA-F0-9]{64}", digest):
            raise SubmissionError("Invalid SHA-256 fingerprint")
        return digest.lower()
    if field == "startup.command":
        return parse_command(value)
    if field == "security.weaknesses":
        return parse_weaknesses(value)
    raise AssertionError("Unsupported field")


def get_field(data, field):
    value = data
    for key in field.split("."):
        if not isinstance(value, dict) or key not in value:
            raise SubmissionError("Missing field")
        value = value[key]
    return value


def keyed_digest(key, field, value):
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    message = f"firmware-re:v1:{LAB}:{field}\0{encoded}".encode("utf-8")
    return hmac.new(key, message, hashlib.sha256).hexdigest()


def no_duplicate_keys(pairs):
    obj = {}
    for key, val in pairs:
        if key in obj:
            raise SubmissionError("Duplicate JSON key")
        obj[key] = val
    return obj


def load_json(raw):
    if len(raw) > MAX_SUBMISSION_BYTES:
        raise SubmissionError("Submission too large")
    try:
        value = json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except (ValueError, UnicodeDecodeError) as exc:
        raise SubmissionError("Malformed JSON") from exc
    if not isinstance(value, dict):
        raise SubmissionError("Expected a JSON object")
    return value


def from_pull_request():
    repo = os.environ.get("PR_HEAD_REPO", "")
    commit = os.environ.get("PR_HEAD_SHA", "")
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo) or not re.fullmatch(r"[a-fA-F0-9]{40}", commit):
        raise SubmissionError("Invalid pull request source")
    owner, name = repo.split("/")
    url = (
        "https://raw.githubusercontent.com/"
        f"{urllib.parse.quote(owner)}/{urllib.parse.quote(name)}/{commit}/{SUBMISSION_PATH}"
    )
    try:
        request = urllib.request.Request(url, headers={"User-Agent": "firmware-re-validator"})
        with urllib.request.urlopen(request, timeout=15) as response:
            return load_json(response.read(MAX_SUBMISSION_BYTES + 1))
    except urllib.error.URLError as e:
        raise SubmissionError("Could not read submission.json from PR head") from e


def main():
    cli = argparse.ArgumentParser()
    cli.add_argument("mode", choices=("seal", "check"))
    cli.add_argument("--file", type=Path, help="Local JSON file for sealing or checking")
    cli.add_argument("--references", type=Path, default=Path(f"labs/{LAB}/reference.hmac.json"))
    cli.add_argument("--pr", action="store_true", help="Read only the submission JSON from a PR fork")
    args = cli.parse_args()

    key = os.environ.get("CRYPTO_KEY", "").encode("utf-8")
    if not key:
        raise SubmissionError("CRYPTO_KEY is not configured")
    if args.mode == "seal" and (args.file is None or args.pr):
        cli.error("seal requires --file and does not support --pr")
    if args.mode == "check" and (args.pr == (args.file is not None)):
        cli.error("check requires exactly one of --file or --pr")

    data = from_pull_request() if args.pr else load_json(args.file.read_bytes())
    if args.mode == "seal":
        checks = {field: keyed_digest(key, field, normalize(field, get_field(data, field))) for field in FIELDS}
        document = {"lab": LAB, "version": 1, "checks": checks}
        args.references.parent.mkdir(parents=True, exist_ok=True)
        args.references.write_text(json.dumps(document, indent=2) + "\n")
        print(f"Generated keyed references: {args.references}")
        return 0

    try:
        references = json.loads(args.references.read_text())
    except FileNotFoundError as e:
        raise SubmissionError("Missing reference.hmac.json: run seal locally first") from e
    if references.get("lab") != LAB or references.get("version") != 1:
        raise SubmissionError("Invalid reference file")
    passed = 0
    for field in FIELDS:
        try:
            reference = references["checks"][field]
            actual = keyed_digest(key, field, normalize(field, get_field(data, field)))
            valid = hmac.compare_digest(actual, reference)
        except (SubmissionError, KeyError, TypeError):
            valid = False
        print(f"{'PASS' if valid else 'FAIL'}  {field}")
        passed += valid
    print(f"\n{passed}/{len(FIELDS)} checks passed")
    return 0 if passed == len(FIELDS) else 1


if __name__ == "__main__":
    try:
        sys.exit(main())
    except (SubmissionError, OSError) as exc:
        print(f"Validation error: {exc}", file=sys.stderr)
        sys.exit(2)
