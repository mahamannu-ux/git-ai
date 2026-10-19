#!/usr/bin/env python3
"""Materialize the release environment's signed trust documents, without logging them."""

import base64
import binascii
import io
import json
import os
from pathlib import Path
import re
import tarfile


def main() -> None:
    encoded = os.environ.get("TRACKAI_SECURITY_TRUST_DOCUMENTS_B64", "")
    if not encoded:
        raise SystemExit("release trust archive secret is missing")
    try:
        archive = base64.b64decode(encoded, validate=True)
        with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
            members = tar.getmembers()
            names = [member.name for member in members]
            if not 1 <= len(members) <= 32 or len(names) != len(set(names)):
                raise ValueError("invalid release trust archive entries")
            if "root.json" not in names:
                raise ValueError("release trust root.json is missing")
            if any(
                not member.isfile()
                or member.size > 4 * 1024 * 1024
                or not re.fullmatch(r"root\.json|keyset-[a-z0-9_-]+\.json", member.name)
                for member in members
            ):
                raise ValueError("unexpected release trust archive entry")
            destination = Path("release-trust")
            destination.mkdir(mode=0o700)
            for member in members:
                source = tar.extractfile(member)
                if source is None:
                    raise ValueError("release trust document could not be read")
                content = source.read()
                if len(content) != member.size:
                    raise ValueError("release trust document is incomplete")
                if not isinstance(json.loads(content), dict):
                    raise ValueError("release trust document must be a JSON object")
                (destination / member.name).write_bytes(content)
    except (binascii.Error, ValueError, tarfile.TarError) as error:
        raise SystemExit(f"invalid release trust archive: {error}") from None


if __name__ == "__main__":
    main()
