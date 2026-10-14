# Evidence Export

Status: built and tested. Shared library, not a running service.

## Scope

Turns any module's signed chain of custody into a court-admissible, self-verifying export package, and provides the standalone verifier that confirms one offline. Every module that keeps an evidence chain (dark web monitoring, vulnerability management, penetration testing, incident response, managed services, Office of Special Projects) produces the same package shape, so a client, auditor or opposing expert learns one verification step for all of them.

## The package

A single zip, wrapped in one top folder, containing:

- `MANIFEST.json` — metadata plus the sha256 of every other file.
- `MANIFEST.sig` — an Ed25519 signature over sha256(MANIFEST.json) by the platform signing key, the same key that signed the chain. Editing the manifest breaks it.
- `proof.json` — the chain: every record with its immutable fields, prev_hash, content_hash and signature, plus a self-check run at export time.
- `public_key.txt` — the signing key's public half.
- `verify_evidence.py` — the standalone verifier, embedded so the package verifies itself.
- `README.txt` — what the package is and how to verify it by hand.
- `timestamp.tsr`, `timestamp.json` — optional RFC 3161 trusted timestamp over the manifest hash, when a TSA is configured.

Because the manifest records the hash of `proof.json` and is itself signed, and the records form a hash chain each committing to the one before it, altering any record, file or the manifest is detectable. Write-once (WORM) storage, such as S3 Object Lock, is applied at rest in production; the signatures make tampering detectable wherever the package travels afterward.

## The independent verifier

`verify_evidence.py` runs with no access to the platform and no network:

    pip install cryptography          # core checks
    pip install asn1crypto            # optional, to also verify the RFC 3161 timestamp
    python verify_evidence.py <package.zip | unpacked-directory>

It prints PASS or FAIL for the package seal, every file's integrity, the chain of custody, that the manifest and chain share one signing key, and the trusted timestamp if present. Exit code 0 means verified. The verification format is `ed25519-sha256-v1`, kept deliberately plain so the check can be reproduced by hand.

## Using it from a module

Modules vendor this package into `app/evidence_export/` (with `verify_evidence.py` beside it), the same copy-per-module convention the platform uses for `evidence.py`, and wire a one-click route:

    from app import evidence
    from app.evidence_export import build_package

    data = build_package(
        records=client_event_records(db, client.id),   # [{fields, prev_hash, content_hash, signature}]
        subject={"id": client.id, "name": client.name},
        product="Vendetta <module>",
        document="<what the chain records>",
        signer=evidence.sign_bytes,                    # signs with the chain key
        public_key_hex=evidence.public_key_hex(),
        key_id=evidence.key_id(),
        scheme=evidence.SCHEME,
        tsa_url=settings.tsa_url,                       # optional
    )

`modules/professional-services` (Office of Special Projects) is the reference wiring, exposing the export at `/clients/{id}/evidence/export.zip` and, for clients, `/portal/evidence/export.zip`.

## Tests

`pytest -q` from the module directory. Needs only `cryptography`; no database.
