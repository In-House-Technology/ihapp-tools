# ihapp-tools

The public contract of the **In House Apps** catalog: JSON Schemas and a validator for

- an app origin (`ihapp-catalog.yaml` with `company-app.yaml`, license and tag/commit);
- the curated index (`catalog.yaml` in [In-House-Technology/catalog](https://github.com/In-House-Technology/catalog));
- the index signature (`catalog-<sha256>.sig`, ed25519) and the key list.

The InHouse cloud (ihc) applies the same rules when it installs or updates an app; this
repository is what publishers and the catalog CI use. MIT licensed.

Use this repository to validate source and catalog entries. For installing or updating an
app on managed InHouseCloud, start with the [customer catalog guide](https://inhouse.technology/cloud/docs/catalog).
For submitting source for curation, see the [publication guide](https://inhouse.technology/cloud/docs/publish-an-app).

## Command line

```bash
npm ci
node bin/ihapp-catalog.js validate <app-dir> [--tag vX.Y.Z --commit <40hex>] [--json]
node bin/ihapp-catalog.js validate-index <catalog.yaml> [--fetch] [--org <org>] [--signature <file> --keys <keys.json>] [--json]
```

Exit code 0 means no findings, 1 findings, 2 usage error. Findings carry stable
`IHC-CATALOG-*` codes.

## GitHub Action

```yaml
- uses: In-House-Technology/ihapp-tools@<commit sha>
  with:
    mode: app          # or index
    path: .
    tag: ${{ github.ref_name }}      # app mode, on tag pushes
    commit: ${{ github.sha }}
    org: In-House-Technology         # index mode
```

Pin the action by commit SHA.

## Signing key

`src/ihapp-catalog-keys.js` lists the public key that signs the curated index
(`inhouse-2026-11`). The private key lives only in the catalog repository's
`catalog-signing` environment.
