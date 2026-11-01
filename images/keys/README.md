# sfab/keys

The API key tool, `sfab-keys`, in an image the cluster pulls from the in-lab registry. It makes every API key inside the cluster and never prints one: each line it writes names a key by its fingerprint, `sha256:` and the first 12 hex digits of the key's sha256.

```
make -C images keys-fetch     # the pinned PyYAML wheel into VENDOR_DIR/keys/, checked against its sha256
make -C images keys           # sfab/keys:4
```

The image is `sfab/client` (pinned Alpine with Python 3.12) plus `sfab-keys` and PyYAML 6.0.3, unpacked from its pinned wheel (`keys.pyyaml` in `spec/versions.yaml`: CPython 3.12 on musl, with its sha256 from PyPI) with Python's own `zipfile`, so the build downloads nothing and runs no `pip`. Its user is 65532. `make -C images registry-seed` pushes it into the in-lab registry, where a pod names it `<mirror>/sfab/keys:4` (`192.0.2.6:5000/sfab/keys:4` in build A). This source builds `sfab/keys:4` (`images.keys_audience` in `spec/versions.yaml`), the tool of chapter 8 on; chapters 1 to 7 were recorded with `sfab/keys:3` (`images.keys`), which every call that names no audience runs the same as. On a host with no `sfab/keys:3` (a fresh clone), `make -C images keys` tags its `sfab/keys:4` build `sfab/keys:3` too, so chapters 1 to 7 run there; a host that has one keeps it untouched.

## What it does

| Command | What it does | Who runs it |
|---|---|---|
| `sfab-keys ensure --namespace NS --secret NAME --field FIELD --prefix PFX` | creates the Secret with `FIELD` set to `<PFX>-<32 hex>` (128 random bits) when it does not exist; an existing Secret is kept as it is, and one without the field is refused | the serving recipe's key Job (`serving-layer/`), for the servers' bearer key |
| `sfab-keys mint --namespace NS --secret NAME --prefix PFX --model SLUG [--id ID] [--if-none] [--for MODELS --audience NAME --audience-models MODELS]` | adds one key for a caller to the Secret as field `<SLUG>.<ID>`, `<PFX>-<SLUG>-<32 hex>`; the id is 8 hex digits. With `--if-none` it adds one only when the Secret holds no key for that caller yet, so a lab's first key per caller is made once. With `--audience` (`sfab/keys:4`) the caller is in that audience, which may call `--audience-models`, and `--for` names the models the key is for: a model outside the audience is refused with exit status 3 before the tool reaches the API, so the Secret is left as it was | the per-model keys behind the API gateway (the lab's keys Job mints the first with `--if-none`) |
| `sfab-keys copy --from-namespace NS --from-secret NAME --field FIELD --namespace NS2 --secret NAME2` | copies one field from one Secret to another: creates the second when it is missing, keeps it when it holds the same value and updates it when the value differs, printing which, with the fingerprint | the model router's backend key, copied from the serving recipe's Secret |
| `sfab-keys revoke --namespace NS --secret NAME --model SLUG --id ID` | removes that key from the Secret | the same |
| `sfab-keys list --namespace NS --secret NAME` | each key's field and fingerprint | anyone with read access |
| `sfab-keys compose --base FILE --keys DIR --out FILE [--format 'Bearer {key}'] [--hold FILE]` | the API gateway's sidecar: the base `apisix.yaml` with one consumer per key file in the mounted Secret (`m_<SLUG>_<ID>` in consumer group `<SLUG>`), ending in `#END`, rewritten in place and only when it changes; while the hold file exists the last file stays as it is | each API gateway pod, as a sidecar |
| `sfab-keys probe --namespace NS --selector SEL --port PORT --path PATH --key-file FILE [--expect STATUS] [--json BODY] [--jsonl] [--label L] [--repeat [--interval S] [--max-s S]]` | one request with the key to every Running pod the selector names, by pod address, and each pod's HTTP status: a GET, or with `--json` a POST of the body as `application/json` (the API gateway's model routes take only POST); `--jsonl` prints one JSON line a pod and answer (with a refusal's message) and a summary line; `--repeat` sends rounds until every pod of a round answers `--expect` or `--max-s` passes | chapter 7's per-pod key probe, a pod in the API gateway's namespace (`common/trace/keyprobe.py`), to see which gateway pods have loaded a key and when |

`ensure`, `mint`, `copy`, `revoke`, `list` and `probe` reach the Kubernetes API with the pod's own service account, so each needs a role that allows exactly what it touches: `get` on the one Secret and `create` on Secrets for `ensure`; `get` and `patch` on the one Secret and `create` on Secrets for `mint`; `get` on the source Secret in its namespace and `get`, `patch` and `create` on the copy for `copy`; and `list` on pods for `probe`. The API's certificate is checked against the service account's `ca.crt`, whose certificates count as trust anchors even when the bundle holds an intermediate CA alone, as the labs' cluster CA does (kubectl accepts such a bundle, and OpenSSL's default check refuses it with "unable to get issuer certificate"; `ch06/README.md`, platform notes).

The kubelet updates a mounted Secret in each pod on its own schedule, so each gateway pod's sidecar sees a new key at its own moment; `probe` shows which pods have it. `compose` writes the file in place, not by renaming a new one over it, because the gateway's container may hold the file as a single-file mount, which keeps the old file when the name is pointed elsewhere; the gateway reads the file only once it ends in `#END`.

## Tests

`images/keys/tests/test_keys.py` runs every command against a stand-in Kubernetes API and a stand-in gateway on the loopback (`make test` at the repo root).
