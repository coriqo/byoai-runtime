# Shield signature file format and loader contract

A signature file tells Shield what to look for: which hosts are AI apps, which
endpoints are model APIs, which files configure MCP servers, which local
programs run models. This page fixes the file format and the rules every loader
must follow. It is the interface for the base list (public, in this repo) and
for a signed bundle (private, published by Coriqo).

- Schema: [`src/byoai/shield_signatures.schema.json`](https://github.com/coriqo/byoai-runtime/blob/main/src/byoai/shield_signatures.schema.json) (JSON Schema 2020-12)
- Sample: `tests/fixtures/shield_signatures/sample.json` (base) and `sample_bundle.json` (bundle shape)
- Negative fixtures: `tests/fixtures/shield_signatures/invalid/`
- Test: `tests/integrations/test_shield_signatures_schema.py`

This page specifies a format. A loader and matcher for model endpoints exist in `src/byoai/shield_signatures.py` (base list `src/byoai/shield_catalog_models.json`; OpenAI, Anthropic, Gemini). The model name is read only from a payload field that is present (`model`, or `modelVersion` in a Gemini response), never from the URL. Within a path pattern `*` matches characters inside one segment, so `*:generateContent` works. Other loader duties below are still open. The
sample is illustrative, not a catalog. Signature evidence feeds the
[event envelope](shield-event-envelope.md) through `detection`
(`rule_id`, `rule_version`, `confidence`).

## File

| Field | Notes |
|---|---|
| `schema_version` | `1`. A loader that does not know the value rejects the file. |
| `format` | `"coriqo.shield.signatures"` |
| `kind` | `base` (public list in the repo) or `bundle` (extra signatures, private, signed) |
| `file_version` | Integer, monotonic per publisher and kind |
| `generated_at` | UTC timestamp `YYYY-MM-DDTHH:MM:SSZ` |
| `expires_at` | UTC timestamp. Required for a bundle, optional for a base list |
| `publisher` | Free text name |
| `signatures` | The entries |
| `signature` | The detached-signature slot. Required for a bundle, absent in a base list |

### Signature slot

```json
"signature": {"alg": "ed25519", "key_id": "coriqo-sig-2026", "sig": "ed25519:<base64>"}
```

- **Signed bytes** are `C(document without "signature")`, where `C` is the canonical encoding of [`seal-format.md` section 3](seal-format.md#3-canonical-encoding) (RFC 8785, `canonical.canonicalize`). This is the same rule as a checkpoint (`C(checkpoint without "sig")`).
- **Encoding** is `"ed25519:" + base64(sig)` as in [`seal-format.md` section 6.2](seal-format.md#62-signature-encoding). No new byte format is introduced.
- **Which key** is chosen by `key_id` from public keys **pinned in the shipped package**. A key inside the bundle, or one fetched at run time, is never trusted. A package may pin several keys so one can be rotated out.
- The slot is "detached" in the sense that it is not part of the signed bytes; a publisher may also ship the same object as a sidecar `<file>.sig`, and a loader treats the two the same.

## Entry

| Field | Notes |
|---|---|
| `id` | Unique. Lowercase letters, digits, `.`, `_`, `-`. Convention `<type-prefix>.<vendor>.<thing>`. Unique within a file and across base plus bundle. |
| `type` | `app_domain`, `model_endpoint`, `agent_protocol`, `mcp_config_path`, `local_runtime`, `local_app` |
| `match` | Match conditions (below). At least one, and the ones the type requires. |
| `vendor`, `technology` | Names for display and reports. |
| `confidence` | `confirmed`, `probable`, `possible`. The **most** a match may report, and only when every `evidence_required` item was observed. If fewer are observed the loader reports `possible` at most. |
| `evidence_required` | Non-empty list from `host_match`, `path_match`, `header_present`, `body_field_present`, `process_running`, `bundle_installed`, `config_file_present`, `config_entry_present`, `port_listening`. |
| `false_positive_notes` | Required, non-empty. What looks like this but is not. |
| `source` | `name`, optional `url` (https), and `licence` (SPDX id or `LicenseRef-*`). |
| `first_seen`, `last_verified` | UTC timestamps, `YYYY-MM-DDTHH:MM:SS[.ffffff]Z` only (no offset). `first_seen <= last_verified <= expires_at` is a contract rule (the schema cannot compare fields); a loader rejects the entry, or the file for a base list, that breaks it. |
| `version` | Integer, at least 1, bumped when the entry changes. |
| `expires_at` | UTC timestamp. Required. An entry nobody re-verified stops matching. At most **400 days** after `last_verified` (a loader rejects a longer one, so no entry lives for ever). |

### Match conditions

Names and patterns only. A signature never holds a header value, a body value, a
credential or a message.

| Key | Content | Rules |
|---|---|---|
| `hosts` | Host patterns | Lowercase. Exact (`api.openai.com`) or a single leftmost wildcard label (`*.openai.azure.com`). No regex. A wildcard sits **above a registrable domain**: `*.co.uk` or `*.github.io` (a public suffix) must never appear, and the review of every change checks each wildcard parent against the public suffix list. The schema cannot do that. It also does not stop punycode (`xn--`) lookalike labels, so review reads each `xn--` host decoded. |
| `paths` | Path patterns | Start with `/`. `*` matches one or more characters inside one segment, at most **4** per pattern (a loader rejects more). Matching is linear in the pattern and path length. A path containing `..` never matches. Query strings are not matched. |
| `header_names` | Header **names** | Lowercase. Presence only. |
| `body_fields` | JSON field **names** | Presence only; the value is never read into a row (a model name may be read only under the envelope's model rules). |
| `process_names` | Process names | |
| `bundle_ids` | macOS bundle or Windows package ids | |
| `ports` | Local TCP ports | |
| `config_paths` | `{darwin, linux, windows}` lists | A base (`~`, `%VAR%` or `$VAR`), then 1 to 12 segments of `/` plus letters, digits, space and `._@+-`. Forward slashes only: no backslash, no empty segment, no control character, no `..`. No absolute paths. The loader also resolves the path (see loader rule 12). |

Required match keys by type:

| Type | Needs |
|---|---|
| `app_domain` | `hosts` |
| `model_endpoint` | `hosts` and `paths` |
| `agent_protocol` | one of `paths`, `header_names`, `body_fields` |
| `mcp_config_path` | `config_paths` |
| `local_runtime` | `process_names` or `ports` |
| `local_app` | `bundle_ids` or `process_names` |

## Loader contract

A loader reads one base list and zero or one bundle. It must follow these rules.
The schema checks structure; everything below is the loader's job and Wave 1's
tests must cover each line.

1. **Validate first.** Parse and validate the whole file against the schema before using any entry. Parse integers without loss (see `seal-format.md` section 3).
2. **Unknown field: reject the file.** The schema is closed (`additionalProperties: false`) at file, entry, match and source level. A new field needs a new `schema_version`; a loader never skips an unknown field and keeps the rest.
   - Bundle: discard the bundle, keep the base list.
   - Base list: refuse it and report a collector-health fact (`ai.collector.health`). Do not guess.
3. **Location decides the kind, not the file.** The base list loads only from its packaged path. Any file at the bundle location is a bundle whatever its `kind` field says, and must carry a valid signature: a bundle with `signature` removed and `kind` edited to `base` is a bad-signature bundle and is discarded whole. The schema also refuses a `base` file that carries a `signature`, but only this rule stops the downgrade.
   - **Bad signature: fail closed on the bundle.** A bundle with a missing slot, an unknown `key_id`, a malformed or wrong signature, or a failed verification is discarded **whole**. No entry of it is used. Verification is offline against pinned keys. The base list stays in force and the loader reports the failure as health, not as a silent fallback.
4. **Expired file.** A bundle past its `expires_at` is treated as invalid and discarded whole. An expired base list is still used, since it ships with the package, but each of its entries is still held to rule 5, and the loader reports that the list is stale.
5. **Expired entry: skip that entry only.** An entry past its `expires_at` never matches. It is reported as a coverage gap, never as "not AI". The check runs at **match time** as well as at load, so a long-running process stops matching an entry the moment it expires. Timestamps are parsed strictly (a real calendar date and time, `Z` only); a malformed one, `first_seen > last_verified`, `last_verified > expires_at` or a lifetime over 400 days rejects the file.
6. **Rollback.** A bundle whose `file_version` is lower than the highest one this loader has accepted is discarded. The loader keeps that number in its own state.
7. **Merging.** Duplicate `id` inside one file rejects the file. Across base and bundle, the entry with the higher `version` wins, **but** a bundle entry may only add coverage: for the same `id`, each `match` list must contain every value of the base entry's, its `evidence_required` must not be a smaller set, and its `confidence` must not be higher. Otherwise the bundle entry is ignored and the loader reports it as health. A bundle can add entries, never remove or weaken a base entry's match (a dead match such as `hosts: ["x.invalid"]` therefore cannot override). Retiring a base entry is a reviewed change to the base list.
8. **No regex.** Patterns are the literal forms above. A loader must not compile a signature field as a regular expression.
9. **Read only.** Loading and matching never write to a signature file.
10. **Never auto-promote.** A domain or process seen in traffic that matches no signature (the existing `health.unmatched` canary, a `desktop.meta` `not_covered` row, a scanner sighting) is **never** added to any signature list automatically, by the loader, the proxy, the extension or Coriqo. It is reported as an unmatched sighting (`unattested` or `unobservable_payload`) and enters a list only through a reviewed change to the base list or a newly signed bundle.
11. **Evidence honesty.** A match from a signature sets `evidence_level` per the envelope rules. A host-only match of a model API is at most `inferred` for the provider and says nothing about the model; a model name is never produced from a signature.

12. **Config paths stay inside their base.** Expand `~`, `%VAR%` or `$VAR`, resolve the result (symlinks included), and reject the path if it leaves the expanded base directory. An unset variable rejects the entry. The schema's pattern is a first filter; this is the check.

## Base app catalog

`src/byoai/shield_catalog_apps.json` is the public base list of AI application
hosts (1,150 entries at `file_version` 2: the model-API seeds, a ranked shadow-AI
list, and two directories of AI tools). It is built by
`scripts/import_shield_catalog.py`, which normalises each URL to a registrable
host, dedupes across lists, and rejects shared infrastructure (`github.io`,
`vercel.app`, `amazonaws.com`), generic platforms (`google.com`, `microsoft.com`)
and parent domains of a seed host, unless the host is an exact AI subdomain such
as `gemini.google.com`. A host is matched exactly, so a listed domain covers that
host only (`www.` and `api.` are separate hosts, not duplicates).
A host may carry a port (`api.openai.com:443`); a port outside 1 to 65535 never matches.

The schema is closed, so each entry's category and trust facts sit in a sidecar,
`src/byoai/shield_catalog_apps_meta.json`, keyed by entry `id`. The sidecar records
`catalog_sha256`, the hash of the catalog file it was built for. `load_app_catalog()`
rejects the whole catalog if the hash differs, if an id is missing or extra, if a
value is outside the enums below, if `tier` disagrees with `origin`, or if a
`candidate` or `ai-enabled` entry reports above `possible`. So a tier cannot be
dropped or altered without the loader noticing.

Model-API endpoints live in `shield_catalog_models.json`; the app catalog repeats none
of them (no id or host appears in both files), so an override by `id` has one target.
Hugging Face (`huggingface.co`) is `ai-enabled` at `possible`: the whole site is
a code and dataset host, not only a model service.

Sidecar fields:

| Field | Values |
|---|---|
| `category` | `chatbot`, `meeting_transcription`, `image_video`, `writing`, `coding`, `sales_marketing`, `data_analytics`, `model_hub`, `hr_recruiting`, `productivity_agents`, `design`, `search` |
| `nature` | `ai-native`, or `ai-enabled` (general SaaS with AI features, such as Figma, Databricks, Grammarly). Directory-only entries are all `ai-enabled`: the source does not say which are AI-first. |
| `tier` | `listed` (the ranked shadow-AI list and the seeds) or `candidate` (directory-only). Never `approved`: nothing in the base list is trusted automatically. |
| `origin` | `seed`, `shadow-ai`, `tio`, `autotune` |

- `ai-enabled` entries and every `candidate` report at most `possible`; only a
  `listed`, `ai-native` entry may report `probable`.
- `source.url` is the vendor's own site, never a review site. `source.name` and
  `source.licence` say where the host really came from: `via tio directory`,
  `via autotune directory` or `via shadow-ai list`, licence
  `LicenseRef-Third-Party-List`; every `candidate` also says `(unverified)`. Seed
  entries keep the vendor licence. Nobody at Coriqo has verified a list-derived
  entry against the vendor: `last_verified` is the list's own date where it gives one,
  else the import date, and is not a claim of review. `tier` (and `AppEntry.verified`)
  is the trust signal.
  `expires_at` is 365 days (`listed`) or 180 days (`candidate`) after it.
- **Overrides.** An admin approves, changes or disables one entry through the
  policy layer, which refers to it by `id`. Ids are unique and the base file is
  read only (loader rule 9), so no override edits it. A bundle cannot do this
  (loader rule 7: a bundle only adds coverage), which is deliberate. The policy
  layer itself (signed Shield policy per-app toggles, Coriqo for organisations)
  is separate work.
- Refresh with `python -I scripts/import_shield_catalog.py --help`. The raw
  lists are inputs only and are not committed.

## Public and private sides

| Piece | Side |
|---|---|
| Format, schema, loader, base list | Public (this repo) |
| Signed bundle of extra signatures | Private (Coriqo). The public scanner verifies it offline and falls back to the base list when it cannot. |

No private data enters the public repo. A bundle's entries use the same format,
so a customer can read what a bundle contains once it is verified.
