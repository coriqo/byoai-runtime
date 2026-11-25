# Operations Guide: Receipt Fetching

## Enabling Receipt Fetching Post-Deployment

After deploying byoai-runtime with the receipts feature, enable receipt fetching by setting the `BYOAI_RECORDER_RECEIPTS` environment variable to `1` on the host running the agent runtime. This is off by default because it requires Coriqo to be deployed and accessible. The Recorder initialization respects this flag and starts the background receipt fetcher only when explicitly enabled, so receipts remain opt-in for deployments that do not yet have checkpoint infrastructure.

## Monitoring for Receipt Unavailability

The receipt fetcher runs in a background daemon thread at a configurable interval (default: 60 seconds). If the Coriqo `/api/v1/receipts/<event_hash>` endpoint returns `403` or `404` three times in a row for the same trace, that trace is marked `receipts_unavailable` in the verification report. Monitor logs for warning messages matching "receipts route answered 403|404" — these indicate the route is either not deployed yet or the device is not authorized to fetch receipts. Verify that:

- Coriqo has been deployed with migration 0314 or later (which adds the receipts endpoint).
- The device's `agent:runtime` role has read permission on the receipts route.
- Network connectivity from the runtime host to Coriqo is intact.

## Testing Receipt Flow: Post-Trace to Fetch and Verify

Once enabled, test the end-to-end flow in three steps:

1. **Post a trace**: Run an agent under byoai-recorder with a tool call. The trace is published via `publish_session()` and a row is written to the receipt store (next to the ledger as `<ledger>.receipts.json`).

2. **Issue a checkpoint on Coriqo**: Open the agent in Coriqo's UI and cut a regulatory checkpoint, which seals a batch of events. The sealed batch includes any event hashes that have been acknowledged since the last checkpoint.

3. **Fetch and verify**: Once the event is old enough (default: 5 minutes) and the checkpoint is sealed, run `BYOAI_RECORDER_RECEIPTS=1 python -m byoai.recorder.cli <ledger.db> --receipts <ledger.db.receipts.json> --receipt-overdue-after 3600 --allow-unchecked-receipts`. The receipt fetcher background pass will contact Coriqo, retrieve the sealed bundle for the trace, and store it. Verify output should show the receipt as `ok` and `with_receipt` count > 0. A clean report means the trace hash is cryptographically proven by the sealed checkpoint.


# Operations Guide: Bedrock model-call log reader (W10)

`byoai-bedrock-log-reader` seals direct Amazon Bedrock model calls from the
account's model-invocation log. Install `byoai-runtime[bedrock-agent,recorder]`,
enrol a recorder directory for the reader with `byoai-recorder-enroll`, then:

```bash
export BYOAI_RECORDER_DIR=/var/lib/byoai/bedrock-reader BYOAI_BEDROCK_LOG_GROUP=<log group> AWS_REGION=<region>
byoai-bedrock-log-reader --check   # access, and whether logging and text delivery are on
byoai-bedrock-log-reader --loop    # run as a service; or --once from a scheduler
```

## The reader's role (in the account that owns the log group)

Required statements first; the optional ones make the status more useful.

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {"Sid": "ReadBedrockInvocationLog", "Effect": "Allow", "Action": ["logs:FilterLogEvents"],
     "Resource": "arn:aws:logs:REGION:ACCOUNT:log-group:LOG_GROUP:*"},
    {"Sid": "FindTheLogGroup", "Effect": "Allow", "Action": ["logs:DescribeLogGroups"],
     "Resource": "arn:aws:logs:REGION:ACCOUNT:log-group:*"},
    {"Sid": "OptionalCheckLoggingIsOn", "Effect": "Allow",
     "Action": ["bedrock:GetModelInvocationLoggingConfiguration"], "Resource": "*"},
    {"Sid": "OptionalReadLargeBodies", "Effect": "Allow", "Action": ["s3:GetObject"],
     "Resource": "arn:aws:s3:::BUCKET/PREFIX/*"},
    {"Sid": "OptionalDecryptLargeBodies", "Effect": "Allow", "Action": ["kms:Decrypt"],
     "Resource": "arn:aws:kms:REGION:ACCOUNT:key/KEY_ID",
     "Condition": {"StringEquals": {"kms:ViaService": "s3.REGION.amazonaws.com"}}}
  ]
}
```

Never granted: `logs:Unmask` (a CloudWatch data protection policy is your own
control; masked values are sealed as returned), any `logs:Put*`/`Delete*`, any
`bedrock:Put*`. The reader never writes to what it reads.

## What to set alongside

- Restrict write access on the log group to the Bedrock delivery role: anyone
  who can write to it can change a record before the reader seals it. Events
  carry `log_record_sha256`, so an edit after sealing is detectable.
- Keep the log group's retention at least the catch-up limit (Coriqo default
  168 hours), or an outage longer than retention loses records; the reader
  declares such a window as a gap.
- Configure the large-data S3 location: without it a body over 100 KB is
  absent from the log, and the status counts `body_missing_over_100kb`.

## Files and processes

- `<dir>/bedrock_log_state.db`: watermark, tool-call index for linking, gaps,
  settings cache. Not evidence; losing it re-reads from the first backfill,
  seals nothing twice, and the status says `state_recreated`.
- `<dir>/bedrock-log-reader.lock`: one reader per directory; a second exits
  with code 3 and says why.
- Exit codes: 0 ok or paused, 1 the sweep or check failed, 2 configuration
  missing, 3 another reader holds the directory.
