# Bedrock model-invocation log fixtures (SYNTHETIC)

These records are **synthetic**. They were written by hand from the AWS documentation of the
`ModelInvocationLog` record and the Converse / Anthropic Messages body shapes (W10 spec §2,
including the annotated example in §2.3); every value is invented. No real log record had been
captured when they were written.

W10 rollout step 0 captures real records in the discovery sandbox (Converse with a tool round
trip, ConverseStream with tools, an error, a body over 100 KB). When those exist, replace these
files with the real records, values redacted, and keep the file names so the tests still read
them. The shapes most likely to change then are the streamed output (`outputBodyJson` as a list
of stream events is an assumption) and the large-data S3 object encoding.

`error_without_body.jsonl` is a real record from the discovery sandbox (2026-11-17), with its
time moved into the tests' window and the account, caller and request id replaced: a call
Bedrock throttled is logged with no `input` and no `output` at all, only its `errorCode`.
