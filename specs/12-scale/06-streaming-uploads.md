# 12.6 — Streaming uploads

> Task: [12 Large-capture scale](README.md) · Depends on: 12.4 (progress plumbing) ·
> PRD: §5 use cases · D17

## Goal
A multi-gigabyte capture can be dropped onto the web UI: the upload streams to disk in
bounded memory instead of buffering the whole body, with the size cap raised to match.

## Specification

- `POST /api/upload` consumes the request body as a stream (`axum` body data stream →
  `tokio::fs::File` writes), holding at most one chunk in memory. The pcap/pcapng magic
  check runs on the first chunk; a non-capture body is rejected before anything meaningful
  hits disk.
- The cap becomes disk-oriented: default 8 GiB, configurable via
  `pktflow serve --max-upload-bytes N` (0 = unlimited). Exceeding it aborts the write and
  removes the partial file. `DefaultBodyLimit` is raised to match the configured cap.
- Temp-file hygiene as today (per-process names, previous upload deleted on replace,
  partial file deleted on any error path) plus deletion on client disconnect mid-stream.
- Upload progress is client-side: the SPA switches the upload to `XMLHttpRequest` (fetch
  exposes no upload progress) and shows percent-sent; once the spawner takes over, the
  12.5 *read* progress covers the rest of the wait, so the user sees a continuous
  sent → reading → done sequence.
- Unchanged: spawner contract, hub swap semantics, 403 when uploads are disabled.

## Acceptance criteria

- [ ] Uploading a body larger than available RAM headroom succeeds with server memory
      growth bounded by chunk size (integration test with a synthetic multi-GB sparse
      body, gated `#[ignore]` for CI tiers without the disk).
- [ ] First-chunk magic rejection leaves no file behind; mid-stream disconnects and
      over-cap uploads leave no partial file behind.
- [ ] `--max-upload-bytes` is honored end-to-end (413 over the cap, success under it);
      default is 8 GiB.
- [ ] The SPA shows upload percent during send and hands off to read progress after; the
      existing small-upload tests still pass unchanged.
