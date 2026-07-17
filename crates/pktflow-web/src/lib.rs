//! `pktflow-web` — the web front-end.
//!
//! One self-contained axum server: a JSON API over the published
//! [`pktflow_flows::AggregatorSnapshot`]s, an SSE ticker for live
//! updates, and an embedded single-page UI (no build step, no CDN — the
//! whole front-end ships inside the binary). Rendering reads only hub
//! snapshots; the aggregation thread stays the single writer (D5).
//!
//! The hub is held behind [`WebState`] so a capture upload
//! (`POST /api/upload`) can swap in a fresh hub mid-serve: the embedder
//! supplies an [`UploadSpawner`] that starts a new pipeline over the
//! written file and returns its hub; every handler reads the current
//! hub per request, so the page follows the swap on its next tick.

pub mod api;

use std::convert::Infallible;
use std::io;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use std::collections::HashMap;

use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, Query as UrlQuery, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use pktflow_view::SnapshotHub;
use tokio_stream::{Stream, StreamExt};

const INDEX_HTML: &str = include_str!("assets/index.html");

/// SSE tick cadence — matches the pipeline's publish throttle closely
/// enough that a tick rarely reports a stale generation twice.
const TICK_INTERVAL: Duration = Duration::from_millis(500);

/// Default upload cap (12.6). Uploads stream to disk one chunk at a
/// time, so this bounds disk, not memory; `--max-upload-bytes`
/// overrides (0 = unlimited).
const DEFAULT_MAX_UPLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

/// Starts a pipeline over an uploaded capture: `(display_name, path)` in,
/// the new pipeline's hub out (or a message for the 500 response). The
/// embedder owns stopping the pipeline it replaces.
pub type UploadSpawner =
    Box<dyn Fn(String, PathBuf) -> Result<Arc<SnapshotHub>, String> + Send + Sync>;

/// Shared server state: the current hub (swapped on upload) and the
/// optional upload hook. Without a hook, `/api/upload` answers 403 and
/// the UI hides its upload affordances (`meta.uploads`).
pub struct WebState {
    hub: RwLock<Arc<SnapshotHub>>,
    on_upload: Option<UploadSpawner>,
    /// The previous upload's temp file, deleted when replaced.
    last_upload: Mutex<Option<PathBuf>>,
    upload_seq: AtomicU64,
    /// Distinguishes this state's temp files from any other `WebState`
    /// in the same process (each starts `upload_seq` at 0).
    upload_ns: u64,
    /// Upload size cap in bytes; 0 = unlimited (12.6).
    max_upload_bytes: u64,
}

/// Process-wide `WebState` counter feeding `upload_ns`.
static UPLOAD_NS: AtomicU64 = AtomicU64::new(0);

impl WebState {
    /// Read-only serving (tests, embedders without a pipeline spawner).
    pub fn new(hub: Arc<SnapshotHub>) -> Self {
        Self {
            hub: RwLock::new(hub),
            on_upload: None,
            last_upload: Mutex::new(None),
            upload_seq: AtomicU64::new(0),
            upload_ns: UPLOAD_NS.fetch_add(1, Ordering::Relaxed),
            max_upload_bytes: DEFAULT_MAX_UPLOAD_BYTES,
        }
    }

    /// Serving with uploads enabled.
    pub fn with_uploads(hub: Arc<SnapshotHub>, spawner: UploadSpawner) -> Self {
        Self {
            on_upload: Some(spawner),
            ..Self::new(hub)
        }
    }

    /// Overrides the upload size cap (12.6); 0 = unlimited.
    pub fn upload_cap(mut self, bytes: u64) -> Self {
        self.max_upload_bytes = bytes;
        self
    }

    /// The hub requests render from right now.
    pub fn hub(&self) -> Arc<SnapshotHub> {
        match self.hub.read() {
            Ok(slot) => Arc::clone(&slot),
            Err(poisoned) => Arc::clone(&poisoned.into_inner()),
        }
    }

    fn swap_hub(&self, hub: Arc<SnapshotHub>) {
        match self.hub.write() {
            Ok(mut slot) => *slot = hub,
            Err(poisoned) => *poisoned.into_inner() = hub,
        }
    }
}

/// The full route table; `Router<()>` ready to serve. Public so tests
/// (and embedders) can drive the API without a socket.
pub fn router(state: Arc<WebState>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/meta", get(meta))
        .route("/api/snapshot", get(snapshot))
        .route("/api/stream/{id}", get(stream_detail))
        .route("/api/search", get(search))
        .route("/api/events", get(events))
        .route(
            "/api/upload",
            // The handler streams the body to disk and enforces the
            // configured cap itself (bytes-written, cleanup on abort) —
            // a framework-level limit here would just duplicate it with
            // a worse failure mode (12.6).
            post(upload).layer(DefaultBodyLimit::disable()),
        )
        .with_state(state)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

/// `meta_json` plus the one server-config flag the page needs: whether
/// uploads are wired up (drives the drop-zone / open-capture button).
fn meta_with_uploads(state: &WebState) -> serde_json::Value {
    let mut doc = api::meta_json(&state.hub());
    doc["uploads"] = serde_json::json!(state.on_upload.is_some());
    doc
}

async fn meta(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    Json(meta_with_uploads(&state))
}

async fn snapshot(State(state): State<Arc<WebState>>) -> Json<serde_json::Value> {
    let mut doc = api::snapshot_json(&state.hub());
    doc["meta"]["uploads"] = serde_json::json!(state.on_upload.is_some());
    Json(doc)
}

async fn stream_detail(State(state): State<Arc<WebState>>, Path(id): Path<u64>) -> Response {
    match api::stream_json(&state.hub(), id) {
        Some(doc) => Json(doc).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("no stream #{id}")})),
        )
            .into_response(),
    }
}

async fn search(
    State(state): State<Arc<WebState>>,
    UrlQuery(params): UrlQuery<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let q = params.get("q").map(String::as_str).unwrap_or("");
    Json(api::search_json(&state.hub(), q))
}

async fn events(
    State(state): State<Arc<WebState>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    // Re-read the hub every tick so an upload swap reaches open pages.
    let ticks = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(TICK_INTERVAL))
        .map(move |_| {
            let payload = api::tick_json(&state.hub()).to_string();
            Ok(Event::default().event("tick").data(payload))
        });
    Sse::new(ticks).keep_alive(KeepAlive::default())
}

/// The capture-file magics we accept: classic pcap in both byte orders,
/// both timestamp resolutions, and the pcapng section header — the same
/// formats the offline reader replays.
fn capture_extension(bytes: &[u8]) -> Option<&'static str> {
    match bytes.first_chunk::<4>()? {
        [0xa1, 0xb2, 0xc3, 0xd4] | [0xd4, 0xc3, 0xb2, 0xa1] => Some("pcap"),
        [0xa1, 0xb2, 0x3c, 0x4d] | [0x4d, 0x3c, 0xb2, 0xa1] => Some("pcap"),
        [0x0a, 0x0d, 0x0d, 0x0a] => Some("pcapng"),
        _ => None,
    }
}

/// A display name safe to show in the header: basename only, trimmed,
/// bounded, never empty.
fn sanitize_name(raw: &str) -> String {
    let base = raw.rsplit(['/', '\\']).next().unwrap_or("").trim();
    let clean: String = base.chars().filter(|c| !c.is_control()).take(120).collect();
    if clean.is_empty() {
        "uploaded capture".into()
    } else {
        clean
    }
}

fn upload_err(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({"error": msg}))).into_response()
}

/// Streams the rest of an upload body (plus the already-read `head`)
/// into `path`, one chunk in memory at a time (12.6), enforcing `cap`
/// bytes total (0 = unlimited). Any error means the caller must remove
/// the partial file.
async fn spill_upload(
    stream: &mut (impl Stream<Item = Result<Bytes, axum::Error>> + Unpin),
    head: &[u8],
    path: &PathBuf,
    cap: u64,
) -> Result<(), (StatusCode, &'static str)> {
    use tokio::io::AsyncWriteExt;
    const STORE_FAILED: (StatusCode, &str) =
        (StatusCode::INTERNAL_SERVER_ERROR, "could not store upload");
    let over_cap = (
        StatusCode::PAYLOAD_TOO_LARGE,
        "upload exceeds the configured size cap",
    );
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|_| STORE_FAILED)?;
    let mut written = 0u64;
    file.write_all(head).await.map_err(|_| STORE_FAILED)?;
    written += head.len() as u64;
    if cap > 0 && written > cap {
        return Err(over_cap);
    }
    while let Some(chunk) = stream.next().await {
        let chunk = chunk.map_err(|_| (StatusCode::BAD_REQUEST, "upload interrupted"))?;
        written += chunk.len() as u64;
        if cap > 0 && written > cap {
            return Err(over_cap);
        }
        file.write_all(&chunk).await.map_err(|_| STORE_FAILED)?;
    }
    file.flush().await.map_err(|_| STORE_FAILED)
}

/// `POST /api/upload?name=FILE` with the raw capture bytes as the body:
/// validate the magic on the first bytes, stream the rest to a temp
/// file in bounded memory (12.6), hand it to the embedder's spawner,
/// and swap the served hub to the new pipeline's.
async fn upload(
    State(state): State<Arc<WebState>>,
    UrlQuery(params): UrlQuery<HashMap<String, String>>,
    body: axum::body::Body,
) -> Response {
    let Some(spawner) = &state.on_upload else {
        return upload_err(StatusCode::FORBIDDEN, "uploads are not enabled");
    };
    let name = sanitize_name(params.get("name").map(String::as_str).unwrap_or(""));

    // Read just enough to validate the magic before anything durable.
    let mut stream = body.into_data_stream();
    let mut head: Vec<u8> = Vec::with_capacity(8);
    let ext = loop {
        match stream.next().await {
            Some(Ok(chunk)) => {
                head.extend_from_slice(&chunk);
                if head.len() >= 4 {
                    match capture_extension(&head) {
                        Some(ext) => break ext,
                        None => {
                            return upload_err(
                                StatusCode::BAD_REQUEST,
                                "not a capture file — expected pcap or pcapng",
                            )
                        }
                    }
                }
            }
            Some(Err(_)) => return upload_err(StatusCode::BAD_REQUEST, "upload interrupted"),
            None if head.is_empty() => return upload_err(StatusCode::BAD_REQUEST, "empty upload"),
            None => {
                return upload_err(
                    StatusCode::BAD_REQUEST,
                    "not a capture file — expected pcap or pcapng",
                )
            }
        }
    };

    let seq = state.upload_seq.fetch_add(1, Ordering::Relaxed);
    let path = std::env::temp_dir().join(format!(
        "pktflow-upload-{}-{}-{seq}.{ext}",
        std::process::id(),
        state.upload_ns,
    ));
    if let Err((status, msg)) =
        spill_upload(&mut stream, &head, &path, state.max_upload_bytes).await
    {
        // Over-cap, disconnect, or write failure: no partial file stays.
        drop(tokio::fs::remove_file(&path).await);
        return upload_err(status, msg);
    }

    match spawner(name.clone(), path.clone()) {
        Ok(hub) => {
            state.swap_hub(hub);
            let previous = state
                .last_upload
                .lock()
                .map(|mut slot| slot.replace(path))
                .unwrap_or(None);
            if let Some(old) = previous {
                drop(tokio::task::spawn_blocking(move || {
                    std::fs::remove_file(old)
                }));
            }
            Json(serde_json::json!({"ok": true, "source": name})).into_response()
        }
        Err(e) => {
            drop(tokio::task::spawn_blocking(move || {
                std::fs::remove_file(path)
            }));
            upload_err(StatusCode::INTERNAL_SERVER_ERROR, &e)
        }
    }
}

/// Binds `listen`, reports the bound address through `on_bound`, and
/// serves until `should_shutdown` turns true (polled 5×/s — the CLI's
/// Ctrl-C flag). Owns its tokio runtime so callers stay sync.
pub fn serve(
    listen: &str,
    state: Arc<WebState>,
    should_shutdown: impl Fn() -> bool + Send + Sync + 'static,
    on_bound: impl FnOnce(std::net::SocketAddr),
) -> io::Result<()> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()?;
    runtime.block_on(async move {
        let listener = tokio::net::TcpListener::bind(listen).await?;
        on_bound(listener.local_addr()?);
        axum::serve(listener, router(state))
            .with_graceful_shutdown(async move {
                loop {
                    if should_shutdown() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            })
            .await
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::{Duration, SystemTime};

    use http_body_util::BodyExt;
    use pktflow_core::{
        Canonicalize, DissectedPacket, Engine, FieldMap, KeyField, LayerPlugin, LayerRecord,
        LinkType, PacketMeta, ParseCtx, ParseError, ParsedLayer, ProtocolName, StopReason,
        StreamIdentity, Value,
    };
    use pktflow_flows::{Aggregator, AggregatorConfig};
    use pktflow_view::SnapshotHub;
    use tower::ServiceExt;

    use super::WebState;

    struct Keyed {
        name: ProtocolName,
    }

    impl LayerPlugin for Keyed {
        fn name(&self) -> ProtocolName {
            self.name
        }

        fn parse(&self, _bytes: &[u8], _ctx: &ParseCtx) -> Result<ParsedLayer, ParseError> {
            Err(ParseError::Malformed("ingest-only test plugin"))
        }

        fn stream_identity(&self) -> Option<&StreamIdentity> {
            static PAIR_KEY: &[KeyField] = &[KeyField {
                a: "src",
                b: Some("dst"),
            }];
            static IDENTITY: StreamIdentity = StreamIdentity {
                key: PAIR_KEY,
                canonicalize: Canonicalize::EndpointSort,
                lifecycle: None,
                rollups: &[],
            };
            Some(&IDENTITY)
        }
    }

    fn hub_with_streams() -> Arc<SnapshotHub> {
        let engine = Arc::new(
            Engine::builder()
                .plugin(Keyed { name: "eth" })
                .plugin(Keyed { name: "ip" })
                .build()
                .expect("valid registry"),
        );
        let mut agg = Aggregator::new(&engine, AggregatorConfig::default());
        let mut fields = FieldMap::new();
        fields.insert("src", Value::U64(1));
        fields.insert("dst", Value::U64(2));
        let mut ip_fields = FieldMap::new();
        ip_fields.insert("src", Value::U64(10));
        ip_fields.insert("dst", Value::U64(20));
        agg.ingest(&DissectedPacket {
            meta: PacketMeta {
                timestamp: SystemTime::UNIX_EPOCH + Duration::from_millis(3),
                caplen: 96,
                origlen: 96,
                link_type: LinkType::ETHERNET,
            },
            layers: vec![
                LayerRecord {
                    protocol: "eth",
                    offset: 0,
                    header_len: 14,
                    fields,
                },
                LayerRecord {
                    protocol: "ip",
                    offset: 14,
                    header_len: 20,
                    fields: ip_fields,
                },
            ],
            stop: StopReason::Complete,
            opaque_len: 0,
            unknown: None,
        });
        let hub = Arc::new(SnapshotHub::new("test.pcap".into(), "offline"));
        hub.publish(agg.snapshot());
        hub.mark_finished();
        hub
    }

    fn plain_router() -> axum::Router {
        super::router(Arc::new(WebState::new(hub_with_streams())))
    }

    async fn get_body(router: axum::Router, uri: &str) -> (u16, String) {
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .uri(uri)
                    .body(axum::body::Body::empty())
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    async fn post_body(router: axum::Router, uri: &str, body: Vec<u8>) -> (u16, String) {
        let response = router
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri(uri)
                    .body(axum::body::Body::from(body))
                    .expect("request"),
            )
            .await
            .expect("response");
        let status = response.status().as_u16();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body")
            .to_bytes();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn index_serves_the_embedded_ui() {
        let (status, body) = get_body(plain_router(), "/").await;
        assert_eq!(status, 200);
        assert!(body.contains("pktflow"), "embedded page names the app");
        assert!(body.contains("<script"), "SPA ships inline");
    }

    #[tokio::test]
    async fn snapshot_carries_the_stream_forest() {
        let (status, body) = get_body(plain_router(), "/api/snapshot").await;
        assert_eq!(status, 200);
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["pktflow"], 1);
        assert_eq!(doc["meta"]["source"], "test.pcap");
        assert_eq!(doc["meta"]["finished"], true);
        assert_eq!(doc["meta"]["uploads"], false);
        assert_eq!(doc["roots"], serde_json::json!([0]));
        let streams = doc["streams"].as_array().expect("streams array");
        assert_eq!(streams.len(), 2, "eth root + ip child");
        assert_eq!(streams[0]["protocol"], "eth");
        assert_eq!(streams[1]["parent"], 0);
        assert_eq!(doc["summary"]["packets"], 1);
    }

    #[tokio::test]
    async fn search_evaluates_queries_and_reports_errors() {
        let (status, body) = get_body(plain_router(), "/api/search?q=proto%20%3D%3D%20ip").await;
        assert_eq!(status, 200);
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["matches"], serde_json::json!([1]), "the ip child");
        assert_eq!(
            doc["visible"],
            serde_json::json!([0, 1]),
            "plus its eth ancestor"
        );
        assert_eq!(doc["error"], serde_json::Value::Null);

        // A broken expression reports instead of filtering.
        let (_, body) = get_body(plain_router(), "/api/search?q=bytes%20%3E").await;
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["matches"], serde_json::Value::Null);
        assert!(doc["error"].as_str().is_some_and(|e| e.contains("value")));
    }

    #[tokio::test]
    async fn stream_lookup_hits_and_misses() {
        let (status, body) = get_body(plain_router(), "/api/stream/1").await;
        assert_eq!(status, 200);
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["protocol"], "ip");

        let (status, _) = get_body(plain_router(), "/api/stream/99").await;
        assert_eq!(status, 404);
    }

    #[tokio::test]
    async fn upload_disabled_without_a_spawner() {
        let (status, body) = post_body(
            plain_router(),
            "/api/upload?name=x.pcap",
            vec![0xd4, 0xc3, 0xb2, 0xa1, 0, 0],
        )
        .await;
        assert_eq!(status, 403);
        assert!(body.contains("not enabled"));
    }

    #[tokio::test]
    async fn upload_swaps_the_served_hub() {
        let state = Arc::new(WebState::with_uploads(
            hub_with_streams(),
            Box::new(|name, path| {
                assert_eq!(name, "fresh.pcap", "basename survives");
                assert!(path.exists(), "capture spilled to disk before spawn");
                let hub = Arc::new(SnapshotHub::new(name, "offline"));
                hub.mark_finished();
                Ok(hub)
            }),
        ));
        // Classic little-endian pcap magic → accepted, hub swapped.
        let (status, body) = post_body(
            super::router(Arc::clone(&state)),
            "/api/upload?name=%2Ftmp%2Ffresh.pcap",
            vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0],
        )
        .await;
        assert_eq!(status, 200, "{body}");
        let (_, body) = get_body(super::router(Arc::clone(&state)), "/api/meta").await;
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["source"], "fresh.pcap");
        assert_eq!(doc["uploads"], true);

        // Garbage bytes are rejected before any pipeline is spawned.
        let (status, body) = post_body(
            super::router(Arc::clone(&state)),
            "/api/upload?name=junk.bin",
            b"not a capture at all".to_vec(),
        )
        .await;
        assert_eq!(status, 400);
        assert!(body.contains("pcap"));
        // The served hub is untouched by the reject.
        let (_, body) = get_body(super::router(state), "/api/meta").await;
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["source"], "fresh.pcap");
    }

    // 12.6: uploads stream to disk in bounded memory — a body far
    // larger than any buffered read still lands whole, chunk by chunk.
    #[tokio::test]
    async fn upload_streams_large_bodies_to_disk() {
        let expected_len = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let seen = std::sync::Arc::clone(&expected_len);
        let state = Arc::new(WebState::with_uploads(
            hub_with_streams(),
            Box::new(move |_, path| {
                let len = std::fs::metadata(&path).expect("spilled file").len();
                seen.store(len, std::sync::atomic::Ordering::SeqCst);
                let hub = Arc::new(SnapshotHub::new("big.pcap".into(), "offline"));
                hub.mark_finished();
                Ok(hub)
            }),
        ));
        // 64 MiB streamed in 64 KiB chunks — one chunk in memory at a time.
        let mut first = vec![0xd4, 0xc3, 0xb2, 0xa1];
        first.resize(64 * 1024, 0xCC);
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = (0..1024)
            .map(|i| {
                Ok(if i == 0 {
                    axum::body::Bytes::from(first.clone())
                } else {
                    axum::body::Bytes::from(vec![0xCC; 64 * 1024])
                })
            })
            .collect();
        let body = axum::body::Body::from_stream(tokio_stream::iter(chunks));
        let response = super::router(Arc::clone(&state))
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/upload?name=big.pcap")
                    .body(body)
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status().as_u16(), 200);
        assert_eq!(
            expected_len.load(std::sync::atomic::Ordering::SeqCst),
            64 * 1024 * 1024,
            "every chunk reached disk"
        );
    }

    // 12.6: exceeding the configured cap aborts with 413 and leaves no
    // partial file behind; under-cap succeeds.
    #[tokio::test]
    async fn upload_cap_is_enforced_without_partial_files() {
        let state = Arc::new(
            WebState::with_uploads(
                hub_with_streams(),
                Box::new(|name, _| {
                    let hub = Arc::new(SnapshotHub::new(name, "offline"));
                    hub.mark_finished();
                    Ok(hub)
                }),
            )
            .upload_cap(16),
        );
        let ns = state.upload_ns;
        let mut body = vec![0xd4, 0xc3, 0xb2, 0xa1];
        body.resize(64, 0);
        let (status, msg) = post_body(
            super::router(Arc::clone(&state)),
            "/api/upload?name=big",
            body,
        )
        .await;
        assert_eq!(status, 413, "{msg}");
        assert!(msg.contains("size cap"));
        assert_eq!(upload_tmp_count(ns), 0, "no partial file left behind");

        let (status, _) = post_body(
            super::router(state),
            "/api/upload?name=small",
            vec![0xd4, 0xc3, 0xb2, 0xa1, 2, 0, 4, 0],
        )
        .await;
        assert_eq!(status, 200, "under the cap still works");
    }

    // 12.6: a body that errors mid-stream (client disconnect) is a 400
    // and leaves no partial file.
    #[tokio::test]
    async fn upload_disconnect_leaves_no_partial_file() {
        let state = Arc::new(WebState::with_uploads(
            hub_with_streams(),
            Box::new(|_, _| unreachable!("spawner must not run for a broken upload")),
        ));
        let ns = state.upload_ns;
        let chunks: Vec<Result<axum::body::Bytes, std::io::Error>> = vec![
            Ok(axum::body::Bytes::from_static(&[0xd4, 0xc3, 0xb2, 0xa1])),
            Err(std::io::Error::other("client went away")),
        ];
        let response = super::router(state)
            .oneshot(
                axum::http::Request::builder()
                    .method("POST")
                    .uri("/api/upload?name=gone.pcap")
                    .body(axum::body::Body::from_stream(tokio_stream::iter(chunks)))
                    .expect("request"),
            )
            .await
            .expect("response");
        assert_eq!(response.status().as_u16(), 400);
        assert_eq!(upload_tmp_count(ns), 0, "no partial file left behind");
    }

    /// One state's upload temp files (the partial-file leak check) —
    /// namespaced so parallel tests can't race each other's counts.
    fn upload_tmp_count(ns: u64) -> usize {
        let prefix = format!("pktflow-upload-{}-{ns}-", std::process::id());
        std::fs::read_dir(std::env::temp_dir())
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.file_name().to_string_lossy().starts_with(&prefix))
                    .count()
            })
            .unwrap_or(0)
    }
}
