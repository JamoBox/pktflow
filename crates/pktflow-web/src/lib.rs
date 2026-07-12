//! `pktflow-web` — the web front-end.
//!
//! One self-contained axum server: a JSON API over the published
//! [`pktflow_flows::AggregatorSnapshot`]s, an SSE ticker for live
//! updates, and an embedded single-page UI (no build step, no CDN — the
//! whole front-end ships inside the binary). Rendering reads only hub
//! snapshots; the aggregation thread stays the single writer (D5).

pub mod api;

use std::convert::Infallible;
use std::io;
use std::sync::Arc;
use std::time::Duration;

use std::collections::HashMap;

use axum::extract::{Path, Query as UrlQuery, State};
use axum::http::StatusCode;
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{Html, IntoResponse, Response};
use axum::routing::get;
use axum::{Json, Router};
use pktflow_view::SnapshotHub;
use tokio_stream::{Stream, StreamExt};

const INDEX_HTML: &str = include_str!("assets/index.html");

/// SSE tick cadence — matches the pipeline's publish throttle closely
/// enough that a tick rarely reports a stale generation twice.
const TICK_INTERVAL: Duration = Duration::from_millis(500);

/// The full route table; `Router<()>` ready to serve. Public so tests
/// (and embedders) can drive the API without a socket.
pub fn router(hub: Arc<SnapshotHub>) -> Router {
    Router::new()
        .route("/", get(index))
        .route("/api/meta", get(meta))
        .route("/api/snapshot", get(snapshot))
        .route("/api/stream/{id}", get(stream_detail))
        .route("/api/search", get(search))
        .route("/api/events", get(events))
        .with_state(hub)
}

async fn index() -> Html<&'static str> {
    Html(INDEX_HTML)
}

async fn meta(State(hub): State<Arc<SnapshotHub>>) -> Json<serde_json::Value> {
    Json(api::meta_json(&hub))
}

async fn snapshot(State(hub): State<Arc<SnapshotHub>>) -> Json<serde_json::Value> {
    Json(api::snapshot_json(&hub))
}

async fn stream_detail(State(hub): State<Arc<SnapshotHub>>, Path(id): Path<u64>) -> Response {
    match api::stream_json(&hub, id) {
        Some(doc) => Json(doc).into_response(),
        None => (
            StatusCode::NOT_FOUND,
            Json(serde_json::json!({"error": format!("no stream #{id}")})),
        )
            .into_response(),
    }
}

async fn search(
    State(hub): State<Arc<SnapshotHub>>,
    UrlQuery(params): UrlQuery<HashMap<String, String>>,
) -> Json<serde_json::Value> {
    let q = params.get("q").map(String::as_str).unwrap_or("");
    Json(api::search_json(&hub, q))
}

async fn events(
    State(hub): State<Arc<SnapshotHub>>,
) -> Sse<impl Stream<Item = Result<Event, Infallible>>> {
    let ticks = tokio_stream::wrappers::IntervalStream::new(tokio::time::interval(TICK_INTERVAL))
        .map(move |_| {
            let payload = api::tick_json(&hub).to_string();
            Ok(Event::default().event("tick").data(payload))
        });
    Sse::new(ticks).keep_alive(KeepAlive::default())
}

/// Binds `listen`, reports the bound address through `on_bound`, and
/// serves until `should_shutdown` turns true (polled 5×/s — the CLI's
/// Ctrl-C flag). Owns its tokio runtime so callers stay sync.
pub fn serve(
    listen: &str,
    hub: Arc<SnapshotHub>,
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
        axum::serve(listener, router(hub))
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

    #[tokio::test]
    async fn index_serves_the_embedded_ui() {
        let (status, body) = get_body(super::router(hub_with_streams()), "/").await;
        assert_eq!(status, 200);
        assert!(body.contains("pktflow"), "embedded page names the app");
        assert!(body.contains("<script"), "SPA ships inline");
    }

    #[tokio::test]
    async fn snapshot_carries_the_stream_forest() {
        let (status, body) = get_body(super::router(hub_with_streams()), "/api/snapshot").await;
        assert_eq!(status, 200);
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["pktflow"], 1);
        assert_eq!(doc["meta"]["source"], "test.pcap");
        assert_eq!(doc["meta"]["finished"], true);
        assert_eq!(doc["roots"], serde_json::json!([0]));
        let streams = doc["streams"].as_array().expect("streams array");
        assert_eq!(streams.len(), 2, "eth root + ip child");
        assert_eq!(streams[0]["protocol"], "eth");
        assert_eq!(streams[1]["parent"], 0);
        assert_eq!(doc["summary"]["packets"], 1);
    }

    #[tokio::test]
    async fn search_evaluates_queries_and_reports_errors() {
        let hub = hub_with_streams();
        let (status, body) = get_body(
            super::router(Arc::clone(&hub)),
            "/api/search?q=proto%20%3D%3D%20ip",
        )
        .await;
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
        let (_, body) = get_body(super::router(hub), "/api/search?q=bytes%20%3E").await;
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["matches"], serde_json::Value::Null);
        assert!(doc["error"].as_str().is_some_and(|e| e.contains("value")));
    }

    #[tokio::test]
    async fn stream_lookup_hits_and_misses() {
        let hub = hub_with_streams();
        let (status, body) = get_body(super::router(Arc::clone(&hub)), "/api/stream/1").await;
        assert_eq!(status, 200);
        let doc: serde_json::Value = serde_json::from_str(&body).expect("json");
        assert_eq!(doc["protocol"], "ip");

        let (status, _) = get_body(super::router(hub), "/api/stream/99").await;
        assert_eq!(status, 404);
    }
}
