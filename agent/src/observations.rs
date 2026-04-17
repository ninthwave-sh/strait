//! Agent-side observation sink for the host control plane (M-HCP-5).
//!
//! The in-container proxy emits `strait::observe::ObservationEvent`
//! values at every request boundary; this module ships them upstream to
//! `strait-host` via the client-streaming `StreamObservations` RPC.
//!
//! The sink is decoupled from the proxy via the [`ObservationSink`]
//! trait so tests and callers without a live host can swap in a no-op
//! or an in-memory recorder. The production entry point is
//! [`HostStreamingSink::spawn`], which takes a configured host client
//! and runs a background task that forwards every event placed onto its
//! queue.

use std::sync::Arc;

use strait::observe::ObservationEvent;
use strait_proto::v1::ObservationEvent as WireObservation;
use tokio::sync::mpsc;
use tracing::warn;
use uuid::Uuid;

/// Sink abstraction used by the proxy when it wants to report an event.
///
/// Implementations must be cheap to `emit` from the hot path: the default
/// production impl drops the event on a bounded channel and returns
/// immediately. Tests can use [`NoopSink`] to disable emission entirely,
/// or record into a `Vec` inside a mutex.
pub trait ObservationSink: Send + Sync {
    /// Accept an event from the proxy. Implementations should not block
    /// the caller longer than a single atomic operation; if the transport
    /// is backed up, the implementation is responsible for logging and
    /// dropping rather than blocking the proxy's request pipeline.
    fn emit(&self, event: ObservationEvent);
}

/// No-op sink. Useful as a default in tests and when the agent runs
/// without a host socket configured.
#[derive(Debug, Default, Clone, Copy)]
pub struct NoopSink;

impl ObservationSink for NoopSink {
    fn emit(&self, _event: ObservationEvent) {}
}

/// Handle to a spawned background task that forwards observations to the
/// host. The task terminates automatically when every sink clone is
/// dropped (the bounded channel closes and the streaming RPC completes).
#[derive(Debug, Clone)]
pub struct HostStreamingSink {
    tx: mpsc::Sender<ObservationEvent>,
    session_id: Arc<String>,
    container_registration_id: Arc<String>,
}

impl HostStreamingSink {
    /// Spawn the uploader task and return a sink the proxy can hand out.
    ///
    /// `queue_capacity` bounds how many events can be buffered in-memory
    /// before new emissions are dropped with a warning. Values around
    /// 256 match the fan-out capacity the host broadcast uses.
    pub fn spawn<F, Fut>(
        session_id: String,
        container_registration_id: String,
        queue_capacity: usize,
        run_stream: F,
    ) -> Self
    where
        F: FnOnce(tokio::sync::mpsc::Receiver<WireObservation>) -> Fut + Send + 'static,
        Fut: std::future::Future<Output = anyhow::Result<()>> + Send + 'static,
    {
        let (tx, mut rx) = mpsc::channel::<ObservationEvent>(queue_capacity.max(1));
        let session_id = Arc::new(session_id);
        let container_registration_id = Arc::new(container_registration_id);

        let session_for_task = session_id.clone();
        let reg_for_task = container_registration_id.clone();
        let (wire_tx, wire_rx) = mpsc::channel::<WireObservation>(queue_capacity.max(1));

        // Translate domain events into wire events on a dedicated task so
        // `run_stream` only has to consume a wire-typed receiver. Both
        // ends close naturally when the sink is dropped.
        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                match to_wire(&session_for_task, &reg_for_task, &event) {
                    Ok(wire) => {
                        if wire_tx.send(wire).await.is_err() {
                            break;
                        }
                    }
                    Err(e) => {
                        warn!(
                            target: "strait_agent::observations",
                            error = %e,
                            "failed to serialize observation; dropping event"
                        );
                    }
                }
            }
        });

        tokio::spawn(async move {
            if let Err(e) = run_stream(wire_rx).await {
                warn!(
                    target: "strait_agent::observations",
                    error = %e,
                    "observation stream terminated with error"
                );
            }
        });

        Self {
            tx,
            session_id,
            container_registration_id,
        }
    }

    /// Session id the sink tags every outbound event with.
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    /// Container registration id the sink tags every outbound event with.
    pub fn container_registration_id(&self) -> &str {
        &self.container_registration_id
    }
}

impl ObservationSink for HostStreamingSink {
    fn emit(&self, event: ObservationEvent) {
        match self.tx.try_send(event) {
            Ok(()) => {}
            Err(tokio::sync::mpsc::error::TrySendError::Full(_)) => {
                warn!(
                    target: "strait_agent::observations",
                    session_id = %self.session_id,
                    "observation queue full; dropping event"
                );
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(_)) => {
                // Background task exited; nothing to do except move on.
            }
        }
    }
}

/// Serialize an `ObservationEvent` into its wire form with host-tagged
/// metadata. Extracted so the spawned task and unit tests share logic.
fn to_wire(
    session_id: &str,
    container_registration_id: &str,
    event: &ObservationEvent,
) -> anyhow::Result<WireObservation> {
    let raw_json = serde_json::to_string(event)?;
    Ok(WireObservation {
        session_id: session_id.to_string(),
        container_registration_id: container_registration_id.to_string(),
        observation_id: Uuid::new_v4().to_string(),
        observed_at_unix_ms: unix_ms_now(),
        raw_json,
    })
}

fn unix_ms_now() -> i64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use strait::observe::EventKind;

    fn sample_event() -> ObservationEvent {
        ObservationEvent {
            version: 4,
            timestamp: "2026-04-17T00:00:00.000Z".into(),
            session: None,
            event: EventKind::ContainerStart {
                container_id: "abc".into(),
                image: "alpine".into(),
            },
        }
    }

    #[test]
    fn to_wire_round_trips_payload() {
        let event = sample_event();
        let wire = to_wire("sess-1", "reg-A", &event).unwrap();
        assert_eq!(wire.session_id, "sess-1");
        assert_eq!(wire.container_registration_id, "reg-A");
        assert!(!wire.observation_id.is_empty());
        assert!(wire.observed_at_unix_ms > 0);
        let decoded: ObservationEvent = serde_json::from_str(&wire.raw_json).unwrap();
        assert_eq!(decoded, event);
    }

    #[tokio::test]
    async fn host_streaming_sink_forwards_events_to_run_stream() {
        use std::sync::Mutex;

        let collected: Arc<Mutex<Vec<WireObservation>>> = Arc::new(Mutex::new(Vec::new()));
        let collected_for_stream = collected.clone();

        let sink = HostStreamingSink::spawn(
            "sess-live".into(),
            "reg-live".into(),
            8,
            move |mut wire_rx| async move {
                while let Some(wire) = wire_rx.recv().await {
                    collected_for_stream.lock().unwrap().push(wire);
                }
                Ok(())
            },
        );

        // Emit two events and drop the sink to close the channel.
        sink.emit(sample_event());
        sink.emit(sample_event());
        drop(sink);

        // Give the forwarder time to drain; wait up to 1s.
        for _ in 0..100 {
            if collected.lock().unwrap().len() >= 2 {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
        let out = collected.lock().unwrap().clone();
        assert_eq!(out.len(), 2, "expected two wire events, got {}", out.len());
        for wire in out {
            assert_eq!(wire.session_id, "sess-live");
            assert_eq!(wire.container_registration_id, "reg-live");
            let decoded: ObservationEvent = serde_json::from_str(&wire.raw_json).unwrap();
            assert_eq!(decoded.version, 4);
        }
    }

    #[test]
    fn noop_sink_is_noop() {
        let sink = NoopSink;
        sink.emit(sample_event());
    }
}
