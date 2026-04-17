//! Generated gRPC types for the strait host control plane.
//!
//! Both the long-lived `strait-host` process and the in-container
//! `strait-agent` depend on this crate so they agree on the wire format.
//! The proto source lives in `strait_host.proto` next to `Cargo.toml` and
//! is compiled at build time by `tonic_build` via `build.rs`.
//!
//! Generated types live in `strait::host::v1` (server + client stubs,
//! message types, and enums). A convenience alias `strait_proto::v1`
//! re-exports the same module at the crate root for shorter call sites.

// The generated code uses `allow(clippy::all)` equivalents already; we wrap
// it in a narrow submodule so we can keep clippy strict on everything else.
pub mod host {
    pub mod v1 {
        #![allow(clippy::all)]
        #![allow(clippy::pedantic)]
        #![allow(missing_docs)]
        tonic::include_proto!("strait.host.v1");
    }
}

/// Convenience alias: `strait_proto::v1` resolves to the generated
/// `strait.host.v1` module.
pub use host::v1;

#[cfg(test)]
mod tests {
    use super::v1::*;

    /// Smoke test: every generated message type round-trips through
    /// `prost::Message::encode_to_vec` + `decode`. If a field number or type
    /// ever collides, `prost-build` would fail at compile; this test catches
    /// defaulting surprises (wrong default, non-round-trip-safe encoding).
    #[test]
    fn messages_round_trip_through_prost() {
        use prost::Message;

        fn rt<M: Message + Default + PartialEq + std::fmt::Debug + Clone>(msg: M) {
            let bytes = msg.encode_to_vec();
            let decoded = M::decode(bytes.as_slice()).expect("decode");
            assert_eq!(msg, decoded);
        }

        rt(RegisterContainerRequest {
            container_id: "abc".into(),
            container_name: "agent-1".into(),
            hostname: "container-1".into(),
            agent_version: "0.1.0".into(),
            labels: vec!["a".into(), "b".into()],
        });
        rt(RegisterContainerResponse {
            session_id: "sess-1".into(),
            default_scope: "default".into(),
            registered_at_unix_ms: 42,
            rules_resume_token: "v1".into(),
        });

        let mut headers = std::collections::HashMap::new();
        headers.insert("accept".to_string(), "application/json".to_string());
        rt(SubmitDecisionRequest {
            session_id: "sess-1".into(),
            request_id: "req-1".into(),
            method: "GET".into(),
            host: "api.github.com".into(),
            path: "/user".into(),
            headers: headers.clone(),
            observed_at_unix_ms: 1,
            explanation: "github api call".into(),
        });
        rt(SubmitDecisionResponse {
            request_id: "req-1".into(),
            verdict: Verdict::AllowOnce as i32,
            reason: "ok".into(),
            decided_at_unix_ms: 2,
            credential: Some(InjectedCredential {
                header_name: "Authorization".into(),
                header_value: "Bearer xyz".into(),
            }),
        });

        rt(FetchCredentialRequest {
            session_id: "sess-1".into(),
            host: "api.github.com".into(),
            action: "http:GET".into(),
            method: "GET".into(),
            path: "/user".into(),
            body_sha256: vec![0u8; 32],
            headers,
        });
        rt(FetchCredentialResponse {
            kind: Some(fetch_credential_response::Kind::Header(HeaderCredential {
                header_name: "Authorization".into(),
                header_value: "Bearer xyz".into(),
            })),
        });
        rt(FetchCredentialResponse {
            kind: Some(fetch_credential_response::Kind::Signed(SignedRequest {
                method: "GET".into(),
                url: "https://example.com/".into(),
                headers: Default::default(),
            })),
        });
        rt(FetchCredentialResponse {
            kind: Some(fetch_credential_response::Kind::None(NoCredential {})),
        });

        rt(StreamRulesRequest {
            session_id: "sess-1".into(),
            resume_token: "v1".into(),
        });
        rt(RuleEvent {
            kind: rule_event::Kind::Add as i32,
            rule_id: "rule-1".into(),
            scope: "default".into(),
            cedar_source: "permit(principal, action, resource);".into(),
            version_token: "v2".into(),
        });

        rt(ObservationEvent {
            session_id: "sess-1".into(),
            observation_id: "obs-1".into(),
            observed_at_unix_ms: 3,
            raw_json: "{}".into(),
        });
        rt(StreamObservationsAck {
            accepted: 10,
            rejected: 0,
        });

        rt(HeartbeatRequest {
            session_id: "sess-1".into(),
            sent_at_unix_ms: 4,
            labels: Default::default(),
        });
        rt(HeartbeatResponse {
            received_at_unix_ms: 5,
            server_time_unix_ms: 6,
        });
    }

    /// Confirm the enum zero-values are `UNSPECIFIED` (proto3 convention).
    #[test]
    fn enum_defaults_are_unspecified() {
        assert_eq!(Verdict::default(), Verdict::Unspecified);
        assert_eq!(rule_event::Kind::default(), rule_event::Kind::Unspecified);
    }
}
