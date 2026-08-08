#![cfg(feature = "test-loopback")]

use std::time::Duration;

use nano_provider_xai::{
    FunctionTool, HistoryItem, MediaType, OutputItem, Provider, ProviderRequestMode, TurnRequest,
    XaiProvider, XaiProviderSettings, prepare_media_history_batch,
};
use serde_json::json;
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const TEST_KEY: &str = "loopback-only-secret";

fn request() -> TurnRequest {
    TurnRequest {
        turn_index: 0,
        model: "grok-4.5".to_owned(),
        history: vec![
            HistoryItem::System {
                content: "system".to_owned(),
            },
            HistoryItem::User {
                content: "user".to_owned(),
            },
        ],
        tools: vec![FunctionTool {
            name: "run_terminal_command".to_owned(),
            description: "Run a command.".to_owned(),
            parameters: json!({
                "additionalProperties": false,
                "properties": {
                    "command": {"type": "string"},
                    "description": {"type": "string"}
                },
                "required": ["command", "description"],
                "type": "object"
            }),
        }],
        mode: ProviderRequestMode::ActionOpen,
        media_history_receipt: None,
    }
}

fn six_image_request() -> TurnRequest {
    let mut base = vec![HistoryItem::User {
        content: "inspect six frames".to_owned(),
    }];
    let mut outputs = Vec::new();
    let mut attachments = Vec::new();
    let mut call_ids = Vec::new();
    for index in 0..6_u64 {
        let call_id = format!("call-{index}");
        let logical_path = format!("frame-{index}.png");
        let mut bytes = b"\x89PNG\r\n\x1a\n".to_vec();
        bytes.extend_from_slice(&index.to_be_bytes());
        let digest = format!("{:x}", Sha256::digest(&bytes));
        base.push(HistoryItem::FunctionCall {
            call_id: call_id.clone(),
            name: "read_file".to_owned(),
            arguments_json: format!(r#"{{"target_file":"{logical_path}"}}"#),
        });
        outputs.push(HistoryItem::FunctionCallOutput {
            call_id: call_id.clone(),
            output: format!(
                "read_file returned an attached image: image/png, 2x1, sha256={digest}"
            ),
        });
        attachments.push(
            HistoryItem::tool_media_attachment_with_origin(
                call_id.clone(),
                logical_path,
                MediaType::Png,
                2,
                1,
                digest,
                bytes,
                0,
                "read_file",
            )
            .expect("attachment"),
        );
        call_ids.push(call_id);
    }
    outputs.extend(attachments);
    let (history, receipt) = prepare_media_history_batch(&base, 0, &call_ids, outputs)
        .expect("six-image candidate")
        .into_parts();
    TurnRequest {
        turn_index: 1,
        model: "grok-4.5".to_owned(),
        history,
        tools: Vec::new(),
        mode: ProviderRequestMode::ActionOpen,
        media_history_receipt: Some(receipt),
    }
}

fn settings() -> XaiProviderSettings {
    XaiProviderSettings {
        model: "grok-4.5".to_owned(),
        reasoning_effort: "high".to_owned(),
        include: vec!["reasoning.encrypted_content".to_owned()],
        parallel_tool_calls: true,
        tool_choice: "auto".to_owned(),
        service_tier: "default".to_owned(),
        max_output_tokens: 256,
        max_request_body_bytes: 1_048_576,
        max_function_arguments_bytes: 1_048_576,
        max_sse_events: 1_024,
        max_sse_event_bytes: 1_048_576,
        max_sse_response_bytes: 4_194_304,
        max_json_depth: 64,
        connect_timeout: Duration::from_secs(2),
        first_event_timeout: Duration::from_secs(2),
        inter_event_timeout: Duration::from_secs(2),
        total_timeout: Duration::from_secs(5),
    }
}

struct CapturedRequest {
    body: Vec<u8>,
    authorization: String,
}

async fn read_captured_request(stream: &mut TcpStream) -> CapturedRequest {
    let mut received = Vec::new();
    let mut header_end = None;
    let mut content_length = None;
    loop {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk).await.expect("read request");
        assert_ne!(count, 0, "request ended before body");
        received.extend_from_slice(&chunk[..count]);
        if header_end.is_none()
            && let Some(position) = received.windows(4).position(|part| part == b"\r\n\r\n")
        {
            let end = position + 4;
            header_end = Some(end);
            let headers = String::from_utf8(received[..position].to_vec()).expect("headers");
            content_length = headers.lines().find_map(|line| {
                let (name, value) = line.split_once(':')?;
                name.eq_ignore_ascii_case("content-length")
                    .then(|| value.trim().parse::<usize>().expect("content length"))
            });
        }
        if let (Some(end), Some(length)) = (header_end, content_length)
            && received.len() >= end + length
        {
            break;
        }
    }
    let end = header_end.expect("header end");
    let headers = String::from_utf8(received[..end - 4].to_vec()).expect("headers");
    let authorization = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("authorization")
                .then(|| value.trim().to_owned())
        })
        .expect("authorization header");
    CapturedRequest {
        body: received[end..end + content_length.expect("body length")].to_vec(),
        authorization,
    }
}

async fn one_shot_server(
    status: &str,
    content_type: &str,
    body_fragments: Vec<Vec<u8>>,
) -> (String, tokio::task::JoinHandle<CapturedRequest>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let status = status.to_owned();
    let content_type = content_type.to_owned();
    let handle = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept request");
        let captured = read_captured_request(&mut stream).await;
        let response_length = body_fragments.iter().map(Vec::len).sum::<usize>();
        stream
            .write_all(
                format!(
                    "HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {response_length}\r\nConnection: close\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .expect("write response headers");
        for fragment in body_fragments {
            stream.write_all(&fragment).await.expect("write fragment");
            stream.flush().await.expect("flush fragment");
            tokio::task::yield_now().await;
        }
        captured
    });
    (format!("http://{address}/v1/responses"), handle)
}

async fn transport_replay_server(
    fail_in_response_stream: bool,
) -> (String, tokio::task::JoinHandle<Vec<CapturedRequest>>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind loopback");
    let address = listener.local_addr().expect("loopback address");
    let handle = tokio::spawn(async move {
        let mut captured = Vec::new();
        let (mut first, _) = listener.accept().await.expect("accept first request");
        captured.push(read_captured_request(&mut first).await);
        if fail_in_response_stream {
            let partial = b"data: {\"type\":\"response.created\",\"sequence_number\":0}\r\n\r\n";
            first
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                        partial.len() + 4096
                    )
                    .as_bytes(),
                )
                .await
                .expect("write partial headers");
            first.write_all(partial).await.expect("write partial body");
        }
        drop(first);

        let (mut second, _) = listener.accept().await.expect("accept replay");
        captured.push(read_captured_request(&mut second).await);
        let response = completed_sse();
        second
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    response.len()
                )
                .as_bytes(),
            )
            .await
            .expect("write replay headers");
        second
            .write_all(&response)
            .await
            .expect("write replay response");
        captured
    });
    (format!("http://{address}/v1/responses"), handle)
}

fn completed_sse() -> Vec<u8> {
    concat!(
        "data: {\"type\":\"response.created\",\"sequence_number\":0,\"response\":{\"id\":\"resp-1\",\"status\":\"in_progress\"}}\r\n\r\n",
        "data: {\"type\":\"response.completed\",\"sequence_number\":1,\"response\":{\"id\":\"resp-1\",\"object\":\"response\",\"model\":\"grok-4.5\",\"status\":\"completed\",\"output\":[{\"type\":\"reasoning\",\"id\":\"reason-1\",\"summary\":[],\"encrypted_content\":\"opaque\"},{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"done\"}]}],\"service_tier\":\"default\",\"system_fingerprint\":\"fp-test\",\"usage\":null}}\r\n\r\n",
        "data: [DONE]\r\n\r\n"
    )
    .as_bytes()
    .to_vec()
}

#[tokio::test]
async fn exact_request_bytes_and_fragmented_crlf_completed_response() {
    let bytes = completed_sse();
    let fragments = bytes.into_iter().map(|byte| vec![byte]).collect();
    let (endpoint, captured) =
        one_shot_server("200 OK", "text/event-stream; charset=utf-8", fragments).await;
    let mut provider = XaiProvider::for_loopback_test(&endpoint, TEST_KEY.to_owned(), settings())
        .expect("loopback provider");
    let prepared = provider.preflight(request()).expect("preflight");
    let completed = provider.send(prepared).await.expect("completed response");
    assert_eq!(completed.response_id, "resp-1");
    assert_eq!(completed.usage, None);
    assert_eq!(completed.service_tier.as_deref(), Some("default"));
    assert_eq!(completed.system_fingerprint.as_deref(), Some("fp-test"));
    assert!(matches!(
        completed.output.as_slice(),
        [
            OutputItem::Reasoning {
                encrypted_content: Some(encrypted),
                ..
            },
            OutputItem::AssistantMessage { text }
        ] if encrypted == "opaque" && text == "done"
    ));

    let captured = captured.await.expect("captured request");
    assert_eq!(captured.authorization, format!("Bearer {TEST_KEY}"));
    let expected = concat!(
        "{\"model\":\"grok-4.5\",\"input\":[",
        "{\"role\":\"system\",\"content\":\"system\"},",
        "{\"role\":\"user\",\"content\":\"user\"}],",
        "\"tools\":[{\"type\":\"function\",\"name\":\"run_terminal_command\",\"description\":\"Run a command.\",\"parameters\":{\"additionalProperties\":false,\"properties\":{\"command\":{\"type\":\"string\"},\"description\":{\"type\":\"string\"}},\"required\":[\"command\",\"description\"],\"type\":\"object\"}}],",
        "\"tool_choice\":\"auto\",\"parallel_tool_calls\":true,",
        "\"reasoning\":{\"effort\":\"high\"},",
        "\"include\":[\"reasoning.encrypted_content\"],",
        "\"store\":false,\"stream\":true,\"max_output_tokens\":256,",
        "\"service_tier\":\"default\",\"truncation\":\"disabled\"}"
    );
    assert_eq!(captured.body, expected.as_bytes());
    assert!(
        !format!("{provider:?}").contains(TEST_KEY),
        "provider Debug leaked authorization"
    );
}

#[tokio::test]
async fn continuation_preserves_reasoning_call_id_and_function_output() {
    let body = concat!(
        "data: {\"type\":\"response.completed\",\"sequence_number\":0,\"response\":{\"id\":\"resp-2\",\"object\":\"response\",\"model\":\"grok-4.5\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"ok\"}]}],\"usage\":{\"input_tokens\":1}}}\n\n",
        "data: [DONE]\n\n"
    );
    let (endpoint, captured) = one_shot_server(
        "200 OK",
        "text/event-stream",
        vec![body.as_bytes().to_vec()],
    )
    .await;
    let mut provider = XaiProvider::for_loopback_test(&endpoint, TEST_KEY.to_owned(), settings())
        .expect("loopback provider");
    let mut continuation = request();
    continuation.turn_index = 1;
    continuation.history.extend([
        HistoryItem::Reasoning {
            id: Some("reason-1".to_owned()),
            summary: json!([]),
            encrypted_content: Some("ciphertext".to_owned()),
            content: None,
        },
        HistoryItem::FunctionCall {
            call_id: "call-1".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{\"command\":\"pwd\",\"description\":\"inspect\"}".to_owned(),
        },
        HistoryItem::FunctionCallOutput {
            call_id: "call-1".to_owned(),
            output: "/workspace\n".to_owned(),
        },
    ]);
    let prepared = provider.preflight(continuation).expect("preflight");
    provider
        .send(prepared)
        .await
        .expect("continuation response");
    let captured = captured.await.expect("captured continuation");
    let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("request JSON");
    assert_eq!(body["store"], false);
    assert_eq!(body["truncation"], "disabled");
    assert_eq!(body["input"][2]["id"], "reason-1");
    assert_eq!(body["input"][2]["encrypted_content"], "ciphertext");
    assert_eq!(body["input"][3]["call_id"], "call-1");
    assert_eq!(body["input"][4]["call_id"], "call-1");
    assert_eq!(body["input"][4]["output"], "/workspace\n");
}

#[tokio::test]
async fn final_only_http_request_keeps_function_schema_and_disables_new_calls() {
    let body = completed_sse();
    let (endpoint, captured) = one_shot_server("200 OK", "text/event-stream", vec![body]).await;
    let mut provider = XaiProvider::for_loopback_test(&endpoint, TEST_KEY.to_owned(), settings())
        .expect("loopback provider");
    let mut final_only = request();
    final_only.turn_index = 1;
    final_only.mode = ProviderRequestMode::FinalOnly;
    final_only.history.extend([
        HistoryItem::FunctionCall {
            call_id: "call-1".to_owned(),
            name: "run_terminal_command".to_owned(),
            arguments_json: "{\"command\":\"pwd\",\"description\":\"inspect\"}".to_owned(),
        },
        HistoryItem::FunctionCallOutput {
            call_id: "call-1".to_owned(),
            output: "/workspace\n".to_owned(),
        },
    ]);

    let prepared = provider.preflight(final_only).expect("final preflight");
    provider.send(prepared).await.expect("final response");

    let captured = captured.await.expect("captured final request");
    let body: serde_json::Value = serde_json::from_slice(&captured.body).expect("request JSON");
    assert_eq!(body["tool_choice"], "none");
    assert_eq!(body["tools"][0]["name"], "run_terminal_command");
    assert_eq!(body["input"][2]["type"], "function_call");
    assert_eq!(body["input"][3]["type"], "function_call_output");
}

#[tokio::test]
async fn six_image_same_turn_sends_newest_four_and_all_six_outputs() {
    let body = completed_sse();
    let (endpoint, captured) = one_shot_server("200 OK", "text/event-stream", vec![body]).await;
    let mut provider = XaiProvider::for_loopback_test(&endpoint, TEST_KEY.to_owned(), settings())
        .expect("loopback provider");
    let prepared = provider
        .preflight(six_image_request())
        .expect("six-image preflight");
    provider.send(prepared).await.expect("completed response");

    let captured = captured.await.expect("captured request");
    let text = String::from_utf8(captured.body).expect("request UTF-8");
    assert_eq!(text.matches("\"type\":\"function_call_output\"").count(), 6);
    assert_eq!(text.matches("\"type\":\"input_image\"").count(), 4);
    assert_eq!(text.matches("media_history_eviction").count(), 2);
    for index in 0..6 {
        assert!(text.contains(&format!("\"call_id\":\"call-{index}\"")));
    }
    for index in 0..2 {
        assert!(!text.contains(&format!(
            "Runtime attachment for read_file call_id=call-{index};"
        )));
    }
    for index in 2..6 {
        assert!(text.contains(&format!(
            "Runtime attachment for read_file call_id=call-{index};"
        )));
    }
}

#[tokio::test]
async fn request_and_stream_transport_failures_replay_exact_body_once() {
    for (fail_in_response_stream, expected_stage) in [(false, "request"), (true, "response_stream")]
    {
        let (endpoint, captured) = transport_replay_server(fail_in_response_stream).await;
        let mut provider =
            XaiProvider::for_loopback_test(&endpoint, TEST_KEY.to_owned(), settings())
                .expect("loopback provider");
        let prepared = provider.preflight(request()).expect("preflight");
        let completed = provider.send(prepared).await.expect("replay succeeds");
        assert_eq!(completed.response_id, "resp-1");
        let telemetry = provider.send_telemetry();
        assert_eq!(telemetry.attempt_count, 2);
        assert!(
            matches!(
                telemetry.retry_code.as_deref(),
                Some("provider_connect_failed" | "provider_transport_failed")
            ),
            "unexpected transport classification: {:?}",
            telemetry.retry_code
        );
        assert_eq!(telemetry.retry_stage.as_deref(), Some(expected_stage));

        let captured = captured.await.expect("captured attempts");
        assert_eq!(captured.len(), 2);
        assert_eq!(captured[0].body, captured[1].body);
        assert_eq!(
            captured[0].authorization, captured[1].authorization,
            "authorization must be reconstructed identically"
        );
    }
}

#[tokio::test]
async fn protocol_and_http_failures_never_retry() {
    let cases = [
        (
            "200 OK",
            "text/event-stream",
            b"data: {\"type\":\"response.future\"}\n\n".to_vec(),
            "provider_protocol_unknown",
        ),
        (
            "200 OK",
            "text/event-stream",
            b"data: [DONE]\n\n".to_vec(),
            "provider_done_before_completed",
        ),
        (
            "200 OK",
            "text/event-stream",
            b"data: {\"type\":\"response.created\",\"sequence_number\":0}\n\n".to_vec(),
            "provider_stream_incomplete",
        ),
        (
            "429 Too Many Requests",
            "application/json",
            format!("{{\"error\":{{\"message\":\"limited {TEST_KEY}\"}}}}").into_bytes(),
            "provider_http_429",
        ),
        (
            "503 Service Unavailable",
            "application/json",
            b"{\"error\":{\"message\":\"down\"}}".to_vec(),
            "provider_http_5xx",
        ),
        (
            "302 Found",
            "text/html",
            b"redirect refused".to_vec(),
            "provider_http_3xx",
        ),
        (
            "200 OK",
            "application/json",
            b"{\"not\":\"sse\"}".to_vec(),
            "provider_content_type_invalid",
        ),
        (
            "200 OK",
            "text/event-stream",
            b"data: {\"type\":\"response.completed\",\"sequence_number\":0,\"response\":{\"id\":\"resp\",\"object\":\"response\",\"model\":\"grok-drift\",\"status\":\"completed\",\"output\":[{\"type\":\"message\",\"role\":\"assistant\",\"content\":[{\"type\":\"output_text\",\"text\":\"x\"}]}]}}\n\n".to_vec(),
            "provider_model_drift",
        ),
        (
            "200 OK",
            "text/event-stream",
            b"data: {\"type\":\"response.web_search_call.in_progress\",\"sequence_number\":0}\n\n"
                .to_vec(),
            "unsupported_server_tool",
        ),
    ];
    for (status, content_type, body, expected) in cases {
        let (endpoint, captured) = one_shot_server(status, content_type, vec![body]).await;
        let mut provider =
            XaiProvider::for_loopback_test(&endpoint, TEST_KEY.to_owned(), settings())
                .expect("loopback provider");
        let prepared = provider.preflight(request()).expect("preflight");
        let error = provider.send(prepared).await.expect_err("must fail closed");
        assert_eq!(error.code(), expected);
        captured.await.expect("single captured request");
        assert!(!error.to_string().contains(TEST_KEY));
    }
}
