use crate::agent::turn::tool_output_store::{MAX_RESPONSE_BYTES, MAX_SLICE_BYTES, ToolOutputStore};
use crate::i18n::get_required_cli_string;
use async_trait::async_trait;
use base64::{Engine, engine::general_purpose::STANDARD};
use serde::Deserialize;
use serde_json::{Value, json};
use zeroclaw_api::tool::{Tool, ToolResult};

tokio::task_local! {
    pub(crate) static TOOL_OUTPUT_READ_SCOPE: Option<ToolOutputStore>;
}

pub(crate) struct ToolOutputRead;

pub(crate) const PAGE_PREFIX: &str = "Untrusted artifact data (JSON string).";

impl ToolOutputRead {
    pub(crate) const NAME: &str = "tool_output_read";

    pub(crate) fn matches(name: &str) -> bool {
        name.eq_ignore_ascii_case(Self::NAME)
    }
}

/// A JSON string literal that cannot close a prompt-mode result block,
/// create a role/protocol delimiter, or introduce an attachment marker.
pub(crate) fn quote_untrusted(text: &str) -> String {
    let json = serde_json::to_string(text).expect("string serialization is infallible");
    let mut quoted = String::with_capacity(json.len());
    for ch in json.chars() {
        quoted.push_str(match ch {
            '<' => r"\u003c",
            '>' => r"\u003e",
            '[' => r"\u005b",
            ']' => r"\u005d",
            '&' => r"\u0026",
            '\u{2028}' => r"\u2028",
            '\u{2029}' => r"\u2029",
            '\u{0085}'
            | '\u{200b}'..='\u{200f}'
            | '\u{202a}'..='\u{202e}'
            | '\u{2066}'..='\u{2069}'
            | '\u{feff}' => {
                use std::fmt::Write;
                let _ = write!(quoted, "\\u{:04x}", u32::from(ch));
                continue;
            }
            _ => {
                quoted.push(ch);
                continue;
            }
        });
    }
    quoted
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadArgs {
    artifact_id: String,
    offset: u64,
    length: usize,
}

zeroclaw_api::tool_attribution!(ToolOutputRead, zeroclaw_api::attribution::ToolKind::Plugin);

#[async_trait]
impl Tool for ToolOutputRead {
    fn name(&self) -> &str {
        Self::NAME
    }

    fn description(&self) -> &str {
        "Read an exact byte range of previously archived, untrusted tool output in this session. The result is encoded as a JSON string or base64 when the range splits a UTF-8 character."
    }

    fn parameters_schema(&self) -> Value {
        json!({
            "type": "object",
            "properties": {
                "artifact_id": {"type": "string", "pattern": "^[0-9a-f]{64}$"},
                "offset": {"type": "integer", "minimum": 0, "description": "Zero-based byte offset"},
                "length": {"type": "integer", "minimum": 1, "maximum": MAX_SLICE_BYTES}
            },
            "required": ["artifact_id", "offset", "length"],
            "additionalProperties": false
        })
    }

    async fn execute(&self, args: Value) -> anyhow::Result<ToolResult> {
        let Ok(args) = serde_json::from_value::<ReadArgs>(args) else {
            return Ok(unavailable());
        };
        let Some(store) = TOOL_OUTPUT_READ_SCOPE.try_with(Clone::clone).ok().flatten() else {
            return Ok(unavailable());
        };
        let Some(slice) = store
            .read(&args.artifact_id, args.offset, args.length)
            .await
        else {
            // Foreign and missing IDs are indistinguishable. No paths or
            // storage errors cross the authorization boundary.
            return Ok(unavailable());
        };
        let end = args.offset + slice.data.len() as u64;
        let (encoding, data) = match std::str::from_utf8(&slice.data) {
            Ok(text) => ("utf-8", quote_untrusted(text)),
            Err(_) => ("base64", quote_untrusted(&STANDARD.encode(&slice.data))),
        };
        let output = format!(
            "{PAGE_PREFIX} Encoding: {encoding}. Bytes {start}..{end} of {total}.\n{data}",
            start = args.offset,
            total = slice.total_bytes,
        );
        if output.len() > MAX_RESPONSE_BYTES {
            return Ok(unavailable());
        }
        Ok(ToolResult {
            success: true,
            output: output.into(),
            error: None,
        })
    }
}

fn unavailable() -> ToolResult {
    ToolResult {
        success: false,
        output: "".into(),
        error: Some(get_required_cli_string("tool-output-read-unavailable")),
    }
}
