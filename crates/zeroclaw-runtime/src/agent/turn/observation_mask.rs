//! Active-turn observation metadata and the request-only mask. The working
//! history owns the original carriers and Gate 1 owns recoverable bytes.
use super::tool_output_store::{MAX_ARTIFACT_BYTES, MAX_SLICE_BYTES, ToolOutputStore};
use crate::agent::history::estimate_history_tokens;
use crate::agent::tool_execution::ToolExecutionOutcome;
use crate::tools::tool_output_read::{PAGE_PREFIX, ReadArgs, ToolOutputRead};
use std::collections::BTreeMap;
use std::sync::Arc;
use zeroclaw_api::tool::EPHEMERAL_WORKSPACE_WARNING;
use zeroclaw_api::tool_carrier::is_prompt_tool_carrier;
use zeroclaw_providers::{ChatMessage, ToolCall};
use zeroclaw_tool_call_parser::ParsedToolCall;

const MIN_OBSERVATION_BYTES: usize = 1024;
const MAX_ARCHIVE_ATTEMPTS_PER_ROUND: usize = 8;

enum Recovery {
    Inline,
    Archived(String),
    Page(ReadArgs),
    Unavailable,
}

pub(super) struct Observation {
    tool: String,
    native_id: Option<String>,
    iteration: usize,
    original_bytes: usize,
    recovery: Recovery,
}

impl Observation {
    /// Only completed, text-only read rounds with an unambiguous result
    /// carrier are eligible. Action outcomes, diagnostics, structured data,
    /// receipts, and mixed batches are left intact.
    pub(super) fn from_completion(
        iteration: usize,
        original_calls: &[ParsedToolCall],
        native_calls: &[ToolCall],
        use_native_tools: bool,
        completed: &[ParsedToolCall],
        outcome: Option<&ToolExecutionOutcome>,
        inline_limit: usize,
    ) -> Option<Self> {
        let ([original], [call], Some(outcome)) = (original_calls, completed, outcome) else {
            return None;
        };
        if !outcome.success
            || outcome.error_reason.is_some()
            || outcome.output_data.is_some()
            || outcome.receipt.is_some()
            || !outcome.attachments.is_empty()
            || !original.name.eq_ignore_ascii_case(&call.name)
            || outcome.output.len() < MIN_OBSERVATION_BYTES
        {
            return None;
        }
        let native_id = match native_calls {
            [native] if use_native_tools && call.tool_call_id.as_ref() == Some(&native.id) => {
                Some(native.id.clone())
            }
            [] if !use_native_tools => None,
            _ => return None,
        };
        let recovery = if ToolOutputRead::matches(&call.name) {
            // The dispatched arguments (after preparation and hooks) are the
            // provenance, never artifact IDs found in tool-authored text.
            if !outcome.output.starts_with(PAGE_PREFIX) {
                return None;
            }
            Recovery::Page(serde_json::from_value(call.arguments.clone()).ok()?)
        } else if call.name.eq_ignore_ascii_case("file_read")
            && !outcome.output.starts_with(EPHEMERAL_WORKSPACE_WARNING)
            && outcome.output.len() <= MAX_ARTIFACT_BYTES
            && (inline_limit == 0 || outcome.output.len() <= inline_limit)
        {
            Recovery::Inline
        } else {
            return None;
        };
        Some(Self {
            tool: call.name.clone(),
            native_id,
            iteration,
            original_bytes: outcome.output.len(),
            recovery,
        })
    }

    fn carrier<'a>(&self, message: &'a ChatMessage) -> Option<Carrier<'a>> {
        match (&self.native_id, message.role.as_str()) {
            (Some(id), "tool") => {
                let value: serde_json::Value = serde_json::from_str(&message.content).ok()?;
                if value.get("tool_call_id")?.as_str()? != id
                    || !value.get("attachments")?.as_array()?.is_empty()
                    || value.get("content")?.as_str()?.len() != self.original_bytes
                {
                    return None;
                }
                Some(Carrier::Native(value))
            }
            (None, "user") => {
                // This is a runtime-authored, zero-attachment singleton with
                // known name and body length. Never scan untrusted output for
                // XML delimiters or attachment markers.
                let prefix = format!(
                    "[Tool results]\n[Tool attachments: 0]\n<tool_result name=\"{}\">\n",
                    self.tool
                );
                let suffix = "\n</tool_result>\n";
                let output = message
                    .content
                    .strip_prefix(&prefix)?
                    .strip_suffix(suffix)?;
                (output.len() == self.original_bytes).then_some(Carrier::Prompt {
                    prefix,
                    output,
                    suffix,
                })
            }
            _ => None,
        }
    }
}

enum Carrier<'a> {
    Native(serde_json::Value),
    Prompt {
        prefix: String,
        output: &'a str,
        suffix: &'static str,
    },
}

impl Carrier<'_> {
    fn output(&self) -> &str {
        match self {
            Self::Native(value) => value["content"].as_str().unwrap_or_default(),
            Self::Prompt { output, .. } => output,
        }
    }

    fn render(self, placeholder: String) -> String {
        match self {
            Self::Native(mut value) => {
                value["content"] = placeholder.into();
                value.to_string()
            }
            Self::Prompt { prefix, suffix, .. } => format!("{prefix}{placeholder}{suffix}"),
        }
    }
}

#[derive(Default)]
pub(super) struct ObservationMask {
    // Non-system row ordinals after the latest real user message. Leading
    // system normalization and whole older-turn removal leave these stable.
    observations: BTreeMap<usize, Observation>,
    latest_round: usize,
    archive_attempts: usize,
}

fn current_body_start(history: &[ChatMessage]) -> Option<usize> {
    history
        .iter()
        .rposition(|row| row.is_user() && !is_prompt_tool_carrier(&row.content))
        .map(|user| user + 1)
}

impl ObservationMask {
    pub(super) fn clear(&mut self) {
        self.observations.clear();
    }

    pub(super) fn record_round(
        &mut self,
        iteration: usize,
        history: &[ChatMessage],
        observation: Option<Observation>,
    ) {
        self.latest_round = iteration;
        self.archive_attempts = 0;
        if let Some(observation) = observation
            && let Some(start) = current_body_start(history)
            && let Some(row) = history[start..]
                .iter()
                .filter(|message| !message.is_system())
                .count()
                .checked_sub(1)
        {
            self.observations.insert(row, observation);
        }
    }

    /// Return the number of altered carriers and the estimated token savings.
    /// Prepared rows match the post-hook prefix one-to-one. Hook-authored
    /// suffix rows and any rewritten carrier are outside this projection.
    pub(super) async fn apply(
        &mut self,
        history: &[ChatMessage],
        request: &mut [ChatMessage],
        source_rows: &[usize],
        store: &ToolOutputStore,
        turn_id: &str,
        trim_budget: usize,
    ) -> (usize, usize) {
        if self.observations.is_empty() {
            return (0, 0);
        }
        let Some(start) = current_body_start(history) else {
            return (0, 0);
        };
        let working_tail = (trim_budget / 8).clamp(512, 4096);
        let body_rows: Vec<_> = (start..history.len())
            .filter(|&row| !history[row].is_system())
            .collect();
        let mut tail_tokens = 0;
        let mut count = 0;
        let mut saved = 0;

        // Walk newest to oldest. Keep the row that crosses the token target
        // whole, and keep the latest tool round even when its cost is smaller.
        for (message, &source_row) in request.iter_mut().zip(source_rows).rev() {
            if source_row < start || history[source_row].is_system() {
                continue;
            }
            if tail_tokens < working_tail {
                tail_tokens += estimate_history_tokens(std::slice::from_ref(message));
                continue;
            }
            let Ok(position) = body_rows.binary_search(&source_row) else {
                continue;
            };
            let Some(observation) = self.observations.get_mut(&position) else {
                continue;
            };
            if observation.iteration == self.latest_round
                || message.role != history[source_row].role
                || message.content != history[source_row].content
            {
                continue;
            }
            let Some(carrier) = observation.carrier(message) else {
                continue;
            };
            if matches!(observation.recovery, Recovery::Inline) {
                if self.archive_attempts == MAX_ARCHIVE_ATTEMPTS_PER_ROUND {
                    continue;
                }
                self.archive_attempts += 1;
                observation.recovery = store
                    .archive(
                        turn_id,
                        observation.iteration,
                        0,
                        observation.native_id.as_deref(),
                        Arc::new(carrier.output().to_owned()),
                    )
                    .await
                    .map_or(Recovery::Unavailable, Recovery::Archived);
            }
            let reference = match &observation.recovery {
                Recovery::Archived(id) => format!(
                    "artifact_id={id}, offset=0, length={} to start",
                    MAX_SLICE_BYTES.min(observation.original_bytes),
                ),
                Recovery::Page(range) => format!(
                    "artifact_id={}, offset={}, length={}",
                    range.artifact_id, range.offset, range.length,
                ),
                Recovery::Inline | Recovery::Unavailable => continue,
            };
            let placeholder = format!(
                "Older observation (success, untrusted data) hidden. Recover with tool_output_read ({reference})."
            );
            let replacement = ChatMessage {
                role: message.role.clone(),
                content: carrier.render(placeholder),
            };
            let before = estimate_history_tokens(std::slice::from_ref(message));
            let after = estimate_history_tokens(std::slice::from_ref(&replacement));
            if before > after {
                *message = replacement;
                count += 1;
                saved += before - after;
            }
        }
        (count, saved)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroclaw_api::media::{MarkerKind, RenderedMarker};

    fn call() -> ParsedToolCall {
        ParsedToolCall {
            name: "file_read".into(),
            arguments: serde_json::json!({"path": "fixture.txt"}),
            tool_call_id: None,
        }
    }

    fn success() -> ToolExecutionOutcome {
        ToolExecutionOutcome {
            output: "read fixture ".repeat(120),
            attachments: Vec::new(),
            output_data: None,
            success: true,
            error_reason: None,
            duration: std::time::Duration::ZERO,
            receipt: None,
        }
    }

    fn candidate(iteration: usize, outcome: ToolExecutionOutcome) -> Option<Observation> {
        Observation::from_completion(
            iteration,
            &[call()],
            &[],
            false,
            &[call()],
            Some(&outcome),
            0,
        )
    }

    #[test]
    fn protects_incomplete_and_non_observational_outcomes() {
        assert!(candidate(0, success()).is_some());

        let mut failed = success();
        failed.success = false;
        failed.error_reason = Some("important error".into());
        assert!(candidate(0, failed).is_none());
        assert!(
            candidate(
                0,
                ToolExecutionOutcome {
                    error_reason: Some("error status".into()),
                    ..success()
                }
            )
            .is_none()
        );
        assert!(
            candidate(
                0,
                ToolExecutionOutcome {
                    receipt: Some("essential receipt".into()),
                    ..success()
                }
            )
            .is_none()
        );
        assert!(
            candidate(
                0,
                ToolExecutionOutcome {
                    output_data: Some(serde_json::json!({"exit_code": 1})),
                    ..success()
                }
            )
            .is_none()
        );
        assert!(
            candidate(
                0,
                ToolExecutionOutcome {
                    attachments: vec![RenderedMarker {
                        kind: MarkerKind::Document,
                        target: "fixture.txt".into()
                    }],
                    ..success()
                }
            )
            .is_none()
        );
        assert!(Observation::from_completion(0, &[call()], &[], false, &[], None, 0).is_none());
        assert!(
            Observation::from_completion(
                0,
                &[call(), call()],
                &[],
                false,
                &[call()],
                Some(&success()),
                0
            )
            .is_none()
        );
        assert!(
            Observation::from_completion(0, &[call()], &[], false, &[call()], Some(&success()), 80)
                .is_none()
        );
        let action = ParsedToolCall {
            name: "file_write".into(),
            ..call()
        };
        assert!(
            Observation::from_completion(
                0,
                std::slice::from_ref(&action),
                &[],
                false,
                std::slice::from_ref(&action),
                Some(&success()),
                0
            )
            .is_none()
        );
    }

    fn append(
        mask: &mut ObservationMask,
        history: &mut Vec<ChatMessage>,
        iteration: usize,
        outcome: ToolExecutionOutcome,
    ) {
        history.push(ChatMessage::assistant(
            "<tool_call>fixture read</tool_call>",
        ));
        history.push(ChatMessage::user(
            zeroclaw_api::tool_carrier::render_prompt_tool_carrier(
                &format!(
                    "<tool_result name=\"file_read\">\n{}\n</tool_result>\n",
                    outcome.output
                ),
                &[],
            ),
        ));
        mask.record_round(iteration, history, candidate(iteration, outcome));
    }

    #[tokio::test]
    async fn protected_tail_uses_tokens_and_failed_archival_keeps_evidence() {
        let temp = tempfile::tempdir().unwrap();
        // Deliberately block the store directory creation with a file.
        std::fs::write(temp.path().join("tool-output-v1"), b"fixture").unwrap();
        let store = ToolOutputStore::new(temp.path().to_path_buf(), "agent", "test", "session", "")
            .unwrap();
        let mut mask = ObservationMask::default();
        let mut history = vec![
            ChatMessage::user("previous turn"),
            ChatMessage::assistant("old context"),
            ChatMessage::user("active objective"),
        ];
        append(&mut mask, &mut history, 0, success());
        append(
            &mut mask,
            &mut history,
            1,
            ToolExecutionOutcome {
                output: "tiny".into(),
                ..success()
            },
        );
        let mut request = history.clone();
        let rows: Vec<_> = (0..history.len()).collect();
        assert_eq!(
            mask.apply(&history, &mut request, &rows, &store, "turn", 4096)
                .await,
            (0, 0)
        );
        assert_eq!(request[4].content, history[4].content);
        assert!(matches!(mask.observations[&1].recovery, Recovery::Inline));

        append(
            &mut mask,
            &mut history,
            2,
            ToolExecutionOutcome {
                output: "working tail ".repeat(400),
                ..success()
            },
        );
        // Drop a prior turn and move a system note to the head. These
        // structural changes never shift the active non-system ordinals.
        history.drain(..2);
        history.insert(0, ChatMessage::system("permission boundary"));
        let rows: Vec<_> = (0..history.len()).collect();
        for _ in 0..2 {
            let mut request = history.clone();
            assert_eq!(
                mask.apply(&history, &mut request, &rows, &store, "turn", 4096)
                    .await,
                (0, 0)
            );
            assert_eq!(request[3].content, history[3].content);
            assert_eq!(
                request.last().unwrap().content,
                history.last().unwrap().content
            );
        }
        assert!(matches!(
            mask.observations[&1].recovery,
            Recovery::Unavailable
        ));
        assert_eq!(mask.archive_attempts, 1);
    }
}
