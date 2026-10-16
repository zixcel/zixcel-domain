//! Bounded JSON-lines CLI; approval state lives only in this process.
use crate::{
    Result, error,
    record_editor::{Edit, Editor, Scope},
    transport::RecordWriteTransport,
};
use serde::Deserialize;
use serde_json::{Value, json};
mod backend;
use std::{
    io::{BufRead, Read, Write},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    protocol: u8,
    command: Command,
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
enum Command {
    Plan { edit: Edit },
    Apply { sha256: String },
    Status {},
    Stop {},
}

pub fn serve(
    scope: Scope,
    input: impl BufRead,
    output: impl Write,
    transport: &mut impl RecordWriteTransport,
) -> Result<()> {
    run(scope, input, output, |editor, command| {
        backend::execute(editor, command, transport)
    })
}

/// Live transports are recreated per operation; approval stays in the same Editor.
pub fn serve_live(scope: Scope, input: impl BufRead, output: impl Write) -> Result<()> {
    run(scope, input, output, backend::live)
}

fn run(
    scope: Scope,
    mut input: impl BufRead,
    mut output: impl Write,
    mut execute: impl FnMut(&mut Editor, Command) -> Result<Value>,
) -> Result<()> {
    let scope = scope.validate()?;
    let mut editor = Editor::new(scope.clone())?;
    let deadline = Instant::now() + Duration::from_secs(1200);
    for _ in 0..100 {
        let mut bytes = Vec::new();
        let count = (&mut input)
            .take(8193)
            .read_until(b'\n', &mut bytes)
            .map_err(|_| error("record_session_input_failed"))?;
        if count == 0 {
            return Ok(());
        }
        if bytes.len() > 8192 {
            return Err(error("record_session_request_budget"));
        }
        if Instant::now() >= deadline {
            return Err(error("record_session_expired"));
        }
        let request: Request =
            serde_json::from_slice(&bytes).map_err(|_| error("invalid_record_session_request"))?;
        if request.protocol != 1 {
            return Err(error("unsupported_record_session_protocol"));
        }
        let stop = matches!(request.command, Command::Stop {});
        let result = match request.command {
            Command::Status {} => Ok(
                json!({"scope":scope,"ready":true,"remaining_seconds":deadline.saturating_duration_since(Instant::now()).as_secs()}),
            ),
            Command::Stop {} => Ok(json!({"session_closed":"requested"})),
            command => execute(&mut editor, command),
        };
        let value: Value = match result {
            Ok(value) => json!({"schema_version":1,"result":value}),
            Err(failure) => json!({"schema_version":1,"error":failure}),
        };
        let bytes =
            serde_json::to_vec(&value).map_err(|_| error("record_session_response_failed"))?;
        if bytes.len() > 1024 * 1024 {
            return Err(error("record_session_response_budget"));
        }
        output
            .write_all(&bytes)
            .and_then(|()| output.write_all(b"\n"))
            .and_then(|()| output.flush())
            .map_err(|_| error("record_session_output_failed"))?;
        if stop {
            return Ok(());
        }
    }
    Err(error("record_session_request_limit"))
}
