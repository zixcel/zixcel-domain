use super::Command;
use crate::{
    Result, error,
    record_editor::Editor,
    transport::{HttpTransport, Provider, RecordWriteTransport},
};
use serde_json::Value;

pub(super) fn live(editor: &mut Editor, command: Command) -> Result<Value> {
    let mut transport = HttpTransport::from_env(Provider::Cloudflare, "CLOUDFLARE_API_TOKEN")?;
    execute(editor, command, &mut transport)
}
pub(super) fn execute(
    editor: &mut Editor,
    command: Command,
    transport: &mut impl RecordWriteTransport,
) -> Result<Value> {
    let encode_error = |_| error("record_session_response_failed");
    match command {
        Command::Plan { edit } => {
            serde_json::to_value(editor.plan(edit, transport)?).map_err(encode_error)
        }
        Command::Apply { sha256 } => {
            serde_json::to_value(editor.apply(&sha256, transport)?).map_err(encode_error)
        }
        _ => Err(error("invalid_record_session_request")),
    }
}
