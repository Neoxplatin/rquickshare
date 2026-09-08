use rqs_lib::SendInfo;

use crate::AppState;

#[tauri::command]
pub async fn send_payload(
    message: SendInfo,
    state: tauri::State<'_, AppState>,
) -> Result<(), String> {
    info!("send_payload: transfer {}", message.id);

    state
        .sender_file
        .send(message)
        .await
        .map_err(|e| format!("couldn't send payload: {e}"))
}
