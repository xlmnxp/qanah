use anyhow::Result;
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use serde::{Deserialize, Serialize};
use webrtc::peer_connection::sdp::session_description::RTCSessionDescription;

/// Serializable wrapper for exchanging SDP + ICE candidates via copy-paste signaling.
#[derive(Debug, Serialize, Deserialize)]
pub struct SignalMessage {
    pub sdp: String,
    pub sdp_type: String,
}

impl SignalMessage {
    pub fn from_sdp(sdp: &RTCSessionDescription) -> Self {
        Self {
            sdp: sdp.sdp.clone(),
            sdp_type: sdp.sdp_type.to_string(),
        }
    }

    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_string(self)?;
        Ok(BASE64.encode(json.as_bytes()))
    }

    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = BASE64.decode(encoded.trim())?;
        let json_str = String::from_utf8(bytes)?;
        let msg: SignalMessage = serde_json::from_str(&json_str)?;
        Ok(msg)
    }

    pub fn to_rtc_session_description(&self) -> Result<RTCSessionDescription> {
        let desc = match self.sdp_type.as_str() {
            "offer" => RTCSessionDescription::offer(self.sdp.clone()),
            "answer" => RTCSessionDescription::answer(self.sdp.clone()),
            "pranswer" => RTCSessionDescription::pranswer(self.sdp.clone()),
            other => anyhow::bail!("Unknown SDP type: {}", other),
        };

        Ok(desc?)
    }
}
