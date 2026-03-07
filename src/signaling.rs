use std::io::{Read, Write};

use anyhow::Result;
use base64::engine::general_purpose::{self, GeneralPurpose, GeneralPurposeConfig};
use base64::engine::DecodePaddingMode;
use base64::{alphabet, Engine};
use flate2::read::DeflateDecoder;
use flate2::write::DeflateEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};

const BASE64_ENCODE: GeneralPurpose = general_purpose::STANDARD;
const BASE64_DECODE: GeneralPurpose = GeneralPurpose::new(
    &alphabet::STANDARD,
    GeneralPurposeConfig::new().with_decode_padding_mode(DecodePaddingMode::Indifferent),
);
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

    /// Encode as compressed base64: JSON → deflate → base64.
    pub fn encode(&self) -> Result<String> {
        let json = serde_json::to_string(self)?;
        let mut encoder = DeflateEncoder::new(Vec::new(), Compression::best());
        encoder.write_all(json.as_bytes())?;
        let compressed = encoder.finish()?;
        Ok(BASE64_ENCODE.encode(&compressed))
    }

    /// Decode from base64, trying compressed (deflate) first, then plain JSON
    /// for backward compatibility.
    pub fn decode(encoded: &str) -> Result<Self> {
        let bytes = BASE64_DECODE.decode(encoded.trim())?;

        if let Ok(msg) = Self::decode_compressed(&bytes) {
            return Ok(msg);
        }

        let json_str = String::from_utf8(bytes)?;
        let msg: SignalMessage = serde_json::from_str(&json_str)?;
        Ok(msg)
    }

    fn decode_compressed(bytes: &[u8]) -> Result<Self> {
        let mut decoder = DeflateDecoder::new(bytes);
        let mut json_str = String::new();
        decoder.read_to_string(&mut json_str)?;
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
