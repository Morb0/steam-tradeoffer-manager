use crate::error::{Error, TradeOfferError};
use crate::types::HttpClient;
use async_fs::File;
use directories::BaseDirs;
use futures::io::AsyncWriteExt;
use lazy_regex::{regex_captures, regex_is_match};
use lazy_static::lazy_static;
use reqwest::cookie::{CookieStore, Jar};
use reqwest::header;
use serde::de::DeserializeOwned;
use std::fmt::Write;
use std::path::PathBuf;
use std::sync::Arc;

lazy_static! {
    pub static ref DEFAULT_CLIENT: HttpClient = {
        let cookie_store = Arc::new(Jar::default());

        get_http_client(cookie_store, USER_AGENT_STRING)
    };
}

pub fn default_data_directory() -> PathBuf {
    if let Some(base_dirs) = BaseDirs::new() {
        base_dirs.config_dir().join("rust-steam-tradeoffer-manager")
    } else {
        "./rust-steam-tradeoffer-manager".into()
    }
}

/// A browser user agent string.
pub const USER_AGENT_STRING: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36";
pub(crate) const COMMUNITY_HOSTNAME: &str = "steamcommunity.com";
pub(crate) const WEB_API_HOSTNAME: &str = "api.steampowered.com";

/// Generates a random sessionid.
pub fn generate_sessionid() -> String {
    // Should look like "37bf523a24034ec06c60ec61"
    (0..12).fold(String::new(), |mut output, _| {
        let b = rand::random::<u8>();
        let _ = write!(output, "{b:02x?}");

        output
    })
}

/// Extracts the session ID, Steam ID and Access Token from cookie values.
pub fn extract_auth_data_from_cookies(
    cookies: &[String],
) -> (Option<String>, Option<u64>, Option<String>) {
    let mut sessionid = None;
    let mut steamid = None;
    let mut access_token = None;

    for cookie in cookies {
        if let Some((_, key, value)) = regex_captures!(r#"([^=]+)=(.+)"#, cookie) {
            match key {
                "sessionid" => sessionid = Some(value.to_string()),
                "steamLoginSecure" => {
                    if let Some((_, steamid_str, access_token_str)) =
                        regex_captures!(r#"^(\d{17})%7C%7C([^;]+)"#, value)
                    {
                        steamid = steamid_str.parse::<u64>().ok();
                        access_token = Some(access_token_str.to_string());
                    }
                }
                _ => {}
            }
        }
    }

    (sessionid, steamid, access_token)
}

/// Writes a file atomically.
pub async fn write_file_atomic(filepath: PathBuf, bytes: &[u8]) -> std::io::Result<()> {
    let mut temp_filepath = filepath.clone();

    temp_filepath.set_extension("tmp");

    let mut temp_file = File::create(&temp_filepath).await?;

    match temp_file.write_all(bytes).await {
        Ok(_) => {
            temp_file.flush().await?;
            async_fs::rename(&temp_filepath, &filepath).await?;
            Ok(())
        }
        Err(error) => {
            // something went wrong writing to this file...
            async_fs::remove_file(&temp_filepath).await?;
            Err(error)
        }
    }
}

/// Creates a client middleware which includes a cookie store and user agent string.
pub fn get_http_client<T>(cookie_store: Arc<T>, user_agent_string: &'static str) -> reqwest::Client
where
    T: CookieStore + 'static,
{
    reqwest::ClientBuilder::new()
        .cookie_provider(cookie_store)
        .user_agent(user_agent_string)
        .build()
        .unwrap()
}

/// Checks if location is login.
fn is_login(location_option: Option<&header::HeaderValue>) -> bool {
    if let Some(location) = location_option {
        if let Ok(location_str) = location.to_str() {
            // starts_with is probably more accurate (should be tested)
            return location_str.contains("/login");
        }
    }

    false
}

/// Deserializes and checks response for errors.
pub async fn parses_response<D>(response: reqwest::Response) -> Result<D, Error>
where
    D: DeserializeOwned,
{
    let status = response.status();
    let headers = response.headers().clone();
    let bytes = response.bytes().await?;

    // Log non-success status and include body for debugging
    if !status.is_success() {
        let body_text = String::from_utf8_lossy(&bytes);
        log::warn!(
            "Steam response error. Status: {}, Body: {}",
            status,
            body_text
        );

        // Session seems expired
        if body_text.contains("Access is denied") {
            return Err(Error::NotLoggedIn);
        }

        // Redirects that might imply not logged in
        if (300..=399).contains(&status.as_u16()) {
            if let Some(location) = headers.get("location") {
                if is_login(Some(location)) {
                    return Err(Error::NotLoggedIn);
                }
            }
        }

        // Capture general error by status range
        if (400..=599).contains(&status.as_u16()) {
            return Err(Error::StatusCode(status));
        }
    }

    // Try to parse JSON first
    match serde_json::from_slice::<serde_json::Value>(&bytes) {
        Ok(json) => {
            // Check x-eresult Steam header
            let eresult = headers
                .get("x-eresult")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u32>().ok());

            let has_extra_fields = json.as_object().map_or(false, |obj| obj.len() > 1);
            let response_has_data = json.get("response").map_or(false, |r| r.is_object() && !r.as_object().unwrap().is_empty());

            if let Some(code) = eresult {
                let is_fake_error = code == 2 && !has_extra_fields && !response_has_data;
                if code != 1 && !is_fake_error {
                    return Err(Error::SteamEresult(code, json.clone()));
                }
            }

            serde_json::from_value::<D>(json).map_err(Error::Parse)
        }
        Err(parse_error) => {
            let html = String::from_utf8_lossy(&bytes);

            if html.contains(r#"<h1>Sorry!</h1>"#) {
                return if let Some((_, message)) = regex_captures!("<h3>(.+)</h3>", &html) {
                    Err(Error::UnexpectedResponse(message.into()))
                } else {
                    Err(Error::MalformedResponse(
                        "Unexpected error response format.",
                    ))
                };
            }

            if html.contains(r#"<h1>Sign In</h1>"#) && html.contains(r#"g_steamID = false;"#) {
                return Err(Error::NotLoggedIn);
            }

            if regex_is_match!(r#"\{"success": ?false\}"#, &html) {
                return Err(Error::ResponseUnsuccessful);
            }

            if let Some((_, message)) =
                regex_captures!(r#"<div id="error_msg">\s*([^<]+)\s*</div>"#, &html)
            {
                return Err(Error::TradeOffer(TradeOfferError::from(message)));
            }

            log::error!(
                "Failed to parse Steam response as JSON: {}\nRaw Body: {}",
                parse_error,
                html
            );

            Err(Error::Parse(parse_error))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_session() {
        let sessionid = generate_sessionid();

        assert_eq!(sessionid.len(), 24);
    }
}
