use std::{path::PathBuf, sync::Arc};
use reqwest_middleware::{ClientBuilder, ClientWithMiddleware};
use reqwest::{header, cookie::CookieStore};
use serde::de::DeserializeOwned;
use lazy_regex::{regex_is_match, regex_captures};
use async_fs::File;
use futures::io::AsyncWriteExt;
use crate::error::{TradeOfferError, Error};

/// Generates a random sessionid.
pub fn generate_sessionid() -> String {
    // Should look like "37bf523a24034ec06c60ec61"
    (0..12)
        .map(|_| { 
            let b = rand::random::<u8>();
            
            format!("{b:02x?}")
        })
        .collect()
}

pub async fn write_file_atomic(
    filepath: PathBuf,
    bytes: &[u8],
) -> std::io::Result<()> {
    let mut temp_filepath = filepath.clone();
    
    temp_filepath.set_extension("tmp");
    
    let mut temp_file = File::create(&temp_filepath).await?;
    
    match temp_file.write_all(bytes).await {
        Ok(_) => {
            temp_file.flush().await?;
            async_fs::rename(&temp_filepath,&filepath).await?;
            Ok(())
        },
        Err(error) => {
            // something went wrong writing to this file...
            async_fs::remove_file(&temp_filepath).await?;
            Err(error)
        }
    }
}

pub fn get_default_middleware<T>(
    cookie_store: Arc<T>,
    user_agent_string: &'static str,
) -> ClientWithMiddleware
where
    T: CookieStore + 'static,
{
    let mut headers = header::HeaderMap::new();
    
    headers.insert(header::USER_AGENT, header::HeaderValue::from_static(user_agent_string));
    
    let client = reqwest::ClientBuilder::new()
        .cookie_provider(cookie_store)
        .default_headers(headers)
        .build()
        .unwrap();
    
    ClientBuilder::new(client)
        .build()
}

fn is_login(location_option: Option<&header::HeaderValue>) -> bool {
    match location_option {
        Some(location) => {
            if let Ok(location_str) = location.to_str() {
                regex_is_match!("/login", location_str)
            } else {
                false
            }
        },
        None => false,
    }
}

pub async fn check_response(
    response: reqwest::Response,
) -> Result<Vec<u8>, Error> {
    let status = &response.status();
    
    match status.as_u16() {
        300..=399 if is_login(response.headers().get("location")) => {
            Err(Error::NotLoggedIn)
        },
        400..=499 => Err(Error::Http(response)),
        500..=599 => Err(Error::Http(response)),
        _ => Ok(response.bytes().await?.to_vec()),
    }
}

pub async fn parses_response<D>(response: reqwest::Response) -> Result<D, Error>
where
    D: DeserializeOwned,
{
    let body = check_response(response).await?;
    // let html = String::from_utf8_lossy(&body);

    // println!("{}", html);

    match serde_json::from_slice::<D>(&body) {
        Ok(body) => Ok(body),
        Err(parse_error) => {
            // unexpected response
            let html = String::from_utf8_lossy(&body);
            
            if regex_is_match!(r#"<h1>Sorry!</h1>"#, &html) {
                if let Some((_, message)) = regex_captures!("<h3>(.+)</h3>", &html) {
                    Err(Error::Response(message.into()))
                } else {
                    Err(Error::MalformedResponse)
                }
            } else if regex_is_match!(r#"<h1>Sign In</h1>"#, &html) && regex_is_match!(r#"g_steamID = false;"#, &html) {
                Err(Error::NotLoggedIn)
            } else if regex_is_match!(r#"\{"success": ?false\}"#, &html) {
                Err(Error::ResponseUnsuccessful)
            } else if let Some((_, message)) = regex_captures!(r#"<div id="error_msg">\s*([^<]+)\s*</div>"#, &html) {
                Err(Error::TradeOffer(TradeOfferError::from(message)))
            } else {
                log::error!("Error parsing body `{}`: {}", parse_error, String::from_utf8_lossy(&body));
                
                Err(Error::Parse(parse_error))
            }
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
