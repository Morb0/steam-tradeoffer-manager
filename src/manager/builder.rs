use super::TradeOfferManager;
use crate::helpers::USER_AGENT_STRING;
use crate::ClassInfoCache;
use crate::enums::Language;
use std::path::PathBuf;
use std::sync::Arc;
use reqwest::cookie::Jar;
use reqwest_middleware::ClientWithMiddleware;

/// Builder for constructing a [`TradeOfferManager`].
#[derive(Debug, Clone)]
pub struct TradeOfferManagerBuilder {
    /// Your account's API key from <https://steamcommunity.com/dev/apikey>.
    pub api_key: String,
    /// The identity secret for the account (optional). Required for mobile confirmations.
    pub identity_secret: Option<String>,
    /// The language for API responses.
    pub language: Language,
    /// The [`ClassInfoCache`] to use for this manager. Useful if instantiating multiple managers 
    /// to share state.
    pub classinfo_cache: ClassInfoCache,
    /// The location to save data to.
    pub data_directory: PathBuf,
    /// Request cookies.
    pub cookie_jar: Option<Arc<Jar>>,
    /// Client to use for requests. Remember to also include the cookies connected to this client.
    pub client: Option<ClientWithMiddleware>,
    /// User agent for requests.
    pub user_agent: &'static str,
    /// How many seconds your computer is behind Steam's servers. Used in mobile confirmations.
    pub time_offset: i64,
    /// Cookies to set on initialization.
    pub cookies: Option<Vec<String>>,
}

impl TradeOfferManagerBuilder {
    /// Creates a new [`TradeOfferManagerBuilder`]. The `data_directory` is the directory used to 
    /// store poll data and classinfo data.
    pub fn new<T>(
        api_key: String,
        data_directory: T,
    ) -> Self
    where
        T: Into<PathBuf>,
    {
        Self {
            api_key,
            identity_secret: None,
            language: Language::English,
            classinfo_cache: ClassInfoCache::default(),
            data_directory: data_directory.into(),
            cookie_jar: None,
            client: None,
            user_agent: USER_AGENT_STRING,
            time_offset: 0,
            cookies: None,
        }
    }
    
    /// The identity secret for the account. Required for mobile confirmations.
    pub fn identity_secret(mut self, identity_secret: String) -> Self {
        self.identity_secret = Some(identity_secret);
        self
    }
    
    /// The language for API responses.
    pub fn language(mut self, language: Language) -> Self {
        self.language = language;
        self
    }
    
    /// The [`ClassInfoCache`] to use for this manager. Useful if instantiating multiple managers
    /// to share state.
    pub fn classinfo_cache(mut self, classinfo_cache: ClassInfoCache) -> Self {
        self.classinfo_cache = classinfo_cache;
        self
    }
    
    /// Client to use for requests. It is also required to include the associated cookies with this
    /// client so that the `set_cookies` method works as expected.
    pub fn client(mut self, client: ClientWithMiddleware, cookie_jar: Arc<Jar>) -> Self {
        self.client = Some(client);
        self.cookie_jar = Some(cookie_jar);
        self
    }
    
    /// How many seconds your computer is behind Steam's servers. Used in mobile confirmations.
    pub fn time_offset(mut self, time_offset: i64) -> Self {
        self.time_offset = time_offset;
        self
    }
    
    /// The API key.
    pub fn api_key(mut self, api_key: String) -> Self {
        self.api_key = api_key;
        self
    }
    
    /// The web cookies.
    pub fn cookies(mut self, cookies: Vec<String>) -> Self {
        self.cookies = Some(cookies);
        self
    }
    
    /// Builds the [`TradeOfferManager`].
    pub fn build(self) -> TradeOfferManager {
        self.into()
    }
}