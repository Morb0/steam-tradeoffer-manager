use super::TradeOfferManager;
use crate::helpers::USER_AGENT_STRING;
use crate::helpers::default_data_directory;
use crate::ClassInfoCache;
use crate::enums::Language;
use std::path::PathBuf;
use std::sync::Arc;
use reqwest::cookie::Jar;

/// Builder for constructing a [`TradeOfferManager`].
/// 
/// An API key is required to use the Steam Web API. You can get one from the 
/// [Steam Community](https://steamcommunity.com/dev/apikey) or by using the 
/// [`TradeOfferManager::get_api_key`][`crate::TradeOfferManager`] method.
/// 
/// By default, the data directory is stored in the config directory of the current user 
/// determined by the OS:
/// - Linux: `/home/<username>/.config/rust-steam-tradeoffer-manager`
/// - MacOS: `/Users/<username>/Library/Application Support/rust-steam-tradeoffer-manager`
/// - Windows: `C:\Users\<username>\AppData\Roaming\rust-steam-tradeoffer-manager`
/// 
/// In some cases (such as when running in a Docker container), the config directory may not be 
/// available. In this case, the data directory will be stored in the 
/// `rust-steam-tradeoffer-manager` directory in the current working directory.
/// 
/// Refer to the [directories](https://docs.rs/directories/5.0.1/directories/struct.BaseDirs.html) 
/// crate for more information.
#[derive(Debug, Clone)]
pub struct TradeOfferManagerBuilder {
    /// Your account's JWT access token.
    pub(crate) access_token: Option<String>,
    /// The identity secret for the account (optional). Required for mobile confirmations.
    pub(crate) identity_secret: Option<String>,
    /// The language for API responses.
    pub(crate) language: Language,
    /// The [`ClassInfoCache`] to use for this manager. Useful if instantiating multiple managers 
    /// to share state.
    pub(crate) classinfo_cache: Option<ClassInfoCache>,
    /// The location to save data to.
    pub(crate) data_directory: PathBuf,
    /// Request cookies.
    pub(crate) cookie_jar: Option<Arc<Jar>>,
    /// Client to use for requests. Remember to also include the cookies connected to this client.
    pub(crate) client: Option<reqwest::Client>,
    /// User agent for requests.
    pub(crate) user_agent: &'static str,
    /// How many seconds your computer is behind Steam's servers. Used in mobile confirmations.
    pub(crate) time_offset: i64,
    /// Cookies to set on initialization.
    pub(crate) cookies: Option<Vec<String>>,
}

impl Default for TradeOfferManagerBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl TradeOfferManagerBuilder {
    /// Creates a new [`TradeOfferManagerBuilder`].
    pub fn new() -> Self {
        Self {
            access_token: None,
            identity_secret: None,
            language: Language::English,
            classinfo_cache: None,
            data_directory: default_data_directory(),
            cookie_jar: None,
            client: None,
            user_agent: USER_AGENT_STRING,
            time_offset: 0,
            cookies: None,
        }
    }

    /// The data_directory is the directory used to store poll data and classinfo data.
    pub fn data_directory<T>(mut self, data_directory: T) -> Self
    where
        T: Into<PathBuf>,
    {
        self.data_directory = data_directory.into();
        self
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
        self.classinfo_cache = Some(classinfo_cache);
        self
    }
    
    /// Client to use for requests. It is also required to include the associated cookies with this
    /// client so that the `set_cookies` method works as expected.
    pub fn client(mut self, client: reqwest::Client, cookie_jar: Arc<Jar>) -> Self {
        self.client = Some(client);
        self.cookie_jar = Some(cookie_jar);
        self
    }
    
    /// How many seconds your computer is behind Steam's servers. Used in mobile confirmations.
    pub fn time_offset(mut self, time_offset: i64) -> Self {
        self.time_offset = time_offset;
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