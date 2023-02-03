use crate::{SteamID, types::{AppId, ContextId}, internal_types::Client, helpers::DEFAULT_CLIENT};

/// Options for loading a user's inventory.
#[derive(Debug, Clone)]
pub struct GetInventoryOptions<'a> {
    /// Client to use for making requests.
    pub client: &'a Client,
    /// The user's Steam ID.
    pub steamid: SteamID,
    /// App ID of inventory.
    pub appid: AppId,
    /// Context ID of inventory.
    pub contextid: ContextId,
    /// Whether to fetch only tradable items.
    pub tradable_only: bool,
    /// The language to use for descriptions.
    pub language: String,
}

impl<'a> GetInventoryOptions<'a> {
    /// Creates a new [`GetInventoryOptions`].
    pub fn new(
        steamid: SteamID,
        appid: AppId,
        contextid: ContextId,
    ) -> GetInventoryOptions<'a> {
        Self::builder(
            steamid,
            appid,
            contextid,
        ).build()
    }
    
    /// Creates a [`GetInventoryOptionsBuilder`] for building options.
    pub fn builder(
        steamid: SteamID,
        appid: AppId,
        contextid: ContextId,
    ) -> GetInventoryOptionsBuilder<'a> {
        GetInventoryOptionsBuilder::new(
            steamid,
            appid,
            contextid,
        )
    }
}

/// Builder for creating [`GetInventoryOptions`].
#[derive(Debug, Clone)]
pub struct GetInventoryOptionsBuilder<'a> {
    client: &'a Client,
    steamid: SteamID,
    appid: AppId,
    contextid: ContextId,
    tradable_only: bool,
    language: String,
}

impl<'a> GetInventoryOptionsBuilder<'a> {
    pub fn new(
        steamid: SteamID,
        appid: AppId,
        contextid: ContextId,
    ) -> Self {
        Self {
            client: &DEFAULT_CLIENT,
            steamid,
            appid,
            contextid,
            tradable_only: true,
            language: String::from("english"),
        }
    }
    
    /// Client to use for making requests.
    pub fn client(mut self, client: &'a Client) -> Self {
        self.client = client;
        self
    }
    
    /// Whether to fetch only tradable items.
    pub fn tradable_only(mut self, tradable_only: bool) -> Self {
        self.tradable_only = tradable_only;
        self
    }
    
    /// The language to use for descriptions.
    pub fn language(mut self, language: String) -> Self {
        self.language = language;
        self
    }
    
    /// Builds into [`GetInventoryOptions`].
    pub fn build(self) -> GetInventoryOptions<'a> {
        GetInventoryOptions {
            client: self.client,
            steamid: self.steamid,
            appid: self.appid,
            contextid: self.contextid,
            tradable_only: self.tradable_only,
            language: self.language,
        }
    }
}