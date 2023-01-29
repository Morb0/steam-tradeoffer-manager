use num_enum::{TryFromPrimitive, IntoPrimitive};
use serde_repr::{Serialize_repr, Deserialize_repr};
use strum_macros::{Display, EnumString};

/// The method of confirmation.
#[derive(Debug, Serialize_repr, Deserialize_repr, Display, EnumString, PartialEq, TryFromPrimitive, IntoPrimitive, Clone, Copy)]
#[repr(u8)]
pub enum ConfirmationMethod {
    None = 0,
    Email = 1,
    MobileApp = 2,
}

/// The type of confirmation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ConfirmationType {
    Generic = 1,
    Trade = 2,
    MarketSell = 3,
    AccountRecovery = 6,
    Unknown,
}

impl From<&str> for ConfirmationType {
    fn from(text: &str) -> Self {
        match text {
            "1" => ConfirmationType::Generic,
            "2" => ConfirmationType::Trade,
            "3" => ConfirmationType::MarketSell,
            "6" => ConfirmationType::AccountRecovery,
            _ => ConfirmationType::Unknown,
        }
    }
}