# steam-tradeoffers

Heavily inspired by the excellent [node-steam-tradeoffer-manager](https://github.com/DoctorMcKay/node-steam-tradeoffer-manager) module.

Thanks to https://github.com/dyc3/steamguard-cli (steamguard) for functionality relating to mobile confirmations.

```rs
use steam_tradeoffers::{
    TradeOfferManager,
    Asset,
    TradeOfferState,
    steamid_ng::SteamID
};

fn assets_item_names<'a>(assets: &'a Vec<Asset>) -> Vec<&'a str> {
    assets
        .iter()
        .map(|item| item.classinfo.market_hash_name.as_ref())
        .collect::<Vec<_>>()
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let steamid = SteamID::from(0);
    let manager = TradeOfferManager::new(
        &steamid,
        "key",
        Some("secret".into()),
    );
    let sessionid = "sessionid";
    let cookies = vec![String::from("cookie=value")];
    
    manager.set_session(sessionid, &cookies)?;
    
    for (offer, old_state) in manager.do_poll(true).await? {
        if let Some(state) = old_state {
            println!(
                "Offer {} changed state: {} -> {}",
                offer,
                state,
                offer.trade_offer_state
            );
        } else if offer.trade_offer_state == TradeOfferState::Active {
            if offer.is_our_offer {
                // we sent this offer
            } else {
                println!(
                    "New offer {}",
                    offer
                );
                println!(
                    "Offering: {:?}",
                    assets_item_names(&offer.items_to_give)
                );
                println!(
                    "Receiving: {:?}",
                    assets_item_names(&offer.items_to_receive)
                );
            }
        }
    }
    
    let items = manager.get_inventory(&steamid, 440, 2, true).await?;
    
    println!("{} items in your inventory", items.len());
    
    Ok(())
}
```

## LICENSE

MIT