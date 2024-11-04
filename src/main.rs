use std::time::Duration;
use alloy::network::EthereumWallet;
use alloy::signers::k256::ecdsa::Signature;
use alloy::signers::local::PrivateKeySigner;
use alloy::signers::Signer;
use clokwerk::{AsyncScheduler, Job, TimeUnits};
use dotenvy_macro::dotenv;
use ed25519_dalek::ed25519::signature::rand_core::OsRng;
use ed25519_dalek::{SigningKey, VerifyingKey};
use eyre::Result;
use fatline_rs::proto::message_data::Body::CastAddBody as CABody;
use fatline_rs::{utils, MessageTrait};
use fatline_rs::proto::{CastAddBody, FarcasterNetwork, HashScheme, Message, MessageData, MessageType, SignatureScheme, CastType};
use fatline_rs::proto::hub_service_client::HubServiceClient;
use jesse::{add_key_for, default_provider, get_nonce, key_add_sign_hash, one_hour_deadline, register_fid_for, register_sign_hash, sign_key_request_metadata, sign_key_request_sign_hash, ID_GATEWAY_ADDRESS, KEY_GATEWAY_ADDRESS};

const HUB_URL: &'static str = dotenv!("HUB_URL");
const OWNER_PRIVATE_KEY: &'static str = dotenv!("OWNER_PRIVATE_KEY");

async fn post_gm(bot_fid: u64, bot_msg_signer: SigningKey, bot_pub_key_bytes: [u8;32]) -> Result<()> {
    // get client
    let mut client = HubServiceClient::connect("").await?;

    // create cast
    let cast_add_body = CABody(CastAddBody {
        embeds_deprecated: vec![],
        mentions: vec![],
        text: "GM farcaster".to_string(),
        mentions_positions: vec![],
        embeds: vec![],
        r#type: CastType::Cast as i32,
        parent: None,
    });

    let data = MessageData {
        r#type: MessageType::CastAdd as i32,
        fid: bot_fid,
        timestamp: utils::now(),
        network: FarcasterNetwork::Mainnet as i32,
        body: Some(cast_add_body),
    };

    let hash = utils::message_hash(&data);
    let signature = utils::sign_hash(&bot_msg_signer, &hash);

    let message = Message {
        data_bytes: Some(data.encode_to_vec()),
        data: None,
        hash_scheme: HashScheme::Blake3 as i32,
        signature_scheme: SignatureScheme::Ed25519 as i32,
        signature: signature.to_vec(),
        signer: bot_pub_key_bytes.to_vec(),
        hash: hash.to_vec(),
    };

    let _result = client.submit_message(message).await?;

    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    // alternatively, import this here!
    let bot_msg_signer = SigningKey::generate(&mut OsRng);
    let bot_pub_key = VerifyingKey::from(&bot_msg_signer);
    // Bot ed25519 public key bytes
    let bot_pub_key_bytes = bot_pub_key.to_bytes();

    // make this an actual account from secrets or env, or sponsored gas tx
    let owner_signer = PrivateKeySigner::random();
    let owner_wallet = EthereumWallet::new(owner_signer.clone());

    let bot_eth_signer = PrivateKeySigner::random();
    let bot_address = bot_eth_signer.address();

    // default optimism mainnet provider
    let provider = default_provider(owner_wallet)?;

    // a registration and key add deadline to be used for requests and signing
    let deadline = one_hour_deadline()?;

    let register_nonce = get_nonce(bot_address, ID_GATEWAY_ADDRESS, &provider).await?;
    // sign up to farcaster, generate the registration message
    let register_hash = register_sign_hash(bot_address, None, register_nonce, deadline);
    let signature = bot_eth_signer.sign_hash(&register_hash).await?;
    // sign up to farcaster, submit the registration parameters on behalf of the bot
    let bot_fid = register_fid_for(bot_address, None, signature, deadline, &provider).await?;

    // create and sign the key add message
    let key_nonce = get_nonce(bot_address, KEY_GATEWAY_ADDRESS, &provider).await?;

    let key_hash = sign_key_request_sign_hash(bot_fid, deadline, bot_pub_key_bytes);
    let signature = bot_eth_signer.sign_hash(&key_hash).await?;
    let metadata = sign_key_request_metadata(bot_fid, bot_address, signature, deadline)?;
    let add_hash = key_add_sign_hash(bot_address, bot_pub_key_bytes, metadata.clone(), key_nonce, deadline);
    let signature = bot_eth_signer.sign_hash(&add_hash).await?;

    // add the key for the bot
    add_key_for(bot_address, deadline, signature, bot_pub_key_bytes, metadata, &provider).await?;

    // The bot is now registered for farcaster, create some content for it

    let mut scheduler = AsyncScheduler::new();
    // gm
    scheduler.every(1.day()).at("8:00am").run(move || {
        let signer = bot_msg_signer.clone();
        async move {
            post_gm(bot_fid, signer, bot_pub_key_bytes).await.unwrap();
        }
    });

    loop {
        scheduler.run_pending();
        tokio::time::sleep(Duration::from_secs(300)).await;
    }
}
