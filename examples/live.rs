use std::{env, time::{SystemTime, UNIX_EPOCH}};

use nujek_payment::{
    Client, CreateBillRequest, CreatePayoutRequest, CreateUserRequest, Currency, Duration,
    Error, ListBillsQuery, OffsetDateTime, PageQuery, WalletMutationRequest,
};

fn required(name: &str) -> Result<String, Box<dyn std::error::Error>> {
    env::var(name).map_err(|_| format!("{name} is required").into())
}

fn enabled(name: &str) -> bool {
    matches!(env::var(name).as_deref(), Ok("1") | Ok("true") | Ok("TRUE"))
}

fn report<T>(name: &str, result: Result<T, Error>) -> Option<T> {
    match result {
        Ok(value) => {
            println!("✓ {name}");
            Some(value)
        }
        Err(error) => {
            eprintln!("✗ {name}: {error}");
            None
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Loads `.env` when present; environment variables supplied by CI take precedence.
    let _ = dotenvy::dotenv();
    let base_url = env::var("NUJEK_BASE_URL")
        .unwrap_or_else(|_| "https://staging-payment-api.nujek.co.id".into());
    let client = Client::new(
        &base_url,
        required("NUJEK_API_KEY")?,
        required("NUJEK_API_SECRET")?,
    )?;

    println!("Read-only endpoint checks:");
    report("GET /v1/balance", client.balance().await);
    report("GET /v1/users", client.list_users(PageQuery { page: Some(1), per_page: Some(20) }).await);
    report("GET /v1/bills", client.list_bills(ListBillsQuery { page: Some(1), per_page: Some(20), ..Default::default() }).await);
    report("GET /v1/qris-static", client.list_qris_static().await);

    if let Ok(qris_static_id) = env::var("NUJEK_LIVE_TEST_QRIS_STATIC_ID") {
        report("GET /v1/qris-static/{uuid}", client.get_qris_static(&qris_static_id).await);
    } else {
        println!("- GET /v1/qris-static/{{uuid}} skipped (set NUJEK_LIVE_TEST_QRIS_STATIC_ID)");
    }

    if !enabled("NUJEK_LIVE_TEST_WRITES") {
        println!("\nWrite endpoint checks skipped. Set NUJEK_LIVE_TEST_WRITES=true to create staging test data.");
        return Ok(());
    }

    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
    let user_id = format!("SDK-LIVE-{nonce}");
    let user = report(
        "POST /v1/users",
        client.create_user(CreateUserRequest {
            external_user_id: user_id.clone(),
            name: Some("SDK live test".into()),
            email: None,
            phone: None,
        }).await,
    );
    if user.is_none() {
        return Ok(());
    }

    report("GET /v1/users/{external_user_id}", client.get_user(&user_id).await);
    report("GET /v1/users/{external_user_id}/wallet", client.get_user_wallet(&user_id).await);
    report("GET /v1/users/{external_user_id}/history", client.user_history(&user_id, PageQuery { page: Some(1), per_page: Some(20) }).await);
    report("GET /v1/users/{external_user_id}/wallet/transactions", client.user_wallet_transactions(&user_id, PageQuery { page: Some(1), per_page: Some(20) }).await);
    report("GET /v1/users/{external_user_id}/bills", client.list_user_bills(&user_id, PageQuery { page: Some(1), per_page: Some(20) }).await);

    let channel_id = env::var("NUJEK_LIVE_TEST_CHANNEL_ID").unwrap_or_else(|_| "NOBU_QRIS".into());
    let bill = report(
        "POST /v1/bills",
        client.create_bill(CreateBillRequest {
            external_id: format!("SDK-LIVE-BILL-{nonce}"),
            channel_id,
            total: env::var("NUJEK_LIVE_TEST_AMOUNT").unwrap_or_else(|_| "10000".into()).parse()?,
            currency: Some(Currency::Idr),
            expired_at: OffsetDateTime::now_utc() + Duration::minutes(15),
            external_user_id: Some(user_id.clone()),
            description: Some("SDK live test bill".into()),
        }).await,
    );

    if let Some(bill) = bill {
        let bill_id = bill.data.uuid;
        report("GET /v1/bills/{bill_uuid}", client.get_bill(&bill_id).await);
        report("GET /v1/bills + X-External-User-Id", client.list_bills_for_user(&user_id, ListBillsQuery { page: Some(1), per_page: Some(20), ..Default::default() }).await);
        report("GET /v1/bills/{bill_uuid} + X-External-User-Id", client.get_bill_for_user(&bill_id, &user_id).await);
        report("GET /v1/users/{external_user_id}/bills/{bill_uuid}", client.get_user_bill(&user_id, &bill_id).await);
    }

    if enabled("NUJEK_LIVE_TEST_WALLET") {
        let amount = "1000".parse()?;
        let reference = format!("SDK-LIVE-WALLET-{nonce}");
        if report("POST /v1/users/{external_user_id}/wallet/topup", client.topup_user_wallet(&user_id, WalletMutationRequest { amount, reference_id: reference.clone(), description: Some("SDK live test".into()) }).await).is_some() {
            report("GET /v1/users/{external_user_id}/wallet/transactions/by-reference", client.lookup_wallet_transaction(&user_id, &reference).await);
            report("POST /v1/users/{external_user_id}/wallet/debit", client.debit_user_wallet(&user_id, WalletMutationRequest { amount, reference_id: format!("{reference}-DEBIT"), description: Some("SDK live test reversal".into()) }).await);
        }
    } else {
        println!("- Wallet mutation checks skipped (set NUJEK_LIVE_TEST_WALLET=true; these alter balances)");
    }

    let payout = client.create_payout(CreatePayoutRequest {
        external_id: format!("SDK-LIVE-PAYOUT-{nonce}"),
        destination_bank: "BCA".into(),
        destination_account: "0000000000".into(),
        destination_name: "SDK live test".into(),
        amount: "1000".parse()?,
        currency: Some(Currency::Idr),
    }).await;
    match payout {
        Err(error) if error.error_code() == Some("not_implemented") => println!("✓ POST /v1/payouts (currently returns expected not_implemented)"),
        other => { report("POST /v1/payouts", other); }
    }

    Ok(())
}
