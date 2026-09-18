use nujek_payment::{
    Client, CreateBillRequest, CreateUserRequest, Currency, Duration, ListBillsQuery,
    OffsetDateTime, PageQuery,
};

async fn create_bill() -> Result<(), Box<dyn std::error::Error>> {
    let client = Client::new("https://payment.example.com", "api-key", "api-secret")?;
    let result = client
        .create_bill(CreateBillRequest {
            external_id: "order-123".into(),
            channel_id: "NOBU_QRIS".into(),
            total: "150000.00".parse()?,
            currency: Some(Currency::Idr),
            expired_at: OffsetDateTime::now_utc() + Duration::minutes(15),
            external_user_id: Some("USER-001".into()),
            description: Some("Pembayaran perjalanan".into()),
        })
        .await?;
    println!("bill={}", result.data.uuid);
    Ok(())
}

async fn user_wallet(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    client
        .create_user(CreateUserRequest {
            external_user_id: "USER-001".into(),
            name: Some("Budi".into()),
            email: None,
            phone: None,
        })
        .await?;
    client
        .user_history(
            "USER-001",
            PageQuery {
                page: Some(1),
                per_page: Some(20),
            },
        )
        .await?;
    Ok(())
}

async fn user_bill_history(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
    let history = client
        .list_bills_for_user(
            "USER-001",
            ListBillsQuery {
                page: Some(1),
                per_page: Some(20),
                ..Default::default()
            },
        )
        .await?;
    let bill = client.get_bill_for_user("bill-uuid", "USER-001").await?;
    println!("{} {}", history.meta.total, bill.data.uuid);
    Ok(())
}

fn main() {
    let _ = (create_bill, user_wallet, user_bill_history);
}
