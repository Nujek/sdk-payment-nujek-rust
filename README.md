# Nujek merchant API SDK (Rust)

```rust
let client = nujek_merchant_api::Client::new(
    "https://payment.example.com", "api-key", "api-secret",
)?;
let result = client.create_bill(nujek_merchant_api::CreateBillRequest {
    external_id: "order-123".into(),
    channel_id: "NOBU_QRIS".into(),
    total: serde_json::json!("150000.00"),
    currency: Some("IDR".into()),
    expired_at: None,
    external_user_id: Some("USER-001".into()),
    description: Some("Pembayaran perjalanan".into()),
}).await?;
```

User dan wallet merchant:

```rust
client.create_user(CreateUserRequest {
    external_user_id: "USER-001".into(),
    name: Some("Budi".into()),
    email: None,
    phone: None,
}).await?;

client.user_history("USER-001", PageQuery { page: Some(1), per_page: Some(20) }).await?;
```

Signature memakai `HMAC-SHA256(METHOD:path:unix_timestamp:raw_body)` dan dikirim dalam header API secara otomatis. Versi SDK saat ini: `0.2.0`.

Untuk callback partner, gunakan `verify_webhook_signature(timestamp, raw_body, signature, webhook_secret, now, 300)` sebelum parsing JSON.
