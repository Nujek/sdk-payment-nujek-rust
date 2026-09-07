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
}).await?;
```

Signature memakai `HMAC-SHA256(METHOD:path:unix_timestamp:raw_body)` dan dikirim dalam header API secara otomatis. Versi rilis awal: `0.1.0`.

Untuk callback partner, gunakan `verify_webhook_signature(timestamp, raw_body, signature, webhook_secret, now, 300)` sebelum parsing JSON.
