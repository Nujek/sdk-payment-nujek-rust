# Nujek merchant API SDK (Rust)

```rust
let client = nujek_payment::Client::new(
    "https://payment.example.com", "api-key", "api-secret",
)?;
let result = client.create_bill(nujek_payment::CreateBillRequest {
    external_id: "order-123".into(),
    channel_id: "NOBU_QRIS".into(),
    total: "150000.00".parse::<rust_decimal::Decimal>()?,
    currency: Some(Currency::Idr),
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

`reference_id` pada `topup_user_wallet` dan `debit_user_wallet` adalah kunci idempotensi
yang scoped ke merchant dan user. Retry dengan reference yang sama tidak membuat transaksi
kedua. Retry dengan nominal atau operasi berbeda menghasilkan konflik. Jika hasil request
tidak pasti karena timeout, gunakan:

```rust
let status = client.lookup_wallet_transaction("USER-001", "TOPUP-001").await?;
```

Bill yang mungkin berhasil dibuat sebelum timeout dapat dicari dengan external ID:

```rust
let bill = client.get_bill_by_external_id("NUJEK_BILL:order-123").await?;
```

Error API dapat diproses tanpa parsing manual:

```rust
match client.get_bill_by_external_id("NUJEK_BILL:order-123").await {
    Ok(result) => println!("status: {:?}", result.data.status),
    Err(error) if error.is_retryable() => {
        // hormati error.retry_after() bila tersedia
    }
    Err(error) if error.is_not_found() => { /* bill belum ditemukan */ }
    Err(error) => eprintln!("request_id={:?}: {error}", error.request_id()),
}
```

Status dan waktu sudah typed: `BillStatus`, `UserStatus`, `WalletMutationStatus`,
`WalletTransactionType`, `Currency`, dan `time::OffsetDateTime`.

`external_user_id` pada `create_bill` hanya mengaitkan bill dengan user. Pembayaran bank
melalui callback mengkredit saldo merchant melalui alur payin yang sudah ada; bill tidak
otomatis melakukan top-up ke saldo user. Top-up user hanya terjadi melalui
`topup_user_wallet`.

Signature memakai `HMAC-SHA256(METHOD:path:unix_timestamp:raw_body)` dan dikirim dalam header API secara otomatis. Nominal memakai `rust_decimal::Decimal`. Nama crate: `nujek-payment`. Versi SDK saat ini: `0.7.0`.

`ListBillsQuery.status` memakai `BillStatus`, sedangkan `start_date` dan `end_date` memakai `time::OffsetDateTime` dan dikirim sebagai RFC3339. Detail QRIS memakai `QrisStaticPayment` typed, bukan JSON bebas.

Untuk callback partner, gunakan `verify_webhook_signature(timestamp, raw_body, signature, webhook_secret, now, 300)` sebelum parsing JSON.
