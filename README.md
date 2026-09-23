# Nujek merchant API SDK (Rust)

```rust
use nujek_payment::{Client, CreateBillRequest, Currency, Duration, OffsetDateTime};

async fn create_bill() -> Result<(), Box<dyn std::error::Error>> {
let client = Client::new(
    "https://payment.example.com", "api-key", "api-secret",
)?;
let result = client.create_bill(CreateBillRequest {
    external_id: "order-123".into(),
    channel_id: "NOBU_QRIS".into(),
    total: "150000.00".parse::<rust_decimal::Decimal>()?,
    currency: Some(Currency::Idr),
    // Wajib; gunakan waktu RFC3339 di masa depan.
    expired_at: OffsetDateTime::now_utc() + Duration::minutes(15),
    external_user_id: Some("USER-001".into()),
    description: Some("Pembayaran perjalanan".into()),
}).await?;
println!("bill={}", result.data.uuid);
Ok(())
}
```

Mulai onboarding user:

```rust
use nujek_payment::{Client, CreateOnboardingSessionRequest};

async fn start_onboarding(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
client.create_onboarding_session(CreateOnboardingSessionRequest {
    external_user_id: "USER-001".into(),
    name: Some("Budi".into()),
    email: Some("budi@example.com".into()),
    phone: Some("628123456789".into()),
    redirect_url: "https://merchant.example.com/onboarding-complete".into(),
}).await?;
Ok(())
}
```

User dibuat hanya setelah menyelesaikan WebView onboarding. Gunakan `webview_url` dari respons
untuk membuka WebView, lalu gunakan `external_user_id` yang sama untuk API wallet dan bill.
`POST /v1/users` tidak tersedia.

Merchant menerima `onboarding_token` di respons saat membuat sesi dan di webhook completion,
bukan pada URL redirect. Gunakan API terautentikasi berikut untuk memeriksa token tersebut:

```rust
let session = client.get_onboarding_session("onboarding-token").await?;
assert_eq!(session.data.status, "active");
assert_eq!(session.data.external_user_id, "USER-001");

// Token tidak kedaluwarsa. Cabut saat merchant tidak lagi mengizinkan koneksi ini.
let revoked = client.revoke_onboarding_session("onboarding-token").await?;
assert_eq!(revoked.data.status, "revoked");
```

`revoke_onboarding_session` hanya dapat digunakan setelah onboarding selesai dan tidak dapat
dibatalkan. Jangan memanggilnya sebagai bagian dari retry normal.

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
use nujek_payment::Client;

async fn inspect_error(client: &Client) {
match client.get_bill_by_external_id("NUJEK_BILL:order-123").await {
    Ok(result) => println!("status: {:?}", result.data.status),
    Err(error) if error.is_retryable() => {
        // hormati error.retry_after() bila tersedia
    }
    Err(error) if error.is_not_found() => { /* bill belum ditemukan */ }
    Err(error) => eprintln!("request_id={:?}: {error}", error.request_id()),
}
}
```

Status dan waktu sudah typed: `BillStatus`, `UserStatus`, `WalletMutationStatus`,
`WalletTransactionType`, `Currency`, dan `time::OffsetDateTime`.

`external_user_id` pada `create_bill` hanya mengaitkan bill dengan user. Pembayaran bank
melalui callback mengkredit saldo merchant melalui alur payin yang sudah ada; bill tidak
otomatis melakukan top-up ke saldo user. Top-up user hanya terjadi melalui
`topup_user_wallet`.

Riwayat bill user dapat diambil dengan salah satu method berikut:

```rust
use nujek_payment::{Client, ListBillsQuery};

async fn user_bill_history(client: &Client) -> Result<(), Box<dyn std::error::Error>> {
let history = client.list_bills_for_user(
    "USER-001",
    ListBillsQuery { page: Some(1), per_page: Some(20), ..Default::default() },
).await?;
let bill = client.get_bill_for_user("bill-uuid", "USER-001").await?;
println!("{} {}", history.meta.total, bill.data.uuid);
Ok(())
}
```

`list_bills_for_user` dan `get_bill_for_user` mengirim header `X-External-User-Id`.
Alternatif path-based adalah `list_user_bills` dan `get_user_bill`.

## Live test staging

Example `live` memanggil endpoint SDK ke staging. Test read-only:

```bash
cp .env.example .env
# isi NUJEK_API_KEY dan NUJEK_API_SECRET pada .env
cargo run --example live
```

Untuk menguji endpoint onboarding dan bill QRIS, set `NUJEK_LIVE_TEST_WRITES=true`.
Ini membuat data nyata di staging. Mutasi wallet hanya dijalankan bila
`NUJEK_LIVE_TEST_WALLET=true`; gunakan hanya pada merchant test karena mengubah saldo.
`NUJEK_LIVE_TEST_QRIS_STATIC_ID` mengaktifkan test detail QRIS static.
Setelah onboarding selesai, isi `NUJEK_LIVE_TEST_EXTERNAL_USER_ID` untuk test user/wallet.
Untuk memeriksa token yang sudah ada, isi `NUJEK_LIVE_TEST_ONBOARDING_TOKEN`; revoke hanya
dijalankan bila `NUJEK_LIVE_TEST_REVOKE_ONBOARDING_TOKEN=true`.

File `.env` tidak dilacak Git dan kredensial asli tidak boleh dimasukkan ke `.env.example`.
Signature memakai `HMAC-SHA256(METHOD:path:unix_timestamp:raw_body)` dan dikirim dalam header API secara otomatis. Nominal memakai `rust_decimal::Decimal`. Nama crate: `nujek-payment`. Versi SDK saat ini: `0.9.1`.

`ListBillsQuery.status` memakai `BillStatus`, sedangkan `start_date` dan `end_date` memakai `time::OffsetDateTime` dan dikirim sebagai RFC3339. Detail QRIS memakai `QrisStaticPayment` typed, bukan JSON bebas.

## Validasi webhook

Setiap delivery webhook memiliki field top-level `event`. Contohnya `bill.paid`,
`user.onboarding.completed`, dan `webhook.test`. Callback `POST` dikirim ke URL webhook
yang dikonfigurasi pada API key yang memicu event.
Ambil `webhook_secret` dari konfigurasi API key di Portal dan simpan sebagai environment
variable (`NUJEK_WEBHOOK_SECRET`); jangan pernah memasukkannya ke source code atau log.

Setelah user menyelesaikan onboarding, redirect hanya membawa `external_user_id` dan
`status=success`. `onboarding_token` tidak dikirim lewat URL; event signed berikut dikirim
ke webhook API key yang membuat sesi:

```json
{
  "event": "user.onboarding.completed",
  "api_key_id": 15,
  "occurred_at": "2026-09-23T12:00:00Z",
  "data": {
    "external_user_id": "USER-001",
    "onboarding_token": "6f1a...",
    "wallet_status": "active"
  }
}
```

Gunakan `event` untuk memilih handler. Nilai `onboarding_token` hanya diproses setelah
signature webhook valid, dan dapat digunakan dengan `get_onboarding_session` atau revoke API.

Header yang dikirim:

- `X-Webhook-Timestamp`: waktu RFC3339, misalnya `2026-09-18T03:15:30.123Z`.
- `X-Webhook-Signature`: `sha256=<hex HMAC-SHA256>`.
- `X-Nujek-Webhook-Id`: ID delivery; simpan sebagai kunci idempotensi agar event retry
  tidak diproses dua kali.
- `X-API-Key`: API key yang terkait dengan bill, bila callback berasal dari API key tersebut.

Signature dihitung atas byte persis `"{X-Webhook-Timestamp}.{raw_body}"`. Jangan parse,
pretty-print, atau mengubah body sebelum validasi. Berikut contoh handler Axum:

```rust
use axum::{body::Bytes, http::{HeaderMap, StatusCode}};
use nujek_payment::verify_webhook_signature;
use std::env;
use time::OffsetDateTime;

async fn payment_webhook(headers: HeaderMap, body: Bytes) -> StatusCode {
    let timestamp = match headers.get("x-webhook-timestamp").and_then(|v| v.to_str().ok()) {
        Some(value) => value,
        None => return StatusCode::BAD_REQUEST,
    };
    let signature = match headers.get("x-webhook-signature").and_then(|v| v.to_str().ok()) {
        Some(value) => value,
        None => return StatusCode::UNAUTHORIZED,
    };
    let secret = match env::var("NUJEK_WEBHOOK_SECRET") {
        Ok(value) => value,
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR,
    };

    if !verify_webhook_signature(
        timestamp,
        &body,
        signature,
        &secret,
        OffsetDateTime::now_utc().unix_timestamp(),
        300,
    ) {
        return StatusCode::UNAUTHORIZED;
    }

    // Setelah signature valid, parse body dan proses event secara idempoten.
    let event: serde_json::Value = match serde_json::from_slice(&body) {
        Ok(value) => value,
        Err(_) => return StatusCode::BAD_REQUEST,
    };
    let delivery_id = headers.get("x-nujek-webhook-id").and_then(|v| v.to_str().ok());
    println!("received event={event}, delivery_id={delivery_id:?}");
    StatusCode::OK
}
```

Balas `2xx` hanya setelah event tercatat atau berhasil diproses. Respons `4xx` dianggap gagal
permanen; respons `5xx` atau timeout akan dicoba ulang. Tetap gunakan idempotensi berdasarkan
`X-Nujek-Webhook-Id` dan/atau `bill_id` karena delivery dapat terkirim lebih dari sekali.
