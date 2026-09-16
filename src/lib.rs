//! Async Rust client for payment-core's authenticated merchant API.

use hmac::{Hmac, Mac};
use reqwest::{Client as HttpClient, Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use rust_decimal::Decimal;
use time::OffsetDateTime;
use sha2::Sha256;
use std::{
    fmt,
    time::{SystemTime, UNIX_EPOCH},
};

type HmacSha256 = Hmac<Sha256>;

/// Creates the lowercase hexadecimal HMAC-SHA256 signature expected by the API.
/// The signed value is `METHOD:path:unix_timestamp:raw_body`; query strings are
/// intentionally excluded to match payment-core's middleware.
pub fn sign(
    method: &str,
    request_path: &str,
    timestamp: i64,
    body: &[u8],
    api_secret: &str,
) -> String {
    let message = format!(
        "{}:{}:{}:{}",
        method.to_uppercase(),
        request_path,
        timestamp,
        String::from_utf8_lossy(body)
    );
    let mut mac =
        HmacSha256::new_from_slice(api_secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(message.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

/// Verifies `X-Nujek-Signature` over `timestamp.raw_body` and rejects stale requests.
pub fn verify_webhook_signature(
    timestamp: i64,
    raw_body: &[u8],
    signature: &str,
    webhook_secret: &str,
    now: i64,
    max_age_seconds: i64,
) -> bool {
    if (now - timestamp).abs()
        > if max_age_seconds > 0 {
            max_age_seconds
        } else {
            300
        }
    {
        return false;
    }
    let expected = sign_webhook(timestamp, raw_body, webhook_secret);
    let provided = signature.strip_prefix("sha256=").unwrap_or(signature);
    let Ok(provided) = hex::decode(provided) else {
        return false;
    };
    provided.len() == expected.len()
        && provided
            .iter()
            .zip(expected.iter())
            .fold(0u8, |acc, (a, b)| acc | (a ^ b))
            == 0
}
fn sign_webhook(timestamp: i64, raw_body: &[u8], secret: &str) -> Vec<u8> {
    let mut mac =
        HmacSha256::new_from_slice(secret.as_bytes()).expect("HMAC accepts keys of any length");
    mac.update(format!("{}.", timestamp).as_bytes());
    mac.update(raw_body);
    mac.finalize().into_bytes().to_vec()
}

#[derive(Debug)]
pub enum Error {
    InvalidBaseUrl(url::ParseError),
    Request(reqwest::Error),
    Response {
        status: StatusCode,
        error_code: Option<String>,
        message: String,
        request_id: Option<String>,
        retry_after: Option<u64>,
        body: String,
    },
    Decode(serde_json::Error),
    InvalidEndpoint,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl(e) => write!(f, "nujek merchant API: invalid base URL: {e}"),
            Self::Request(e) => write!(f, "nujek merchant API: request failed: {e}"),
            Self::Response { status, error_code, message, request_id, .. } => {
                write!(f, "nujek payment API: HTTP {status}")?;
                if let Some(code) = error_code { write!(f, " [{code}]")?; }
                write!(f, ": {message}")?;
                if let Some(id) = request_id { write!(f, " (request_id={id})")?; }
                Ok(())
            }
            Self::Decode(e) => write!(f, "nujek merchant API: decode response: {e}"),
            Self::InvalidEndpoint => write!(f, "nujek merchant API: endpoint must start with /"),
        }
    }
}
impl std::error::Error for Error {}
impl Error {
    pub fn status(&self) -> Option<StatusCode> { match self { Self::Response { status, .. } => Some(*status), _ => None } }
    pub fn error_code(&self) -> Option<&str> { match self { Self::Response { error_code, .. } => error_code.as_deref(), _ => None } }
    pub fn request_id(&self) -> Option<&str> { match self { Self::Response { request_id, .. } => request_id.as_deref(), _ => None } }
    pub fn message(&self) -> Option<&str> { match self { Self::Response { message, .. } => Some(message), _ => None } }
    /// Returns a bounded response body suitable for diagnostics; request payloads are never stored here.
    pub fn body(&self) -> Option<&str> { match self { Self::Response { body, .. } => Some(body), _ => None } }
    pub fn retry_after(&self) -> Option<u64> { match self { Self::Response { retry_after, .. } => *retry_after, _ => None } }
    pub fn is_conflict(&self) -> bool { self.status() == Some(StatusCode::CONFLICT) }
    pub fn is_not_found(&self) -> bool { self.status() == Some(StatusCode::NOT_FOUND) }
    pub fn is_retryable(&self) -> bool {
        matches!(self.status(), Some(StatusCode::REQUEST_TIMEOUT | StatusCode::TOO_EARLY | StatusCode::TOO_MANY_REQUESTS))
            || self.status().is_some_and(|status| status.is_server_error())
    }
}

#[derive(Clone)]
pub struct Client {
    base_url: Url,
    api_key: String,
    api_secret: String,
    http: HttpClient,
}
impl Client {
    pub fn new(
        base_url: &str,
        api_key: impl Into<String>,
        api_secret: impl Into<String>,
    ) -> Result<Self, Error> {
        let base_url = Url::parse(base_url.trim_end_matches('/')).map_err(Error::InvalidBaseUrl)?;
        if base_url.scheme().is_empty() || base_url.host_str().is_none() {
            return Err(Error::InvalidBaseUrl(url::ParseError::EmptyHost));
        }
        Ok(Self {
            base_url,
            api_key: api_key.into(),
            api_secret: api_secret.into(),
            http: HttpClient::new(),
        })
    }
    pub fn with_http_client(mut self, http: HttpClient) -> Self {
        self.http = http;
        self
    }

    pub async fn request<T: DeserializeOwned>(
        &self,
        method: Method,
        endpoint: &str,
        body: Option<serde_json::Value>,
    ) -> Result<T, Error> {
        if !endpoint.starts_with('/') {
            return Err(Error::InvalidEndpoint);
        }
        let path = endpoint.split_once('?').map_or(endpoint, |(p, _)| p);
        let mut url = self.base_url.clone();
        url.set_path(&format!(
            "{}{}",
            self.base_url.path().trim_end_matches('/'),
            path
        ));
        if let Some((_, query)) = endpoint.split_once('?') {
            url.set_query(Some(query));
        }
        let has_body = body.is_some();
        let payload = body
            .map(|v| serde_json::to_vec(&v))
            .transpose()
            .map_err(Error::Decode)?
            .unwrap_or_default();
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;
        let signature = sign(method.as_str(), path, timestamp, &payload, &self.api_secret);
        let mut request = self
            .http
            .request(method, url)
            .header("X-Api-Key", &self.api_key)
            .header("X-Timestamp", timestamp.to_string())
            .header("X-Signature", signature);
        if has_body {
            request = request.header("Content-Type", "application/json");
        }
        let response = request.body(payload).send().await.map_err(Error::Request)?;
        let status = response.status();
        let request_id_header = response.headers().get("x-request-id").and_then(|v| v.to_str().ok()).map(str::to_owned);
        let retry_after_header = response.headers().get("retry-after").and_then(|v| v.to_str().ok()).and_then(|v| v.parse().ok());
        let bytes = response.bytes().await.map_err(Error::Request)?;
        if !status.is_success() {
            let body_text = String::from_utf8_lossy(&bytes).into_owned();
            let parsed: serde_json::Value = serde_json::from_slice(&bytes).unwrap_or_default();
            let message = parsed.get("message").and_then(|v| v.as_str())
                .or_else(|| parsed.get("error").and_then(|v| v.as_str()))
                .unwrap_or("API request failed").to_string();
            let error_code = parsed.get("error_code").and_then(|v| v.as_str()).map(str::to_owned)
                .or_else(|| parsed.get("code").and_then(|v| v.as_str()).map(str::to_owned));
            return Err(Error::Response {
                status,
                error_code,
                message,
                request_id: request_id_header,
                retry_after: retry_after_header,
                body: body_text.chars().take(4096).collect(),
            });
        }
        serde_json::from_slice(&bytes).map_err(Error::Decode)
    }

    pub async fn create_bill(&self, request: CreateBillRequest) -> Result<Envelope<Bill>, Error> {
        self.request(
            Method::POST,
            "/v1/bills",
            Some(serde_json::to_value(request).unwrap()),
        )
        .await
    }
    pub async fn create_user(&self, request: CreateUserRequest) -> Result<Envelope<UserCreated>, Error> {
        self.request(Method::POST, "/v1/users", Some(serde_json::to_value(request).map_err(Error::Decode)?)).await
    }
    pub async fn list_users(&self, query: PageQuery) -> Result<UserList, Error> {
        self.request(Method::GET, &format!("/v1/users?{query}"), None).await
    }
    pub async fn get_user(&self, external_user_id: &str) -> Result<Envelope<UserDetail>, Error> {
        self.request(Method::GET, &format!("/v1/users/{}", encode_path(external_user_id)), None).await
    }
    pub async fn get_user_wallet(&self, external_user_id: &str) -> Result<Envelope<UserWalletResponse>, Error> {
        self.request(Method::GET, &format!("/v1/users/{}/wallet", encode_path(external_user_id)), None).await
    }
    pub async fn topup_user_wallet(&self, external_user_id: &str, request: WalletMutationRequest) -> Result<Envelope<WalletMutationResponse>, Error> {
        self.mutate_user_wallet("topup", external_user_id, request).await
    }
    pub async fn debit_user_wallet(&self, external_user_id: &str, request: WalletMutationRequest) -> Result<Envelope<WalletMutationResponse>, Error> {
        self.mutate_user_wallet("debit", external_user_id, request).await
    }
    async fn mutate_user_wallet(&self, operation: &str, external_user_id: &str, request: WalletMutationRequest) -> Result<Envelope<WalletMutationResponse>, Error> {
        self.request(Method::POST, &format!("/v1/users/{}/{operation}", encode_path(external_user_id)), Some(serde_json::to_value(request).map_err(Error::Decode)?)).await
    }
    pub async fn user_history(&self, external_user_id: &str, query: PageQuery) -> Result<WalletTransactionList, Error> {
        self.request(Method::GET, &format!("/v1/users/{}/history?{query}", encode_path(external_user_id)), None).await
    }
    pub async fn user_wallet_transactions(&self, external_user_id: &str, query: PageQuery) -> Result<WalletTransactionList, Error> {
        self.request(Method::GET, &format!("/v1/users/{}/wallet/transactions?{query}", encode_path(external_user_id)), None).await
    }
    pub async fn lookup_wallet_transaction(&self, external_user_id: &str, reference_id: &str) -> Result<Envelope<WalletTransactionLookup>, Error> {
        let query = url::form_urlencoded::Serializer::new(String::new()).append_pair("reference_id", reference_id).finish();
        self.request(Method::GET, &format!("/v1/users/{}/wallet/transactions/by-reference?{query}", encode_path(external_user_id)), None).await
    }
    pub async fn get_bill(&self, id: &str) -> Result<Envelope<Bill>, Error> {
        self.request(Method::GET, &format!("/v1/bills/{id}"), None)
            .await
    }
    pub async fn get_bill_by_external_id(&self, external_id: &str) -> Result<Envelope<Bill>, Error> {
        self.request(Method::GET, &format!("/v1/bills/by-external-id/{}", encode_path(external_id)), None).await
    }
    pub async fn list_bills(&self, query: ListBillsQuery) -> Result<BillList, Error> {
        self.request(Method::GET, &format!("/v1/bills?{query}"), None)
            .await
    }
    pub async fn create_payout(&self, request: CreatePayoutRequest) -> Result<Payout, Error> {
        self.request(
            Method::POST,
            "/v1/payouts",
            Some(serde_json::to_value(request).unwrap()),
        )
        .await
    }
    pub async fn balance(&self) -> Result<Envelope<Balance>, Error> {
        self.request(Method::GET, "/v1/balance", None).await
    }
    pub async fn list_qris_static(&self) -> Result<Envelope<Vec<QrisStatic>>, Error> {
        self.request(Method::GET, "/v1/qris-static", None).await
    }
    pub async fn get_qris_static(&self, id: &str) -> Result<Envelope<QrisStaticDetail>, Error> {
        self.request(Method::GET, &format!("/v1/qris-static/{id}"), None)
            .await
    }
}

fn encode_path(value: &str) -> String {
    url::form_urlencoded::byte_serialize(value.as_bytes()).collect()
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub data: T,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BillStatus {
    Pending,
    Paid,
    Settled,
    Expired,
    #[serde(other)]
    Unknown,
}

impl BillStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Paid => "paid",
            Self::Settled => "settled",
            Self::Expired => "expired",
            Self::Unknown => "unknown",
        }
    }
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    Active,
    Inactive,
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum WalletMutationStatus {
    Completed,
    Pending,
    Failed,
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum Currency {
    #[serde(rename = "IDR")]
    Idr,
    #[serde(rename = "USD")]
    Usd,
    #[serde(rename = "EUR")]
    Eur,
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum QrisStatus {
    Active,
    Inactive,
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PayoutStatus {
    Pending,
    Processing,
    Success,
    Failed,
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBillRequest {
    pub external_id: String,
    pub channel_id: String,
    pub total: Decimal,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Currency>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<OffsetDateTime>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_user_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateUserRequest {
    pub external_user_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub phone: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct MerchantUser {
    pub id: i64,
    pub uuid: String,
    pub merchant_id: i64,
    pub external_user_id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: UserStatus,
    pub created_at: Option<OffsetDateTime>,
    pub updated_at: Option<OffsetDateTime>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserWallet {
    pub available: Decimal,
    pub pending: Decimal,
    pub locked: Decimal,
    pub currency: Currency,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserCreated {
    pub user: MerchantUser,
    pub wallet: UserWallet,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserDetail {
    pub user: MerchantUser,
    pub wallet: UserWallet,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserWalletResponse {
    pub external_user_id: String,
    pub wallet: UserWallet,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserListItem {
    pub id: i64,
    pub uuid: String,
    pub external_user_id: String,
    pub name: Option<String>,
    pub email: Option<String>,
    pub phone: Option<String>,
    pub status: UserStatus,
    pub available: Decimal,
    pub pending: Decimal,
    pub locked: Decimal,
    pub created_at: Option<OffsetDateTime>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct UserList {
    pub data: Vec<UserListItem>,
    pub meta: Pagination,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletMutationRequest {
    pub amount: Decimal,
    pub reference_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletMutationResponse {
    pub transaction_id: String,
    pub external_user_id: String,
    pub amount: Decimal,
    pub balance_before: Decimal,
    pub balance_after: Decimal,
    pub status: WalletMutationStatus,
    pub reference_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletTransactionLookup {
    pub transaction_id: String,
    pub reference_id: String,
    pub operation: WalletTransactionType,
    pub amount: Decimal,
    pub balance_before: Decimal,
    pub balance_after: Decimal,
    pub status: WalletMutationStatus,
    pub created_at: Option<OffsetDateTime>,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WalletTransactionType {
    Topup,
    Debit,
    Transfer,
    Payin,
    Payout,
    Settlement,
    Correction,
    #[serde(other)]
    Unknown,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletTransaction {
    pub id: i64,
    pub uuid: String,
    pub idempotency_key: String,
    pub reference_id: String,
    #[serde(rename = "type")]
    pub transaction_type: WalletTransactionType,
    pub description: Option<String>,
    pub created_at: Option<OffsetDateTime>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct WalletTransactionList {
    pub data: Vec<WalletTransaction>,
    pub meta: Pagination,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct PageQuery {
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}
impl fmt::Display for PageQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(value) = self.page { query.append_pair("page", &value.to_string()); }
        if let Some(value) = self.per_page { query.append_pair("per_page", &value.to_string()); }
        f.write_str(&query.finish())
    }
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePayoutRequest {
    pub external_id: String,
    pub destination_bank: String,
    pub destination_account: String,
    pub destination_name: String,
    pub amount: Decimal,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<Currency>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Bill {
    pub uuid: String,
    pub external_id: String,
    pub channel_id: Option<String>,
    pub total: Option<Decimal>,
    pub total_fee: Option<Decimal>,
    pub net_amount: Option<Decimal>,
    pub currency: Option<Currency>,
    pub status: BillStatus,
    pub bank_reference_no: Option<String>,
    pub payment_value: Option<String>,
    pub bank_status: Option<String>,
    pub paid_at: Option<OffsetDateTime>,
    pub expired_at: Option<OffsetDateTime>,
    pub created_at: Option<OffsetDateTime>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct BillList {
    pub data: Vec<Bill>,
    pub meta: Pagination,
}
#[derive(Debug, Serialize, Deserialize, Default)]
pub struct Pagination {
    pub page: i64,
    pub per_page: i64,
    pub total: i64,
    pub total_pages: i64,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Payout {
    pub id: i64,
    pub uuid: String,
    pub external_id: String,
    pub amount: Decimal,
    pub fee: Decimal,
    pub status: PayoutStatus,
    pub created_at: OffsetDateTime,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub merchant_id: i64,
    pub balances: std::collections::BTreeMap<String, Decimal>,
    pub currency: Currency,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct QrisStatic {
    pub id: i64,
    pub uuid: String,
    pub merchant_id: Option<i64>,
    pub provider: String,
    pub nmid: String,
    pub qr_string: String,
    pub reference_no: Option<String>,
    pub store_id: String,
    pub terminal_id: String,
    pub fee_percent: Decimal,
    pub status: QrisStatus,
    pub created_at: OffsetDateTime,
    pub updated_at: OffsetDateTime,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct QrisStaticDetail {
    pub qris_static: QrisStatic,
    pub total_received: Decimal,
    pub payments: Vec<QrisStaticPayment>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct QrisStaticPayment {
    pub id: i64,
    pub uuid: String,
    pub qris_static_id: i64,
    pub amount: Decimal,
    pub currency: Option<Currency>,
    pub bank_reference_no: Option<String>,
    pub payment_reference_no: Option<String>,
    pub payer_name: Option<String>,
    pub paid_at: Option<OffsetDateTime>,
    pub bill_id: Option<i64>,
    pub created_at: OffsetDateTime,
}

#[derive(Debug, Default)]
pub struct ListBillsQuery {
    pub start_date: Option<OffsetDateTime>,
    pub end_date: Option<OffsetDateTime>,
    pub status: Option<BillStatus>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
    pub channel_id: Option<String>,
    pub search: Option<String>,
}
impl fmt::Display for ListBillsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(v) = &self.start_date {
            if let Ok(value) = v.format(&time::format_description::well_known::Rfc3339) {
                query.append_pair("start_date", &value);
            }
        }
        if let Some(v) = &self.end_date {
            if let Ok(value) = v.format(&time::format_description::well_known::Rfc3339) {
                query.append_pair("end_date", &value);
            }
        }
        if let Some(v) = &self.status {
            query.append_pair("status", v.as_str());
        }
        if let Some(v) = self.page {
            query.append_pair("page", &v.to_string());
        }
        if let Some(v) = self.per_page {
            query.append_pair("per_page", &v.to_string());
        }
        if let Some(v) = &self.channel_id { query.append_pair("channel_id", v); }
        if let Some(v) = &self.search { query.append_pair("search", v); }
        f.write_str(&query.finish())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn signature_matches_server_format() {
        assert_eq!(
            sign(
                "post",
                "/v1/bills",
                1700000000,
                br#"{"total":100}"#,
                "secret"
            ),
            "c2e34a3fb4e021e233b322a7ddd7496f5e5bf7799dfbd1dc4c88c2ee24d14f3c"
        );
    }
    #[test]
    fn query_is_encoded() {
        let q = ListBillsQuery {
            status: Some(BillStatus::Paid),
            page: Some(2),
            ..Default::default()
        };
        assert_eq!(q.to_string(), "status=paid&page=2");
    }
    #[test]
    fn webhook_signature_is_verified() {
        let body = br#"{"event":"bill.paid"}"#;
        let mut mac = HmacSha256::new_from_slice(b"whsec_test").unwrap();
        mac.update(b"1700000000.");
        mac.update(body);
        let signature = format!("sha256={}", hex::encode(mac.finalize().into_bytes()));
        assert!(verify_webhook_signature(
            1700000000,
            body,
            &signature,
            "whsec_test",
            1700000000,
            300
        ));
    }
}
