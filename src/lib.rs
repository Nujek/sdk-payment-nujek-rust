//! Async Rust client for payment-core's authenticated merchant API.

use hmac::{Hmac, Mac};
use reqwest::{Client as HttpClient, Method, StatusCode, Url};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
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

#[derive(Debug)]
pub enum Error {
    InvalidBaseUrl(url::ParseError),
    Request(reqwest::Error),
    Response { status: StatusCode, body: String },
    Decode(serde_json::Error),
    InvalidEndpoint,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidBaseUrl(e) => write!(f, "nujek merchant API: invalid base URL: {e}"),
            Self::Request(e) => write!(f, "nujek merchant API: request failed: {e}"),
            Self::Response { status, body } => {
                write!(f, "nujek merchant API: HTTP {status}: {body}")
            }
            Self::Decode(e) => write!(f, "nujek merchant API: decode response: {e}"),
            Self::InvalidEndpoint => write!(f, "nujek merchant API: endpoint must start with /"),
        }
    }
}
impl std::error::Error for Error {}

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
        let bytes = response.bytes().await.map_err(Error::Request)?;
        if !status.is_success() {
            return Err(Error::Response {
                status,
                body: String::from_utf8_lossy(&bytes).into_owned(),
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
    pub async fn get_bill(&self, id: &str) -> Result<Envelope<Bill>, Error> {
        self.request(Method::GET, &format!("/v1/bills/{id}"), None)
            .await
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

#[derive(Debug, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub data: T,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CreateBillRequest {
    pub external_id: String,
    pub channel_id: String,
    pub total: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expired_at: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CreatePayoutRequest {
    pub external_id: String,
    pub destination_bank: String,
    pub destination_account: String,
    pub destination_name: String,
    pub amount: serde_json::Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub currency: Option<String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Bill {
    pub uuid: String,
    pub external_id: String,
    pub channel_id: Option<String>,
    pub total: Option<serde_json::Value>,
    pub total_fee: Option<serde_json::Value>,
    pub net_amount: Option<serde_json::Value>,
    pub currency: Option<String>,
    pub status: String,
    pub bank_reference_no: Option<String>,
    pub payment_value: Option<String>,
    pub bank_status: Option<String>,
    pub paid_at: Option<String>,
    pub expired_at: Option<String>,
    pub created_at: Option<String>,
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
    pub amount: serde_json::Value,
    pub fee: serde_json::Value,
    pub status: String,
    pub created_at: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Balance {
    pub merchant_id: i64,
    pub balances: serde_json::Map<String, serde_json::Value>,
    pub currency: String,
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
    pub fee_percent: serde_json::Value,
    pub status: String,
    pub created_at: String,
    pub updated_at: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct QrisStaticDetail {
    pub qris_static: QrisStatic,
    pub total_received: serde_json::Value,
    pub payments: Vec<serde_json::Value>,
}

#[derive(Debug, Default)]
pub struct ListBillsQuery {
    pub start_date: Option<String>,
    pub end_date: Option<String>,
    pub status: Option<String>,
    pub page: Option<i64>,
    pub per_page: Option<i64>,
}
impl fmt::Display for ListBillsQuery {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut query = url::form_urlencoded::Serializer::new(String::new());
        if let Some(v) = &self.start_date {
            query.append_pair("start_date", v);
        }
        if let Some(v) = &self.end_date {
            query.append_pair("end_date", v);
        }
        if let Some(v) = &self.status {
            query.append_pair("status", v);
        }
        if let Some(v) = self.page {
            query.append_pair("page", &v.to_string());
        }
        if let Some(v) = self.per_page {
            query.append_pair("per_page", &v.to_string());
        }
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
            status: Some("pending paid".into()),
            page: Some(2),
            ..Default::default()
        };
        assert_eq!(q.to_string(), "status=pending+paid&page=2");
    }
}
