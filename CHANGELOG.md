# Changelog

## 0.8.2

- Added a credential-driven live staging example covering SDK endpoints.
- Added `.env.example` for safe live-test configuration.
- Decode user-list responses from deployed API versions that omit a zero `pending` balance.
- Corrected webhook verification to match the RFC3339 timestamp and headers sent by the API.

## 0.8.1

- Fixed user wallet top-up and debit routes to use `/wallet/{operation}`.
- Added bill history and detail methods scoped by external user ID.
- Re-exported `Duration` and `OffsetDateTime` for request construction.

## 0.8.0

- **Breaking:** `CreateBillRequest.expired_at` is required and encoded as RFC3339.
- Decode the `/v1` structured error envelope into `Error::Response` code and message.

## 0.7.1

- Fixed RFC3339 decoding for API response timestamps.
- Allow omitted optional bill fields in create-bill responses.

## 0.7.0

- Typed `ListBillsQuery.status` with `BillStatus`.
- Typed bill date filters with `time::OffsetDateTime` encoded as RFC3339.
- Replaced free-form QRIS payment JSON with `QrisStaticPayment`.

## 0.6.0

- Added structured API errors with status, error code, request ID, retry-after, and bounded response body.
- Added `is_retryable`, `is_conflict`, and `is_not_found` helpers.
- Added typed `BillStatus`, `UserStatus`, wallet mutation/transaction status, currency, and timestamps using `time::OffsetDateTime`.
- Monetary fields use `rust_decimal::Decimal`.
