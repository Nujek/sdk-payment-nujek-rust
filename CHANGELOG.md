# Changelog

## 0.6.0

- Added structured API errors with status, error code, request ID, retry-after, and bounded response body.
- Added `is_retryable`, `is_conflict`, and `is_not_found` helpers.
- Added typed `BillStatus`, `UserStatus`, wallet mutation/transaction status, currency, and timestamps using `time::OffsetDateTime`.
- Monetary fields use `rust_decimal::Decimal`.
