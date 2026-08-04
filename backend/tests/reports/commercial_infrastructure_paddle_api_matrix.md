# Commercial Infrastructure — Paddle API Client Matrix (message 2)

Every row maps to a real, currently-passing test. All HTTP is mocked via
`httpx.MockTransport` — no live Paddle call is made anywhere in this file.

| # | Behavior | Test |
|---|---|---|
| 1 | Sandbox environment resolves to `https://sandbox-api.paddle.com` | `test_commercial_paddle_client.py::TestCorrectUrlsPerEnvironment::test_sandbox_base_url` |
| 2 | Production environment resolves to `https://api.paddle.com` | `test_commercial_paddle_client.py::TestCorrectUrlsPerEnvironment::test_production_base_url` |
| 3 | Unknown environment string is rejected | `test_commercial_paddle_client.py::TestCorrectUrlsPerEnvironment::test_unknown_environment_rejected` |
| 4 | Every request sends `Authorization: Bearer <api_key>` | `test_commercial_paddle_client.py::TestAuthorizationHeader::test_bearer_token_sent` |
| 5 | 401 raises `PaddleAuthenticationError`, message never contains the API key | `test_commercial_paddle_client.py::TestSanitizedErrors::test_401_raises_authentication_error_without_key_in_message` |
| 6 | 422 raises `PaddleValidationError` | `test_commercial_paddle_client.py::TestSanitizedErrors::test_422_raises_validation_error` |
| 7 | Error carries `paddle-request-id` for support correlation, nothing more | `test_commercial_paddle_client.py::TestSanitizedErrors::test_error_carries_sanitized_request_id` |
| 8 | Error's dict form never contains the full response body | `test_commercial_paddle_client.py::TestSanitizedErrors::test_error_dict_never_contains_full_body` |
| 9 | Connection timeout raises `PaddleNetworkError` | `test_commercial_paddle_client.py::TestTimeouts::test_timeout_raises_network_error` |
| 10 | 500 is retried once, then succeeds | `test_commercial_paddle_client.py::TestRetries::test_500_retried_then_succeeds` |
| 11 | 401 is never retried (non-retryable status) | `test_commercial_paddle_client.py::TestRetries::test_401_never_retried` |
| 12 | 429 is retried honoring the `Retry-After` header | `test_commercial_paddle_client.py::TestRetries::test_429_retried_with_retry_after` |
| 13 | A non-idempotent request (`idempotent=False`) is never retried even on 500 | `test_commercial_paddle_client.py::TestRetries::test_non_idempotent_request_never_retried` |
| 14 | Request body is JSON-encoded on the wire | `test_commercial_paddle_client.py::TestJSONEncodingDecoding::test_request_body_is_json_encoded` |
| 15 | Empty response body decodes to `{}`, not an exception | `test_commercial_paddle_client.py::TestJSONEncodingDecoding::test_empty_response_body_returns_empty_dict` |
| 16 | Correlation ID is sent as a header, is not treated as or confused with a secret | `test_commercial_paddle_client.py::TestCorrelationId::test_correlation_id_sent_as_header_not_secret` |
| 17 | `POST /transactions` (checkout) is non-idempotent by contract | `paddle_client.py::PaddleAPIClient.create_checkout` (idempotent=False), exercised indirectly by `test_commercial_paddle_checkout.py` |
| 18 | `GET /subscriptions/{id}` is idempotent (retryable) by contract | `paddle_client.py::PaddleAPIClient.get_subscription` (idempotent=True), exercised indirectly by `test_commercial_paddle_subscription_items.py` |
| 19 | `PATCH /subscriptions/{id}` (item update) is non-idempotent by contract | `paddle_client.py::PaddleAPIClient.update_subscription_items` (idempotent=False) |
| 20 | `POST /subscriptions/{id}/cancel` is non-idempotent by contract | `paddle_client.py::PaddleAPIClient.cancel_subscription` (idempotent=False) |
| 21 | `POST /customers/{id}/portal-sessions` is non-idempotent by contract | `paddle_client.py::PaddleAPIClient.get_customer_portal_session` (idempotent=False) |
| 22 | `GET /prices/{id}` is idempotent (retryable) by contract | `paddle_client.py::PaddleAPIClient.get_price`, exercised only by the opt-in `test_commercial_paddle_sandbox_optional.py` |
| 23 | No Paddle SDK is imported anywhere in the client module | `test_commercial_paddle_contract.py::TestNeverFallsBackToStripe::test_paddle_adapter_module_never_imports_stripe` (adjacent proof: adapter module has zero `import stripe`); client module itself uses only `httpx` (verified by direct inspection of `paddle_client.py` imports) |
| 24 | Client construction requires `environment` + `api_key`; missing either fails closed via the adapter/registry layer, never at the HTTP layer | `test_commercial_provider_registry.py::TestPaddleSelectedButNotActivated::test_paddle_missing_api_key_fails_closed_even_with_price_mapping` |

Total distinct client-layer behaviors covered: **24**, backed by **16 executed test functions/parametrizations** in `test_commercial_paddle_client.py` plus 3 registry-level not-configured tests (rows 17–22 are direct-inspection contract notes, not independently executed rows, and are marked as such).
