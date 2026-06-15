"""Twilio connector record type constants — M79A.

M79A scope (drift foundation)
------------------------------
Five safe drift surfaces ingested in the initial Twilio connector milestone:

    twilio_account                  — account metadata (status, type, friendly
                                      name truncated; SID stored as prefix only)
    twilio_incoming_phone_number    — phone number configuration posture (last-4
                                      digits only; webhook URLs as booleans;
                                      capabilities, address requirements,
                                      emergency status)
    twilio_messaging_service        — Messaging Service configuration posture
                                      (URL presence as booleans; smart encoding,
                                      validity period, geomatch, sticky sender,
                                      MMS converter, number count)
    twilio_verify_service           — Verify Service configuration posture (code
                                      length, lookup/PSD2/landline-skip flags,
                                      default template presence)
    twilio_api_key_summary          — API key metadata summary (SID, friendly
                                      name, dates; secret is NEVER stored)

Privacy contract
----------------
SECURITY: in M79A no auth_token, API secret, full phone number, webhook URL
string, message body, call log, customer data, raw API response, or any
re-identifying field is ever stored on a normalised record.

Never stored:
  - auth_token or any API secret / private key material
  - full phone numbers (only the last 4 digits are kept)
  - webhook / callback URL strings (stored as bool: configured or not)
  - message bodies, call SIDs, call legs, recording data
  - customer PII (caller name, call metadata, SMS content)
  - raw Twilio API response dicts
  - sub-account auth tokens
"""
from __future__ import annotations

from typing import TypedDict

# ── M79A record type string constants ─────────────────────────────────────────

# One per Twilio account — top-level account posture.
# SECURITY: auth_token is NEVER stored. SID is stored as prefix only (first 8
# chars). Subaccount credentials are never fetched or stored.
TWILIO_ACCOUNT = "twilio_account"

# One per incoming phone number — number configuration posture.
# SECURITY: full phone number is NEVER stored — only the last 4 digits.
# Webhook URL strings are NEVER stored — only boolean presence flags.
TWILIO_INCOMING_PHONE_NUMBER = "twilio_incoming_phone_number"

# One per Messaging Service — service configuration posture.
# SECURITY: webhook URL strings (inbound_request_url, fallback_url,
# status_callback_url) are NEVER stored — only boolean presence flags.
# Message bodies and sender information are never accessed.
TWILIO_MESSAGING_SERVICE = "twilio_messaging_service"

# One per Verify Service — service configuration posture.
# SECURITY: template content, PII verification targets, and customer
# verification codes are NEVER stored. Only safe config metadata is kept.
TWILIO_VERIFY_SERVICE = "twilio_verify_service"

# One per API key — key metadata only.
# SECURITY: the API key secret is NEVER stored — only the SID, friendly name,
# and creation/update timestamps (opaque metadata).
TWILIO_API_KEY_SUMMARY = "twilio_api_key_summary"

# ── Aggregate set ─────────────────────────────────────────────────────────────

TWILIO_RECORD_TYPES: frozenset[str] = frozenset({
    TWILIO_ACCOUNT,
    TWILIO_INCOMING_PHONE_NUMBER,
    TWILIO_MESSAGING_SERVICE,
    TWILIO_VERIFY_SERVICE,
    TWILIO_API_KEY_SUMMARY,
})


# ── TypedDicts ────────────────────────────────────────────────────────────────


class TwilioAccountRecord(TypedDict):
    """Safe normalised record for a Twilio account (M79A).

    SECURITY: auth_token is NEVER a field here. account_sid_prefix is the
    first 8 characters of the account SID only — not the full SID. The full
    SID is used solely as an API path parameter inside the connector and is
    never written to this record.
    """

    record_type: str            # always "twilio_account"
    record_id: str              # f"twilio_account_{account_sid_prefix}"
    provider_resource_id: str   # f"accounts/{account_sid_prefix}"
    account_sid_prefix: str     # first 8 chars of account SID only
    friendly_name: str          # truncated to 100 chars
    status: str                 # "active" | "suspended" | "closed" | "unknown"
    account_type: str           # "Full" | "Trial" | "unknown"
    subaccount_count: int       # count of sub-accounts (0 if unavailable)


class TwilioIncomingPhoneNumberRecord(TypedDict):
    """Safe normalised record for a Twilio incoming phone number (M79A).

    SECURITY: the full phone number string is NEVER stored — only the last 4
    digits (phone_number_last4). Webhook URL strings are NEVER stored — only
    boolean flags indicating whether they are configured.
    """

    record_type: str            # always "twilio_incoming_phone_number"
    record_id: str              # the phone number SID (e.g. "PN...")
    provider_resource_id: str   # f"incoming_phone_numbers/{sid}"
    phone_number_sid: str       # the phone number SID
    friendly_name: str          # truncated to 100 chars
    phone_number_last4: str     # last 4 characters of the E.164 number only
    iso_country: str            # ISO 3166-1 alpha-2 country code
    capability_voice: bool      # whether voice is enabled
    capability_sms: bool        # whether SMS is enabled
    capability_mms: bool        # whether MMS is enabled
    capability_fax: bool        # whether Fax is enabled
    sms_url_configured: bool    # bool(sms_url) — URL string is NEVER stored
    voice_url_configured: bool  # bool(voice_url) — URL string is NEVER stored
    status_callback_configured: bool  # bool(status_callback)
    address_requirements: str   # "none" | "local" | "foreign" | "any"
    emergency_status: str       # "Active" | "Inactive" | ""


class TwilioMessagingServiceRecord(TypedDict):
    """Safe normalised record for a Twilio Messaging Service (M79A).

    SECURITY: webhook URL strings (inbound_request_url, fallback_url,
    status_callback_url) are NEVER stored — only boolean presence flags.
    Message content and sender identities are never accessed.
    """

    record_type: str                        # always "twilio_messaging_service"
    record_id: str                          # the Messaging Service SID
    provider_resource_id: str              # f"messaging_services/{sid}"
    messaging_service_sid: str             # the Messaging Service SID
    friendly_name: str                     # truncated to 100 chars
    inbound_request_url_configured: bool   # bool(inbound_request_url)
    fallback_url_configured: bool          # bool(fallback_url)
    status_callback_url_configured: bool   # bool(status_callback_url)
    smart_encoding: bool                   # smart encoding enabled
    validity_period: int                   # message validity period in seconds
    area_code_geomatch: bool               # area code geomatch enabled
    sticky_sender: bool                    # sticky sender enabled
    mms_converter: bool                    # MMS converter enabled
    use_inbound_webhook_on_number: bool    # use inbound webhook on number
    number_count: int                      # count of phone numbers in service


class TwilioVerifyServiceRecord(TypedDict):
    """Safe normalised record for a Twilio Verify Service (M79A).

    SECURITY: template content, PII verification payloads, and customer
    verification codes are NEVER stored. Only safe configuration metadata is
    kept. default_template_sid_present is a bool — the SID itself is not stored.
    """

    record_type: str                        # always "twilio_verify_service"
    record_id: str                          # the Verify Service SID
    provider_resource_id: str              # f"verify_services/{sid}"
    verify_service_sid: str                # the Verify Service SID
    friendly_name: str                     # truncated to 100 chars
    code_length: int                       # OTP code length (digits)
    lookup_enabled: bool                   # phone number lookup enabled
    psd2_enabled: bool                     # PSD2 / SCA enabled
    do_not_share_warning_enabled: bool     # "do not share" warning shown
    skip_sms_to_landlines: bool            # skip SMS delivery to landlines
    default_template_sid_present: bool     # bool(default_template_sid)


class TwilioApiKeySummaryRecord(TypedDict):
    """Safe normalised record for a Twilio API key (M79A).

    SECURITY: the API key secret is NEVER stored — only the SID (opaque
    identifier), friendly name, and creation / update timestamps.
    """

    record_type: str            # always "twilio_api_key_summary"
    record_id: str              # the API key SID (e.g. "SK...")
    provider_resource_id: str   # f"api_keys/{sid}"
    api_key_sid: str            # the API key SID
    friendly_name: str          # truncated to 100 chars
    date_created: str           # ISO 8601 creation timestamp (opaque)
    date_updated: str           # ISO 8601 last-updated timestamp (opaque)
