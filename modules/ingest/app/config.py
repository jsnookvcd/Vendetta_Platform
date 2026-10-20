"""Telemetry Ingest configuration. Values come from the environment.

Telemetry Ingest is the SOC's front door for data. Connectors read each client's
own security tools (EDR, identity, email, cloud, SaaS, network); every record is
normalized once to the Open Cybersecurity Schema Framework (OCSF), stamped with the
client's platform id, and sealed into a signed Merkle batch so any event can later
be proven to have arrived exactly as it is shown. Streaming Sigma rules run over the
normalized events, and detections are served in the shared finding model for MDR.
"""
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")

    app_name: str = "Vendetta Telemetry Ingest"
    module_enabled: bool = True
    internal_email_domains: str = "vendettacd.io"
    admin_emails: str = ""
    database_url: str = "postgresql+psycopg://ingest:ingest@db:5432/ingest"
    secret_key: str = "change-me"
    api_token: str = ""
    allow_insecure_defaults: bool = False
    # Ed25519 private key (32 bytes hex) that signs every sealed batch of telemetry.
    # Blank derives a stable key from secret_key; production sets a dedicated key.
    evidence_signing_key: str = ""
    encryption_key: str = ""
    cookie_secure: bool = False
    public_url: str = ""
    login_max_attempts: int = 8
    login_window_seconds: int = 300
    admin_user: str = "admin"
    admin_password_hash: str = ""

    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_url: str = ""
    entra_allowed_group: str = ""
    entra_allowed_emails: str = ""

    @property
    def oidc_enabled(self) -> bool:
        return bool(self.entra_client_id and self.entra_tenant_id)

    platform_hub_url: str = ""
    platform_hub_token: str = ""
    platform_url: str = ""
    platform_token: str = ""
    platform_public_url: str = ""
    provision_interval_seconds: int = 300

    # Background work this process runs: any of connectors, stream, seal, bucket, or
    # "all". The ECS services split them (ingest-worker runs connectors,seal,bucket;
    # ingest-stream runs stream); docker compose runs all of them in one process.
    worker_roles: str = "all"

    # ---------------------------------------------------------------- pipeline
    # Seconds between seal runs. Each run seals every tenant's unsealed events into
    # one signed batch per tenant (0 disables the schedule; POST /api/seal still works).
    seal_interval_seconds: int = 60
    # Largest batch a single seal writes. A busier tenant gets several batches.
    seal_max_events: int = 20000
    # Seconds between connector polling rounds (0 disables the schedule).
    connector_interval_seconds: int = 300
    # Seconds between streaming detection passes (0 disables the schedule).
    stream_interval_seconds: int = 30
    # How long normalized events stay in the module's own hot store. The raw archive
    # and the lake keep them for the client's retention period; batch headers are
    # never deleted, so a proof can always be checked against the chain.
    hot_retention_days: int = 30
    # Largest single raw record accepted (bytes of JSON). Larger records are rejected
    # and counted, never truncated, because a truncated record cannot be proven.
    max_record_bytes: int = 262144
    # Largest push body and the most records one push may carry.
    max_push_bytes: int = 5_000_000
    max_push_records: int = 5000

    # ---------------------------------------------------------------- AWS sinks
    # All optional. With none set the module keeps everything in its own Postgres,
    # which is how development and the test suite run.
    aws_region: str = "us-east-1"
    kinesis_stream: str = ""
    raw_bucket: str = ""
    bucket_feed_queue_url: str = ""
    tenant_secret_prefix: str = "vcd/ingest/tenants/"
    # Buckets the bucket door may read (comma separated). Empty means the door is off.
    bucket_allowlist: str = ""
    # Evidence account bucket (Object Lock, compliance mode) for daily chain anchors.
    anchor_bucket: str = ""
    # OpenSearch hot tier. Signed with the task role when on AWS.
    opensearch_url: str = ""
    opensearch_index_prefix: str = "vcd-soc"

    # Optional RFC 3161 Time-Stamp Authority applied to each daily anchor.
    tsa_url: str = ""


settings = Settings()

SEVERITIES = ["low", "medium", "high", "critical"]
SEV_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
WORKSTREAM = "Scoping and Containment"
FINDING_STATUSES = ["new", "reviewing", "confirmed", "false_positive", "closed"]
OPEN_FINDING_STATUSES = ["new", "reviewing", "confirmed"]
