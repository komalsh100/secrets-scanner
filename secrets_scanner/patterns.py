"""
Secret patterns for detection.
Covers 20+ secret types with severity classification.
"""

SECRET_PATTERNS = [
    # ── Critical ──────────────────────────────────────────────────────────────
    {
        "name": "AWS Access Key ID",
        "pattern": r"(?i)(AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
        "severity": "CRITICAL",
        "description": "Amazon Web Services Access Key ID"
    },
    {
        "name": "AWS Secret Access Key",
        "pattern": r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
        "severity": "CRITICAL",
        "description": "Amazon Web Services Secret Access Key"
    },
    {
        "name": "Private Key (RSA/EC/DSA)",
        "pattern": r"-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY( BLOCK)?-----",
        "severity": "CRITICAL",
        "description": "Private cryptographic key material"
    },
    {
        "name": "Google API Key",
        "pattern": r"AIza[0-9A-Za-z\-_]{35}",
        "severity": "CRITICAL",
        "description": "Google API Key"
    },
    {
        "name": "Google OAuth Client Secret",
        "pattern": r"(?i)google.{0,20}client.secret.{0,10}['\"][a-zA-Z0-9_\-]{24}['\"]",
        "severity": "CRITICAL",
        "description": "Google OAuth2 Client Secret"
    },
    {
        "name": "Stripe Secret Key",
        "pattern": r"sk_(live|test)_[0-9a-zA-Z]{24,}",
        "severity": "CRITICAL",
        "description": "Stripe payment secret key"
    },
    {
        "name": "GitHub Personal Access Token",
        "pattern": r"ghp_[0-9a-zA-Z]{36}",
        "severity": "CRITICAL",
        "description": "GitHub Personal Access Token"
    },
    {
        "name": "GitHub OAuth Token",
        "pattern": r"gho_[0-9a-zA-Z]{36}",
        "severity": "CRITICAL",
        "description": "GitHub OAuth Token"
    },
    {
        "name": "GitHub Actions Token",
        "pattern": r"ghs_[0-9a-zA-Z]{36}",
        "severity": "CRITICAL",
        "description": "GitHub Actions Token"
    },
    {
        "name": "Slack Bot Token",
        "pattern": r"xoxb-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{24}",
        "severity": "CRITICAL",
        "description": "Slack Bot Token"
    },
    {
        "name": "Slack User Token",
        "pattern": r"xoxp-[0-9]{11}-[0-9]{11}-[0-9]{11}-[0-9a-zA-Z]{32}",
        "severity": "CRITICAL",
        "description": "Slack User OAuth Token"
    },
    {
        "name": "Twilio API Key",
        "pattern": r"SK[0-9a-fA-F]{32}",
        "severity": "CRITICAL",
        "description": "Twilio API Key SID"
    },
    {
        "name": "SendGrid API Key",
        "pattern": r"SG\.[0-9A-Za-z\-_]{22}\.[0-9A-Za-z\-_]{43}",
        "severity": "CRITICAL",
        "description": "SendGrid API Key"
    },
    {
        "name": "Mailgun API Key",
        "pattern": r"key-[0-9a-zA-Z]{32}",
        "severity": "CRITICAL",
        "description": "Mailgun API Key"
    },
    # ── High ──────────────────────────────────────────────────────────────────
    {
        "name": "JWT Token",
        "pattern": r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9._-]{10,}\.[A-Za-z0-9._-]{10,}",
        "severity": "HIGH",
        "description": "JSON Web Token (JWT)"
    },
    {
        "name": "Database Connection String",
        "pattern": r"(?i)(mysql|postgresql|postgres|mongodb|redis|oracle|mssql):\/\/[^\s\"']+:[^\s\"']+@[^\s\"']+",
        "severity": "HIGH",
        "description": "Database connection string with credentials"
    },
    {
        "name": "Generic Password in Code",
        "pattern": r"(?i)(password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
        "severity": "HIGH",
        "description": "Hardcoded password in source code"
    },
    {
        "name": "Generic Secret in Code",
        "pattern": r"(?i)(secret|api_secret|client_secret)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "severity": "HIGH",
        "description": "Hardcoded secret value"
    },
    {
        "name": "Generic API Key in Code",
        "pattern": r"(?i)(api_key|apikey|api-key)\s*[=:]\s*['\"][^'\"]{8,}['\"]",
        "severity": "HIGH",
        "description": "Hardcoded API key"
    },
    {
        "name": "Bearer Token",
        "pattern": r"(?i)bearer\s+[a-zA-Z0-9\-_=]+\.[a-zA-Z0-9\-_=]+\.?[a-zA-Z0-9\-_.+/=]*",
        "severity": "HIGH",
        "description": "Bearer authentication token"
    },
    {
        "name": "Azure Storage Account Key",
        "pattern": r"(?i)AccountKey=[a-zA-Z0-9+/]{88}==",
        "severity": "HIGH",
        "description": "Azure Storage Account access key"
    },
    {
        "name": "Azure SAS Token",
        "pattern": r"(?i)sv=\d{4}-\d{2}-\d{2}&ss=[a-z]+&srt=[a-z]+&sp=[a-z]+&se=\d{4}",
        "severity": "HIGH",
        "description": "Azure Shared Access Signature token"
    },
    # ── Medium ────────────────────────────────────────────────────────────────
    {
        "name": "Generic Token",
        "pattern": r"(?i)(token|access_token|auth_token|refresh_token)\s*[=:]\s*['\"][^'\"]{16,}['\"]",
        "severity": "MEDIUM",
        "description": "Generic authentication token"
    },
    {
        "name": "IP Address (Private)",
        "pattern": r"(?i)(host|server|endpoint)\s*[=:]\s*['\"]?(10\.\d+\.\d+\.\d+|172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|192\.168\.\d+\.\d+)['\"]?",
        "severity": "MEDIUM",
        "description": "Hardcoded private IP address"
    },
    {
        "name": "SSH Private Key Path",
        "pattern": r"(?i)(ssh_key|id_rsa|identity_file)\s*[=:]\s*['\"][^'\"]+['\"]",
        "severity": "MEDIUM",
        "description": "Reference to SSH private key file"
    },
]

# File extensions to scan
SCANNABLE_EXTENSIONS = {
    '.py', '.js', '.ts', '.java', '.go', '.rb', '.php', '.cs', '.cpp', '.c',
    '.h', '.sh', '.bash', '.zsh', '.env', '.yml', '.yaml', '.json', '.xml',
    '.properties', '.conf', '.config', '.ini', '.toml', '.tf', '.tfvars',
    '.gradle', '.pom', '.dockerfile', '.md', '.txt', '.sql'
}

# Binary extensions to skip
BINARY_EXTENSIONS = {
    '.png', '.jpg', '.jpeg', '.gif', '.bmp', '.ico', '.svg',
    '.zip', '.tar', '.gz', '.rar', '.7z',
    '.exe', '.dll', '.so', '.dylib',
    '.pdf', '.doc', '.docx', '.xls', '.xlsx',
    '.pyc', '.class', '.jar', '.war',
    '.mp3', '.mp4', '.avi', '.mov',
    '.ttf', '.woff', '.woff2', '.eot',
    '.lock'
}

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
