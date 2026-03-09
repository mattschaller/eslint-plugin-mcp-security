/**
 * Shared constants for MCP security rules.
 *
 * Credential paths, secret patterns, shell/fs function lists used
 * across multiple rules to keep detection consistent.
 */

/** Credential file/directory patterns used by SANDWORM_MODE attacks. */
export const CREDENTIAL_PATTERNS: ReadonlyArray<{ pattern: RegExp; label: string }> = [
  // Credential directories
  { pattern: /~\/\.ssh\b/, label: '~/.ssh (SSH keys)' },
  { pattern: /~\/\.aws\b/, label: '~/.aws (AWS credentials)' },
  { pattern: /~\/\.gnupg\b/, label: '~/.gnupg (GPG keys)' },
  { pattern: /~\/\.config\/gcloud/, label: 'GCloud credentials' },
  { pattern: /~\/\.azure\b/, label: '~/.azure (Azure credentials)' },
  { pattern: /~\/\.kube\b/, label: '~/.kube (Kubernetes config)' },
  { pattern: /~\/\.docker\/config\.json/, label: 'Docker credentials' },
  { pattern: /~\/\.npmrc\b/, label: '~/.npmrc (npm auth tokens)' },

  // Credential files by name
  { pattern: /\.env\b/, label: '.env (environment secrets)' },
  { pattern: /\bid_rsa\b/, label: 'SSH private key (id_rsa)' },
  { pattern: /\bid_ed25519\b/, label: 'SSH private key (id_ed25519)' },
  { pattern: /\bid_ecdsa\b/, label: 'SSH private key (id_ecdsa)' },

  // System credential files
  { pattern: /\/etc\/shadow\b/, label: '/etc/shadow' },
  { pattern: /\/etc\/passwd\b/, label: '/etc/passwd' },

  // Key/cert file extensions
  { pattern: /\.pem\b/, label: 'PEM certificate/key file' },
  { pattern: /\.p12\b/, label: 'PKCS#12 key file' },
  { pattern: /\.pfx\b/, label: 'PFX key file' },
  { pattern: /\.keystore\b/, label: 'Java keystore' },

  // Cloud credential references
  { pattern: /aws_access_key/i, label: 'AWS access key' },
  { pattern: /aws_secret/i, label: 'AWS secret' },
];

/** Shell execution functions (CWE-78). */
export const SHELL_FUNCTIONS = new Set([
  'exec',
  'execSync',
  'execFile',
  'execFileSync',
  'spawn',
  'spawnSync',
]);

/** Filesystem functions vulnerable to path traversal (CWE-22). */
export const FS_FUNCTIONS = new Set([
  // Reading
  'readFile',
  'readFileSync',
  'createReadStream',
  // Writing
  'writeFile',
  'writeFileSync',
  'createWriteStream',
  'appendFile',
  'appendFileSync',
  // Deletion
  'unlink',
  'unlinkSync',
  'rm',
  'rmSync',
  'rmdir',
  'rmdirSync',
  // Directory listing
  'readdir',
  'readdirSync',
  // File manipulation
  'rename',
  'renameSync',
  'copyFile',
  'copyFileSync',
  // Opening files
  'open',
  'openSync',
  // Metadata (information disclosure)
  'stat',
  'statSync',
  'lstat',
  'lstatSync',
  // Permissions
  'chmod',
  'chmodSync',
  'chown',
  'chownSync',
]);

/** Patterns that match hardcoded secrets in string literals (applied to node.value, no quotes). */
export const SECRET_PATTERNS: ReadonlyArray<{ pattern: RegExp; label: string }> = [
  // Generic API keys / tokens assigned in code
  { pattern: /(?:api[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9\-_/.+]{8,}/i, label: 'API key' },
  { pattern: /(?:secret[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9\-_/.+]{8,}/i, label: 'Secret key' },
  { pattern: /(?:access[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9\-_/.+]{8,}/i, label: 'Access token' },
  { pattern: /(?:auth[_-]?token)\s*[:=]\s*['"]?[A-Za-z0-9\-_/.+]{8,}/i, label: 'Auth token' },
  { pattern: /(?:private[_-]?key)\s*[:=]\s*['"]?[A-Za-z0-9\-_/.+]{8,}/i, label: 'Private key' },

  // Provider-specific key prefixes (matched against string value, no surrounding quotes)
  { pattern: /^sk-[A-Za-z0-9]{20,}$/, label: 'OpenAI/Stripe secret key' },
  { pattern: /^ghp_[A-Za-z0-9]{36,}$/, label: 'GitHub personal access token' },
  { pattern: /^gho_[A-Za-z0-9]{36,}$/, label: 'GitHub OAuth token' },
  { pattern: /^AKIA[A-Z0-9]{16}$/, label: 'AWS access key ID' },
  { pattern: /^xox[bporas]-[A-Za-z0-9\-]{10,}$/, label: 'Slack token' },

  // Bearer tokens in headers
  { pattern: /^Bearer\s+[A-Za-z0-9\-_/.+]{20,}$/, label: 'Bearer token' },

  // Connection strings with credentials
  { pattern: /^(?:mongodb|postgres|mysql|redis):\/\/[^:]+:.+@/i, label: 'Database connection string with credentials' },
];

/** Auth-related identifiers for heuristic auth-check detection. */
export const AUTH_IDENTIFIERS = new Set([
  'auth',
  'authenticate',
  'authentication',
  'authorize',
  'authorization',
  'verify',
  'verifyToken',
  'verifySession',
  'checkAuth',
  'requireAuth',
  'isAuthenticated',
  'isAuthorized',
  'session',
  'token',
  'credential',
  'credentials',
  'permission',
  'permissions',
  'context',
  'ctx',
]);

/** Dangerous operations that should be scoped/guarded in tool handlers. */
export const UNSCOPED_DANGEROUS_CALLS = new Set([
  'exit',       // process.exit()
  'kill',       // process.kill()
  'rmSync',     // recursive delete
  'rmdir',
  'rmdirSync',
]);
