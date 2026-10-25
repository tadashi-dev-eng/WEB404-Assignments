# Assignment 1 — Remediation Planning & Code Hardening Report

## Assignment 1 — OWASP Juice Shop Security Findings

The target is an intentionally vulnerable training application. The recommendations below are written as production-oriented controls while preserving the educational purpose of the lab. Changes should be tested in a separate branch or deployment so that the original findings remain reproducible for assessment evidence.

---

## 1. Executive Summary

The assessment identified four security weaknesses in HTTP responses and publicly accessible content:

1. No **Content-Security-Policy (CSP)** header was observed.
2. **Wildcard CORS** allowed requests from any origin.
3. The public **`/ftp/` directory** exposed a browsable file listing.
4. **Inode-based ETags** disclosed server-side file metadata.

The highest-priority work is to remove the public file exposure and restrict cross-origin access. CSP should then be introduced in report-only mode and tightened without breaking the application. ETag behavior is a lower-risk defense-in-depth improvement, but it should still be addressed because it removes unnecessary infrastructure metadata from responses.

The recommended target state is:

- only explicitly approved origins can make cross-origin requests;
- no backup, configuration, or operational files are served from a public web root;
- a restrictive, tested CSP is returned on all application responses;
- ETags are disabled or generated without filesystem inode metadata;
- automated tests and deployment checks prevent regression.

---

## 2. Evidence and Finding Register

| ID | Finding | Evidence observed | Risk | Confidence | Priority |
|---|---|---|---|---|---|
| **VULN-01** | Missing CSP | The response did not include a `Content-Security-Policy` header. | High | High | P1 |
| **VULN-02** | Wildcard CORS | `Access-Control-Allow-Origin: *` was returned; Nikto also observed broad allowed methods. | Medium | High | P1 |
| **VULN-03** | Public `/ftp/` directory | `GET /ftp/` returned HTTP 200 and exposed an active directory listing. `robots.txt` also referenced the path. | Medium | High | P1 |
| **VULN-04** | Inode-based ETag disclosure | Nikto reported ETags containing file metadata, for example `W/"24b1-1a172cb84e7"`. | Low | High | P2 |

### Evidence sources

- `nikto_scan.txt` — scanner output for `localhost:3000`.
- `assets/csp.png` — missing CSP evidence.
- `assets/reasponse-header.png` — response-header evidence for wildcard CORS.
- `assets/ftp.png` — public directory listing evidence.
- `assets/v3.png` — ETag evidence.
- OWASP ZAP HTML exports — supporting passive-scan evidence.

### Important interpretation

These findings are security weaknesses, not proof of a complete exploit chain. For example, a CSP reduces the impact of some script-injection paths but does not replace output encoding, input validation, or secure session handling. Similarly, changing ETags limits metadata disclosure but does not make sensitive files safe to publish. The underlying exposure must be remediated first.

---

## 3. Remediation Plan

### 3.1 VULN-03 — Remove the public `/ftp/` exposure

**Risk rationale:** An unauthenticated directory listing can reveal backups, test files, source artifacts, invoices, logs, or other operational data. File names alone may disclose application structure and can enable targeted attacks.

**Required actions**

1. Remove `/ftp/` from the web server's public document root.
2. Delete or relocate backups and operational files to private storage outside the container/image served by the application.
3. Disable directory indexing at the web-server or reverse-proxy layer.
4. Review `robots.txt`; do not treat it as an access-control mechanism. Remove the `/ftp/` entry after the resource is no longer public.
5. Search the image, mounted volumes, and build artifacts for copies of the same files.
6. If a file-download feature is genuinely required, implement an authenticated download endpoint with authorization checks, an allowlist of file identifiers, and audit logging.

**Hardening examples**

For Nginx:

```nginx
location /ftp/ {
    deny all;
    return 404;
}

autoindex off;
```

For an Express application, do not mount the directory:

```js
// Do not expose operational or backup files:
// app.use('/ftp', express.static(path.join(__dirname, 'ftp')));
```

If static content is required, mount only a dedicated directory containing reviewed, non-sensitive assets.

**Acceptance criteria**

- `curl -i http://localhost:3000/ftp/` returns `404` or `403`, never `200`.
- No directory index is rendered for `/ftp/` or any equivalent path.
- Known backup/configuration files cannot be downloaded by guessing their names.
- A repository/image review confirms that sensitive files are outside the public web root.

---

### 3.2 VULN-02 — Replace wildcard CORS with an allowlist

**Risk rationale:** `Access-Control-Allow-Origin: *` permits any website to read responses from endpoints that are intended to be used cross-origin. If credentials, tokens, or sensitive API responses are involved, permissive CORS can magnify the impact of other weaknesses.

**Required actions**

1. Identify the small set of legitimate front-end or API origins.
2. Replace `*` with an exact allowlist maintained through environment configuration.
3. Never combine wildcard origins with credentialed requests.
4. Allow only required methods and headers; remove broad methods such as `DELETE` unless the endpoint needs them.
5. Add `Vary: Origin` when the response varies by the request origin.
6. Apply CORS per route or API group instead of globally where possible.

**Hardening example (Express)**

```js
const allowedOrigins = new Set(
  (process.env.CORS_ALLOWED_ORIGINS ?? '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
);

app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error('CORS origin is not allowed'));
  },
  methods: ['GET', 'POST'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
}));
```

The exact middleware and error-handling pattern must follow the application's existing framework conventions. The important control is an explicit allowlist, not the specific package.

**Acceptance criteria**

- An approved origin receives the expected `Access-Control-Allow-Origin` value.
- An unapproved origin does not receive an allow permission.
- Preflight responses list only required methods and headers.
- Credentialed requests are accepted only for approved origins.
- Automated tests cover approved, unapproved, absent, and malformed `Origin` headers.

---

### 3.3 VULN-01 — Introduce and enforce a tested CSP

**Risk rationale:** Without CSP, browsers have no additional response-level policy restricting script, style, image, frame, or connection sources. This increases the potential impact of XSS and unsafe third-party content.

**Implementation approach**

1. Inventory the application's scripts, styles, images, fonts, API connections, workers, frames, and third-party resources.
2. Start with `Content-Security-Policy-Report-Only` to identify required sources without breaking the lab application.
3. Remove inline scripts and inline event handlers where practical. Prefer external files and nonces or hashes for unavoidable inline code.
4. Move to enforcing `Content-Security-Policy` after violations are reviewed.
5. Avoid broad directives such as `*`, `unsafe-eval`, and `unsafe-inline` unless a documented compatibility exception is necessary.

**Illustrative baseline**

```http
Content-Security-Policy:
  default-src 'self';
  script-src 'self';
  style-src 'self';
  img-src 'self' data:;
  font-src 'self';
  connect-src 'self';
  object-src 'none';
  base-uri 'self';
  frame-ancestors 'self';
  form-action 'self';
  upgrade-insecure-requests;
```

This is a starting point, not a copy-and-deploy guarantee. The policy must be adjusted to the application's verified resource inventory. `frame-ancestors` should be set according to the intended embedding policy; use `'none'` if framing is not required.

**Acceptance criteria**

- Every application response includes an enforcing CSP after rollout.
- ZAP reports no missing CSP header.
- Normal application flows work without unexpected CSP violations.
- No unnecessary `unsafe-eval`, `unsafe-inline`, wildcard source, or unapproved third-party source remains.
- CSP violation reports, if enabled, are rate-limited and do not collect sensitive data.

---

### 3.4 VULN-04 — Remove inode-based ETag metadata

**Risk rationale:** ETags that include inode or filesystem metadata can disclose implementation details and help correlate resources across requests. This is normally low impact, but the metadata is unnecessary for this deployment.

**Required actions**

1. Confirm whether the application or reverse proxy generates the ETag.
2. Disable ETags where cache validation is not required, or configure a metadata-safe strategy.
3. If caching is needed, use content-hash-based versioning and explicit `Cache-Control` directives.
4. Recheck static assets and error responses, not only `/`.

**Hardening examples**

For Express, if the application does not require ETag-based conditional requests:

```js
app.disable('etag');
```

For Nginx, review proxy/static caching configuration and ensure the upstream response is not reintroducing filesystem-derived validators. Prefer immutable, content-hashed asset names for long-lived static caching.

**Acceptance criteria**

- Responses no longer contain inode-based ETag values.
- Conditional requests still behave as intended, or the application's cache policy explicitly documents that ETags are disabled.
- `Last-Modified` and cache headers do not expose more metadata than required.
- Nikto no longer reports inode leakage.

---

## 4. Prioritized Delivery Plan

| Phase | Actions | Owner | Target |
|---|---|---|---|
| **P1 — Immediate containment** | Block `/ftp/`; remove sensitive files from the public root; replace wildcard CORS; restrict methods and origins. | Application and platform owner | Before the next deployment |
| **P1 — Browser defense** | Inventory resources and deploy CSP in report-only mode; fix violations; enforce the reviewed policy. | Front-end and application owner | Same iteration |
| **P2 — Defense in depth** | Remove inode-based ETags; review cache headers and static asset strategy. | Platform owner | Next hardening iteration |
| **P2 — Regression prevention** | Add automated header, path-access, CORS, and CSP checks to CI/CD. | QA/DevSecOps owner | Before closure |
| **P3 — Verification and closure** | Re-run ZAP and Nikto, compare results with the baseline, attach evidence, and document residual risk. | Security assessor | After deployment |

No finding should be marked closed based only on a configuration change. Closure requires a retest against the deployed target and evidence that the control is effective.

---

## 5. Verification Test Plan

Run these checks against the remediated test instance:

```bash
# Confirm the important response headers
curl -sS -D - -o /dev/null http://localhost:3000/ \
  | grep -Ei 'content-security-policy|access-control-allow-origin|etag|x-content-type-options'

# Confirm the sensitive path is blocked
curl -i http://localhost:3000/ftp/

# Test an unapproved CORS origin
curl -i -H 'Origin: https://attacker.example' \
  http://localhost:3000/

# Test a permitted preflight with only the required method
curl -i -X OPTIONS \
  -H 'Origin: https://approved.example' \
  -H 'Access-Control-Request-Method: GET' \
  http://localhost:3000/
```

Expected outcomes:

- CSP is present and enforcing.
- `/ftp/` is denied or absent, with no listing.
- An unapproved origin is not granted cross-origin access.
- Allowed methods are limited to the documented API contract.
- Inode-based ETags are absent or replaced by a documented safe strategy.

After manual checks, rerun the same ZAP passive scan and Nikto scan used for the baseline. Record the scan date, target version, tool versions, and relevant screenshots or exported reports. Any remaining alert should be classified as **fixed**, **accepted residual risk**, or **false positive** with a written justification.

---

## 6. Secure Development and Regression Controls

To prevent recurrence:

- Add an integration test that fails if `/ftp/` or other non-public directories return `200`.
- Add header assertions for CSP, CORS, and ETag behavior.
- Store allowed CORS origins in deployment configuration, not in source-code wildcards.
- Add a CI check that rejects backup extensions and sensitive files in the public static directory.
- Review changes to reverse-proxy, static-file, and security-header configuration during code review.
- Run ZAP passive scanning and a lightweight Nikto check in a non-production pipeline environment.
- Keep scan evidence and remediation status linked to the release or assessment record.

---

## 7. Residual Risk and Closure Statement

Once these controls are implemented, the assessed exposure should be substantially reduced, but the application remains intentionally vulnerable by design and may contain weaknesses outside this assessment's scope. CSP and CORS are browser-enforced controls; they do not replace server-side authorization, secure coding, dependency management, or input/output validation.

The assessment can be considered remediated only when:

1. all P1 actions are deployed;
2. the verification tests pass;
3. ZAP and Nikto are rerun against the deployed version;
4. no unexplained finding remains; and
5. any accepted residual risk has an owner, justification, and review date.

**Recommended final status:** Open — remediation planned; close after technical retest.
