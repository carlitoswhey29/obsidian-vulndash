# VulnDash Obsidian Plugin

VulnDash is an Obsidian plugin that provides a near-live CVE dashboard with polling, filtering, and severity-based alerting.

## Security Notes

- Rendering is safe by construction: no `innerHTML` is used; all user/API strings are sanitized before rendering.
- API keys are optional and not logged.
- Polling uses async operations and exponential backoff for transient/rate-limit failures.
- Build includes CycloneDX SBOM generation for supply-chain visibility.

## Build, SBOM, and Test in Obsidian

1. Install dependencies:
   ```bash
   npm install
   ```
2. Run strict checks and compile plugin:
   ```bash
   npm run build
   ```
3. Generate CycloneDX SBOM JSON:
   ```bash
   npm run sbom
   ```
4. Run full secure pipeline:
   ```bash
   npm run build:secure
   ```
5. Copy plugin artifacts to your vault's plugin folder:
   ```bash
   mkdir -p <Vault>/.obsidian/plugins/vulndash
   cp manifest.json main.js styles.css <Vault>/.obsidian/plugins/vulndash/
   ```
6. In Obsidian: **Settings → Community Plugins → Reload plugins**, then enable **VulnDash**.
7. Open VulnDash via ribbon icon or command palette: `Open vulnerability dashboard`.

## Operational Guidance

- Prefer setting a GitHub token (fine-grained) and NVD API key to reduce rate limits.
- Use filtering settings to reduce noise (keywords, products, minimum CVSS/severity).

## Sync Architecture

- **Transport vs client responsibilities**
  - `HttpClient` is transport-generic and only handles HTTP execution plus typed transport errors.
  - Source clients (`GitHubAdvisoryClient`, `NvdClient`) own pagination and source-specific query mapping.
- **Cursor semantics**
  - `since` always means *fetch records changed since timestamp*.
  - Cursor state is persisted per source (`sourceSyncCursor`) and advanced only after a successful source sync.
- **Merge behavior**
  - Polling merges by stable source-aware key (`<source>:<id>`).
  - Incoming records replace cached records only when normalized freshness (`updatedAt`) is newer.
  - Dedup is deterministic across pages and overlap windows.
- **Retry / rate-limit handling**
  - Retryable errors (timeouts, network, 429, transient 5xx) use exponential backoff.
  - `Retry-After` is honored for rate limits.
  - Retry budget is bounded and sync fails cleanly when exhausted.
- **Per-source isolation**
  - Each source sync runs with independent cursor, warnings, retries, and result status.
  - Partial source failure does not discard successful records from other sources.

### Polling cycle sequence (simplified)

1. Read source cursor.
2. Apply overlap window to compute effective `since`.
3. Fetch paginated data with source client bounds (`maxPages`, `maxItems`).
4. Deduplicate and merge into cache with freshness checks.
5. If full source sync succeeds, advance only that source cursor.
6. Emit structured sync result/log summary.
