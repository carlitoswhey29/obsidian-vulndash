# VulnDash Obsidian Plugin

VulnDash is an Obsidian plugin that provides a near-live CVE dashboard with polling, filtering, and severity-based alerting.

## Clean Architecture Directory Tree

```text
.
├── manifest.json
├── package.json
├── tsconfig.json
├── esbuild.config.mjs
├── styles.css
└── src
    ├── main.ts
    ├── domain
    │   ├── entities
    │   │   ├── Severity.ts
    │   │   └── Vulnerability.ts
    │   └── services
    │       └── Cvss.ts
    ├── application
    │   ├── ports
    │   │   └── VulnerabilityFeed.ts
    │   └── services
    │       ├── AlertEngine.ts
    │       ├── PollingOrchestrator.ts
    │       └── types.ts
    └── infrastructure
        ├── api
        │   ├── GitHubAdvisoryClient.ts
        │   ├── HttpClient.ts
        │   └── NvdClient.ts
        ├── obsidian
        │   └── VulnDashView.ts
        └── utils
            └── sanitize.ts
```

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
