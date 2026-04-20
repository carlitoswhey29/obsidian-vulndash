# VulnDash

VulnDash is a near-live vulnerability and Common Vulnerabilities and Exposures (CVE) dashboard integrated directly into your Obsidian vault. It aggregates security advisories from multiple sources, caches them locally via a robust background ingestion pipeline, and seamlessly correlates them against your specific software stack using offline matching.

## Features

* **Offline-First Vulnerability Correlation**: Avoids API rate limits and slow load times by continuously syncing feeds (NVD, GitHub Advisories, custom JSON) into a local vault cache. SBOM components are instantly matched against this local database using PURL and CPE identifiers.
* **Comprehensive SBOM Workspace**: Import your Software Bill of Materials (SBOM) JSON files. VulnDash officially supports both **CycloneDX** and **SPDX** formats. The plugin automatically parses components, tracks your inventory, and reveals exactly which packages in your stack are vulnerable.
* **Smart Alerting & Notifications**: Stay informed without leaving your workflow. VulnDash can trigger native Obsidian notices or OS-level desktop notifications when new threats match your environment. 
* **Advanced Triage Workflows**: Manage your security posture directly in Obsidian. Mark findings with distinct triage states (`Active`, `Investigating`, `Mitigated`, `Accepted Risk`, `False Positive`, or `Suppressed`) to track your mitigation progress over time.
* **Obsidian Native Integration**: Generate automated Daily Rollup notes of your current threat landscape. VulnDash can also auto-link components to your existing Project notes and create dedicated vulnerability notes for critical threats to document mitigation strategies.
* **Unified & Filterable Dashboard**: View a sortable, virtualized table of vulnerabilities. Filter out the noise by setting minimum CVSS scores, severity levels, specific triage states, or using keyword matching.
* **Local & Secure**: API keys are encrypted using the Web Crypto API before being stored locally on your device. They are never logged or exposed in plain text.

## Installation

### Community Plugins (Recommended)
Once approved and merged, you will be able to install VulnDash directly from the Obsidian Community Plugins directory.
1. Open Obsidian **Settings -> Community Plugins**.
2. Disable "Safe Mode" if it is active.
3. Click "Browse" and search for "VulnDash".
4. Click "Install" and then "Enable".

### Manual Installation
1. Download the latest release from the GitHub repository.
2. Extract the contents into your vault's `.obsidian/plugins/vulndash` directory.
3. Ensure the folder contains `main.js`, `manifest.json`, and `styles.css`.
4. Reload Obsidian and enable the plugin in **Settings -> Community Plugins**.

## Configuration

To ensure seamless offline correlation, it is highly recommended to configure your API keys to support the background sync pipeline.

1. Go to **Settings > VulnDash**.
2. Under **Integration & Feeds**, provide your **NVD API key** and a fine-grained **GitHub token**. 
3. Adjust your **Background Sync Interval** and **Overlap Window**. The internal ingestion pipeline will fetch incremental updates to keep your local vulnerability cache fresh without hitting rate limits.
4. Under **Alerts & Notifications**, toggle your preference for in-app Obsidian notices versus OS-level desktop notifications, and set your minimum severity threshold for alerts.

### Adding SBOMs
To make VulnDash fully aware of your environment, configure it to watch your software stack:
1. Place a valid CycloneDX or SPDX SBOM `.json` file anywhere in your Obsidian vault.
2. Go to **Settings > VulnDash** and click **Manage SBOMs** under the SBOM Workspace section.
3. Click **Add SBOM** and use the fuzzy search to select your JSON file.
4. VulnDash will parse the components, extract PURLs and CPEs, and instantly run an offline correlation against your synced vulnerabilities to highlight active risks in your projects.

## Usage

Once enabled and configured, you can open the dashboard in two ways:
* Click the ribbon icon in the Obsidian left-hand sidebar.
* Open the Command Palette (`Ctrl/Cmd + P`) and run the command: `VulnDash: Open vulnerability dashboard`.

Inside the dashboard:
* **Sorting & Searching**: Click any column header to sort. Use the global search bar or the dedicated component/triage filters to quickly locate specific findings.
* **Triage & Review**: Select a vulnerability or component to update its triage state. Mark items as `Mitigated` once patched or `Accepted Risk` if no fix is currently viable.
* **Expanding Details**: Click on any vulnerability or component row to expand the detailed view. This reveals a markdown-rendered summary, affected project links, and external references to the original advisories.
* **Daily Rollups**: Use the Command Palette to generate a Daily Rollup note, which provides a snapshot summary of new findings and your current component inventory status.

## Development

If you wish to compile the plugin locally:

1. Clone the repository and install dependencies:
   ```bash
   npm install
   ```
2. Run strict checks and compile the plugin:
   ```bash
   npm run build
   ```
3. Generate the CycloneDX SBOM JSON for the plugin itself:
   ```bash
   npm run sbom
   ```
4. Copy the compiled artifacts (`manifest.json`, `main.js`, `styles.css`) to your vault's plugin folder:
   ```bash
   mkdir -p <Vault>/.obsidian/plugins/vulndash
   cp dist/manifest.json dist/main.js dist/styles.css <Vault>/.obsidian/plugins/vulndash/
   ```
