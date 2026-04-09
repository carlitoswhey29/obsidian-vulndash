# VulnDash

VulnDash is a near-live vulnerability and Common Vulnerabilities and Exposures (CVE) dashboard integrated directly into your Obsidian vault. It aggregates security advisories from multiple sources, filters them against your specific software stack, and automatically alerts you to critical threats.

## Features

* **Unified Dashboard**: View a sortable, filterable table of vulnerabilities fetched from the National Vulnerability Database (NVD), GitHub Advisories, specific GitHub repositories, or custom JSON feeds.
* **SBOM Integration**: Import CycloneDX Software Bill of Materials (SBOM) JSON files directly from your vault. VulnDash automatically parses these files to filter the dashboard, showing only vulnerabilities relevant to the components you actually use.
* **Smart Alerting & Note Creation**: Get native Obsidian notices or OS-level desktop notifications when new threats matching your stack are detected. Automatically generate Obsidian notes for new HIGH or CRITICAL vulnerabilities to document mitigation strategies.
* **Advanced Filtering**: Filter noise by setting minimum CVSS scores, severity levels, or using keyword and regular expression matching.
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

By default, VulnDash can fetch data anonymously, but you will quickly hit API rate limits. It is highly recommended to configure your own API keys.

1. Go to **Settings > VulnDash**.
2. Under **Integration & Export**, provide your **NVD API key** and a fine-grained **GitHub token**. 
3. Adjust your **Polling interval** and **Cache duration** to suit your needs.

### Adding SBOMs
To make VulnDash fully aware of your environment, configure it to watch your software stack:
1. Place a valid CycloneDX SBOM `.json` file anywhere in your Obsidian vault.
2. Go to **Settings > VulnDash** and click **Manage SBOMs** under the SBOM Workspace section.
3. Click **Add SBOM** and use the fuzzy search to select your JSON file.
4. VulnDash will parse the components and compute a list of product filters. You can inspect these components, rename them to match CVE naming conventions, or exclude them from filtering entirely.

## Usage

Once enabled and configured, you can open the dashboard in two ways:
* Click the ribbon icon in the Obsidian left-hand sidebar.
* Open the Command Palette (`Ctrl/Cmd + P`) and run the command: `VulnDash: Open vulnerability dashboard`.

Inside the dashboard:
* **Sorting**: Click any column header (ID, Title, Source, Severity, CVSS, Published) to sort the vulnerabilities.
* **Searching**: Use the search bar at the top of the dashboard to quickly filter visible results.
* **Expanding Details**: Click on any vulnerability row to expand it. This reveals the full markdown-rendered summary and external reference links to the original advisories.

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
