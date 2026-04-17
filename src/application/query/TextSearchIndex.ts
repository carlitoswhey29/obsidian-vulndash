import { VulnerabilityRecord } from './QueryTypes';

export class TextSearchIndex {
    private tokenMap = new Map<string, Set<string>>();
    private cveMap = new Map<string, string>(); // lowercase CVE to actual ID

    public index(records: VulnerabilityRecord[]): void {
        this.tokenMap.clear();
        this.cveMap.clear();

        for (const record of records) {
            this.cveMap.set(record.id.toLowerCase(), record.id);

            const tokens = this.tokenize(`${record.id} ${record.components.join(' ')} ${record.description || ''}`);
            for (const token of tokens) {
                if (!this.tokenMap.has(token)) {
                    this.tokenMap.set(token, new Set());
                }
                this.tokenMap.get(token)!.add(record.id);
            }
        }
    }

    public search(query: string): Map<string, number> {
        const results = new Map<string, number>();
        if (!query.trim()) return results;

        const tokens = this.tokenize(query);
        const isCveQuery = query.toLowerCase().startsWith('cve-');

        // Exact CVE match short-circuit
        if (isCveQuery && this.cveMap.has(query.toLowerCase())) {
            results.set(this.cveMap.get(query.toLowerCase())!, 100);
            return results;
        }

        for (const token of tokens) {
            for (const [indexedToken, ids] of this.tokenMap.entries()) {
                if (indexedToken.includes(token)) {
                    const weight = indexedToken === token ? 2 : 1; // Exact word match gets higher weight
                    for (const id of ids) {
                        results.set(id, (results.get(id) || 0) + weight);
                    }
                }
            }
        }

        return results;
    }

    private tokenize(text: string): string[] {
        return text.toLowerCase().split(/[\s,.-]+/).filter(t => t.length > 2);
    }
}
