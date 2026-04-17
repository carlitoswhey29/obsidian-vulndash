import { VulnerabilityRecord } from './QueryTypes';

export class ExactMatchIndexes {
    private severityIndex = new Map<string, Set<string>>();
    private sourceIndex = new Map<string, Set<string>>();
    private enabledIndex = new Set<string>();
    private followedIndex = new Set<string>();
    private allIds = new Set<string>();

    public index(records: VulnerabilityRecord[]): void {
        this.clear();
        for (const record of records) {
            this.allIds.add(record.id);

            if (!this.severityIndex.has(record.severity)) {
                this.severityIndex.set(record.severity, new Set());
            }
            this.severityIndex.get(record.severity)!.add(record.id);

            if (!this.sourceIndex.has(record.source)) {
                this.sourceIndex.set(record.source, new Set());
            }
            this.sourceIndex.get(record.source)!.add(record.id);

            if (record.enabled) this.enabledIndex.add(record.id);
            if (record.followed) this.followedIndex.add(record.id);
        }
    }

    public getMatchingIds(severities?: string[], sources?: string[], enabledOnly?: boolean, followedOnly?: boolean): Set<string> {
        let result = new Set(this.allIds);

        if (severities && severities.length > 0) {
            result = this.intersectArrays(result, severities.map(s => this.severityIndex.get(s) || new Set()));
        }

        if (sources && sources.length > 0) {
            result = this.intersectArrays(result, sources.map(s => this.sourceIndex.get(s) || new Set()));
        }

        if (enabledOnly) {
            result = this.intersect(result, this.enabledIndex);
        }

        if (followedOnly) {
            result = this.intersect(result, this.followedIndex);
        }

        return result;
    }

    private clear(): void {
        this.severityIndex.clear();
        this.sourceIndex.clear();
        this.enabledIndex.clear();
        this.followedIndex.clear();
        this.allIds.clear();
    }

    private intersect(a: Set<string>, b: Set<string>): Set<string> {
        const intersection = new Set<string>();
        for (const item of b) {
            if (a.has(item)) intersection.add(item);
        }
        return intersection;
    }

    private intersectArrays(base: Set<string>, sets: Set<string>[]): Set<string> {
        const unionOfSets = new Set<string>();
        for (const s of sets) {
            for (const item of s) {
                unionOfSets.add(item);
            }
        }
        return this.intersect(base, unionOfSets);
    }
}
