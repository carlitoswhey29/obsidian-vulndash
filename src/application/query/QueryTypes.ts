export interface VulnerabilityRecord {
    id: string; // Typically CVE
    severity: string;
    source: string;
    components: string[];
    description?: string;
    enabled: boolean;
    followed: boolean;
}

export interface QueryFilters {
    text?: string;
    severities?: string[];
    sources?: string[];
    enabledOnly?: boolean;
    followedOnly?: boolean;
}

export interface QueryResult {
    id: string;
    score: number;
}
