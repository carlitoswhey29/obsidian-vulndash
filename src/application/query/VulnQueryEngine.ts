import { ExactMatchIndexes } from './ExactMatchIndexes';
import { TextSearchIndex } from './TextSearchIndex';
import { QueryRanking } from './QueryRanking';
import { VulnerabilityRecord, QueryFilters, QueryResult } from './QueryTypes';

export class VulnQueryEngine {
    private exactIndexes = new ExactMatchIndexes();
    private textIndex = new TextSearchIndex();

    public buildIndexes(records: VulnerabilityRecord[]): void {
        this.exactIndexes.index(records);
        this.textIndex.index(records);
    }

    public execute(filters: QueryFilters): QueryResult[] {
        const exactMatchIds = this.exactIndexes.getMatchingIds(
            filters.severities,
            filters.sources,
            filters.enabledOnly,
            filters.followedOnly
        );

        let textScores = new Map<string, number>();
        const isTextSearchActive = !!filters.text && filters.text.trim().length > 0;

        if (isTextSearchActive) {
            textScores = this.textIndex.search(filters.text!);
        }

        return QueryRanking.rankAndSort(textScores, exactMatchIds, isTextSearchActive);
    }
}
