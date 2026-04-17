import { QueryResult } from './QueryTypes';

export class QueryRanking {
    public static rankAndSort(
        textScores: Map<string, number>,
        exactMatchIds: Set<string>,
        isTextSearchActive: boolean
    ): QueryResult[] {
        const results: QueryResult[] = [];

        for (const id of exactMatchIds) {
            const score = textScores.get(id) || 0;
            if (isTextSearchActive && score === 0) continue; // Filtered out by text search

            results.push({ id, score });
        }

        return results.sort((a, b) => {
            // 1. Sort by text search score (descending)
            if (b.score !== a.score) {
                return b.score - a.score;
            }
            // 2. Deterministic fallback: reverse alphabetical by ID (newest CVEs first generally)
            return b.id.localeCompare(a.id);
        });
    }
}
