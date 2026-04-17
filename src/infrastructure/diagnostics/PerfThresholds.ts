export const PerfThresholds = {
    WARN_RENDER_MS: 16,        // Dropping below 60fps
    WARN_FETCH_MS: 1000,       // Slow network/API calls
    WARN_INDEX_BUILD_MS: 50,   // Query engine index rebuild
    WARN_QUERY_MS: 10,         // Search/filter latency
    WARN_CACHE_WRITE_MS: 100,  // IndexedDB block
    MAX_EXPECTED_PAYLOAD: 5000 // Number of items before warning
} as const;
