import { PerfDebugState } from './PerfDebugState';

export class PerfTimers {
    /**
     * Safely wraps an asynchronous function with performance timing.
     * Does not alter the return type or business logic.
     */
    public static async measureAsync<T>(
        label: string,
        thresholdMs: number,
        fn: () => Promise<T>
    ): Promise<T> {
        const debugState = PerfDebugState.getInstance();
        if (!debugState.isDebugActive) return fn();

        const start = performance.now();
        try {
            return await fn();
        } finally {
            const duration = performance.now() - start;
            debugState.record(label, duration);

            if (duration > thresholdMs) {
                console.warn(`[VulnDash Perf] ${label} exceeded threshold: ${duration.toFixed(2)}ms (Limit: ${thresholdMs}ms)`);
            }
        }
    }

    /**
     * Safely wraps a synchronous function with performance timing.
     */
    public static measureSync<T>(
        label: string,
        thresholdMs: number,
        fn: () => T
    ): T {
        const debugState = PerfDebugState.getInstance();
        if (!debugState.isDebugActive) return fn();

        const start = performance.now();
        try {
            return fn();
        } finally {
            const duration = performance.now() - start;
            debugState.record(label, duration);

            if (duration > thresholdMs) {
                console.warn(`[VulnDash Perf] ${label} exceeded threshold: ${duration.toFixed(2)}ms (Limit: ${thresholdMs}ms)`);
            }
        }
    }
}

