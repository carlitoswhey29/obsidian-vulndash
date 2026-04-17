export class PerfDebugState {
    private static instance: PerfDebugState;
    private isEnabled: boolean = false;
    private metrics: Map<string, number[]> = new Map();

    private constructor() {}

    public static getInstance(): PerfDebugState {
        if (!PerfDebugState.instance) {
            PerfDebugState.instance = new PerfDebugState();
        }
        return PerfDebugState.instance;
    }

    public enable(): void {
        this.isEnabled = true;
    }

    public disable(): void {
        this.isEnabled = false;
        this.metrics.clear();
    }

    public get isDebugActive(): boolean {
        return this.isEnabled;
    }

    public record(label: string, durationMs: number): void {
        if (!this.isEnabled) return;

        if (!this.metrics.has(label)) {
            this.metrics.set(label, []);
        }

        const series = this.metrics.get(label)!;
        series.push(durationMs);
        if (series.length > 100) series.shift(); // Keep last 100 samples
    }

    public getSummary(): Record<string, { avg: number, max: number, count: number }> {
        const summary: Record<string, { avg: number, max: number, count: number }> = {};
        for (const [label, times] of this.metrics.entries()) {
            if (times.length === 0) continue;
            const max = Math.max(...times);
            const avg = times.reduce((a, b) => a + b, 0) / times.length;
            summary[label] = { avg, max, count: times.length };
        }
        return summary;
    }
}
