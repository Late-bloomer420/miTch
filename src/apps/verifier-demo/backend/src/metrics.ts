export class SimpleMetrics {
    private counters = new Map<string, number>();
    private gauges = new Map<string, number>();

    inc(key: string, delta = 1) {
        this.counters.set(key, (this.counters.get(key) || 0) + delta);
    }

    gauge(key: string, value: number) {
        this.gauges.set(key, value);
    }

    get() {
        return {
            counters: Object.fromEntries(this.counters),
            gauges: Object.fromEntries(this.gauges)
        };
    }

    reset() {
        this.counters.clear();
        this.gauges.clear();
    }
}
