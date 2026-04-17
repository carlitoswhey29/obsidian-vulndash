import { Setting } from 'obsidian';
import { PerfDebugState } from '../../infrastructure/diagnostics/PerfDebugState';

export class PerfDiagnosticsSection {
    public static render(containerEl: HTMLElement): void {
        const debugState = PerfDebugState.getInstance();

        new Setting(containerEl)
            .setName('Enable Performance Diagnostics')
            .setDesc('Captures local performance metrics for UI renders, API fetches, and indexing. Warnings will appear in the developer console.')
            .addToggle(toggle => toggle
                .setValue(debugState.isDebugActive)
                .onChange(async (value) => {
                    if (value) {
                        debugState.enable();
                    } else {
                        debugState.disable();
                    }
                    // Typically requires UI refresh or saving to plugin settings if persistence is desired
                }));

        if (debugState.isDebugActive) {
            const summaryDiv = containerEl.createDiv({ cls: 'vulndash-perf-summary' });
            summaryDiv.createEl('h4', { text: 'Diagnostic Metrics (Last 100 events)' });

            const stats = debugState.getSummary();
            if (Object.keys(stats).length === 0) {
                summaryDiv.createEl('p', { text: 'No metrics recorded yet. Interact with the plugin to generate data.' });
            } else {
                const pre = summaryDiv.createEl('pre');
                pre.style.fontSize = '11px';
                pre.style.background = 'var(--background-secondary)';
                pre.style.padding = '8px';
                pre.style.borderRadius = '4px';

                let output = String().padEnd(25) + ' | AVG (ms) | MAX (ms) | COUNT\n';
                output += '-'.repeat(60) + '\n';

                for (const [label, data] of Object.entries(stats)) {
                    const l = label.padEnd(25);
                    const avg = data.avg.toFixed(2).padStart(8);
                    const max = data.max.toFixed(2).padStart(8);
                    const count = data.count.toString().padStart(5);
                    output += `${l} | ${avg} | ${max} | ${count}\n`;
                }
                pre.innerText = output;
            }
        }
    }
}
