export interface CommandRegistrar {
  addCommand(command: {
    readonly callback: () => void;
    readonly id: string;
    readonly name: string;
  }): void;
}

export class GenerateDailyRollupCommand {
  public constructor(
    private readonly onGenerate: () => Promise<void>
  ) {}

  public register(registrar: CommandRegistrar): void {
    registrar.addCommand({
      callback: () => {
        void this.onGenerate();
      },
      id: 'vulndash-generate-daily-rollup',
      name: 'Generate daily threat briefing'
    });
  }
}
