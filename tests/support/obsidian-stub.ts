export const normalizePath = (path: string): string =>
  path.replace(/\\/g, '/').replace(/\/+/g, '/').replace(/^\.\//, '');

export class App {}

export class Component {}

export class Modal {
  public constructor(_app?: App) {}
}

export class FuzzySuggestModal<T> extends Modal {
  public open(): void {}
  protected getItems(): T[] {
    return [];
  }
}

export interface FuzzyMatch {
  readonly score?: number;
}

export class Notice {
  public constructor(_message?: string, _timeout?: number) {}
}

export class Plugin {
  public app = new App();
  public addCommand(): void {}
  public addRibbonIcon(): void {}
  public addSettingTab(): void {}
  public registerEvent(): void {}
  public registerView(): void {}
}

export class PluginSettingTab {
  public containerEl = createDiv();

  public constructor(_app?: App, _plugin?: Plugin) {}
}

export class ItemView {
  public contentEl = createDiv();

  public constructor(_leaf?: WorkspaceLeaf) {}
}

export class Setting {
  public constructor(_containerEl?: HTMLElement) {}
  public setName(_name: string): this { return this; }
  public setDesc(_description: string): this { return this; }
  public addToggle(callback: (component: ToggleComponent) => void): this {
    callback(new ToggleComponent());
    return this;
  }
  public addDropdown(callback: (component: DropdownComponent) => void): this {
    callback(new DropdownComponent());
    return this;
  }
  public addText(callback: (component: TextComponent) => void): this {
    callback(new TextComponent());
    return this;
  }
  public addButton(callback: (component: ButtonComponent) => void): this {
    callback(new ButtonComponent());
    return this;
  }
}

export class TextComponent {
  public inputEl = createInput();
  public setPlaceholder(_value: string): this { return this; }
  public setValue(_value: string): this { return this; }
  public onChange(_callback: (value: string) => void): this { return this; }
}

export class ToggleComponent {
  public setValue(_value: boolean): this { return this; }
  public onChange(_callback: (value: boolean) => void): this { return this; }
}

export class DropdownComponent {
  public addOption(_value: string, _label: string): this { return this; }
  public setValue(_value: string): this { return this; }
  public onChange(_callback: (value: string) => void): this { return this; }
}

export class ButtonComponent {
  public setButtonText(_value: string): this { return this; }
  public onClick(_callback: () => void): this { return this; }
}

export class WorkspaceLeaf {}

export class TAbstractFile {
  public path = '';
}

export class TFile extends TAbstractFile {}

export const MarkdownRenderer = {
  render: async (): Promise<void> => undefined
};

export const requestUrl = async (): Promise<never> => {
  throw new Error('requestUrl not implemented in test stub.');
};

export const setIcon = (): void => {};

const createInput = (): HTMLInputElement => ({
  addEventListener: () => undefined
}) as unknown as HTMLInputElement;

const createDiv = (): HTMLElement => ({
  addClass: () => undefined,
  appendChild: () => undefined,
  createDiv,
  createEl: () => createDiv(),
  empty: () => undefined,
  removeClass: () => undefined,
  setText: () => undefined,
  style: {}
}) as unknown as HTMLElement;
