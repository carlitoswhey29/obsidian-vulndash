import type { VulnDashSettings } from '../use-cases/types';
import type { ComponentCatalog, TrackedComponent } from './types';

type ComponentPreferenceSettings = Pick<VulnDashSettings, 'disabledSbomComponentKeys' | 'followedSbomComponentKeys'>;

interface ComponentPreferenceState {
  disabledKeys: Set<string>;
  followedKeys: Set<string>;
}

const compareKeys = (left: string, right: string): number =>
  left.localeCompare(right);

const normalizeComponentKey = (key: string): string =>
  key.trim().toLowerCase();

const normalizeStoredKeys = (values: unknown): string[] => {
  if (!Array.isArray(values)) {
    return [];
  }

  const normalized = new Set<string>();

  for (const value of values) {
    if (typeof value !== 'string') {
      continue;
    }

    const normalizedValue = normalizeComponentKey(value);
    if (normalizedValue) {
      normalized.add(normalizedValue);
    }
  }

  return Array.from(normalized).sort(compareKeys);
};

const createPreferenceState = (
  settings: Partial<ComponentPreferenceSettings>
): ComponentPreferenceState => ({
  disabledKeys: new Set(normalizeStoredKeys(settings.disabledSbomComponentKeys)),
  followedKeys: new Set(normalizeStoredKeys(settings.followedSbomComponentKeys))
});

const createTrackedComponentWithPreferences = (
  component: TrackedComponent,
  state: ComponentPreferenceState
): TrackedComponent => {
  const normalizedKey = normalizeComponentKey(component.key);

  return {
    ...component,
    isEnabled: !state.disabledKeys.has(normalizedKey),
    isFollowed: state.followedKeys.has(normalizedKey)
  };
};

export class ComponentPreferenceService {
  public normalizeSettings<T extends ComponentPreferenceSettings>(settings: T): T {
    return {
      ...settings,
      disabledSbomComponentKeys: normalizeStoredKeys(settings.disabledSbomComponentKeys),
      followedSbomComponentKeys: normalizeStoredKeys(settings.followedSbomComponentKeys)
    };
  }

  public isFollowed(key: string, settings: Partial<ComponentPreferenceSettings>): boolean {
    const normalizedKey = normalizeComponentKey(key);
    if (!normalizedKey) {
      return false;
    }

    return createPreferenceState(settings).followedKeys.has(normalizedKey);
  }

  public isEnabled(key: string, settings: Partial<ComponentPreferenceSettings>): boolean {
    const normalizedKey = normalizeComponentKey(key);
    if (!normalizedKey) {
      return true;
    }

    return !createPreferenceState(settings).disabledKeys.has(normalizedKey);
  }

  public follow<T extends ComponentPreferenceSettings>(key: string, settings: T): T {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.followedKeys.add(normalizedKey);
    }, key);
  }

  public unfollow<T extends ComponentPreferenceSettings>(key: string, settings: T): T {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.followedKeys.delete(normalizedKey);
    }, key);
  }

  public disable<T extends ComponentPreferenceSettings>(key: string, settings: T): T {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.disabledKeys.add(normalizedKey);
    }, key);
  }

  public enable<T extends ComponentPreferenceSettings>(key: string, settings: T): T {
    return this.updateSettings(settings, (state, normalizedKey) => {
      state.disabledKeys.delete(normalizedKey);
    }, key);
  }

  public applyPreferences(
    catalog: ComponentCatalog,
    settings: Partial<ComponentPreferenceSettings>
  ): ComponentCatalog {
    const state = createPreferenceState(settings);

    return {
      ...catalog,
      components: catalog.components.map((component) => createTrackedComponentWithPreferences(component, state))
    };
  }

  private updateSettings<T extends ComponentPreferenceSettings>(
    settings: T,
    update: (state: ComponentPreferenceState, normalizedKey: string) => void,
    key: string
  ): T {
    const state = createPreferenceState(settings);
    const normalizedKey = normalizeComponentKey(key);

    if (normalizedKey) {
      update(state, normalizedKey);
    }

    return {
      ...settings,
      disabledSbomComponentKeys: Array.from(state.disabledKeys).sort(compareKeys),
      followedSbomComponentKeys: Array.from(state.followedKeys).sort(compareKeys)
    };
  }
}
