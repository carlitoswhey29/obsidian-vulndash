import type { ImportedSbomComponent, ImportedSbomConfig } from './types';

export interface SbomComparisonGroup {
  components: ImportedSbomComponent[];
  key: string;
  label: string;
}

export interface SbomComparisonChange {
  fields: string[];
  key: string;
  label: string;
  left: ImportedSbomComponent[];
  right: ImportedSbomComponent[];
}

export interface SbomComparisonResult {
  changed: SbomComparisonChange[];
  leftOnly: SbomComparisonGroup[];
  rightOnly: SbomComparisonGroup[];
  unchangedCount: number;
}

export class SbomComparisonService {
  public compare(left: ImportedSbomConfig, right: ImportedSbomConfig): SbomComparisonResult {
    const leftGroups = this.groupComponents(left.components);
    const rightGroups = this.groupComponents(right.components);
    const keys = Array.from(new Set([...leftGroups.keys(), ...rightGroups.keys()])).sort((a, b) => a.localeCompare(b));

    const changed: SbomComparisonChange[] = [];
    const leftOnly: SbomComparisonGroup[] = [];
    const rightOnly: SbomComparisonGroup[] = [];
    let unchangedCount = 0;

    for (const key of keys) {
      const leftGroup = leftGroups.get(key);
      const rightGroup = rightGroups.get(key);

      if (leftGroup && !rightGroup) {
        leftOnly.push(leftGroup);
        continue;
      }
      if (!leftGroup && rightGroup) {
        rightOnly.push(rightGroup);
        continue;
      }
      if (!leftGroup || !rightGroup) {
        continue;
      }

      const leftSignature = this.buildGroupSignature(leftGroup.components);
      const rightSignature = this.buildGroupSignature(rightGroup.components);
      if (leftSignature === rightSignature) {
        unchangedCount += 1;
        continue;
      }

      changed.push({
        fields: this.detectChangedFields(leftGroup.components, rightGroup.components),
        key,
        label: leftGroup.label,
        left: leftGroup.components,
        right: rightGroup.components
      });
    }

    return {
      changed,
      leftOnly,
      rightOnly,
      unchangedCount
    };
  }

  private groupComponents(components: ImportedSbomComponent[]): Map<string, SbomComparisonGroup> {
    const groups = new Map<string, SbomComparisonGroup>();

    for (const component of components) {
      const key = this.buildComparisonKey(component);
      const existing = groups.get(key);
      if (existing) {
        existing.components.push(component);
        existing.components.sort((left, right) => this.buildComponentSignature(left).localeCompare(this.buildComponentSignature(right)));
        continue;
      }

      groups.set(key, {
        components: [component],
        key,
        label: this.buildGroupLabel(component)
      });
    }

    return groups;
  }

  private buildComparisonKey(component: ImportedSbomComponent): string {
    return `${component.namespace.trim().toLowerCase()}|${(component.normalizedName.trim() || component.name.trim()).toLowerCase()}`;
  }

  private buildGroupLabel(component: ImportedSbomComponent): string {
    const name = component.normalizedName.trim() || component.name.trim() || component.id;
    const namespace = component.namespace.trim();
    return namespace ? `${namespace} / ${name}` : name;
  }

  private buildGroupSignature(components: ImportedSbomComponent[]): string {
    return components
      .map((component) => this.buildComponentSignature(component))
      .sort((left, right) => left.localeCompare(right))
      .join('||');
  }

  private buildComponentSignature(component: ImportedSbomComponent): string {
    return [
      component.name.trim(),
      component.normalizedName.trim(),
      component.version.trim(),
      component.purl.trim(),
      component.cpe.trim(),
      component.bomRef.trim(),
      component.enabled ? 'enabled' : 'disabled',
      component.excluded ? 'excluded' : 'included'
    ].join('|');
  }

  private detectChangedFields(left: ImportedSbomComponent[], right: ImportedSbomComponent[]): string[] {
    const leftJoined = this.joinFieldValues(left);
    const rightJoined = this.joinFieldValues(right);
    const changedFields: string[] = [];
    const fields: Array<keyof ReturnType<SbomComparisonService['joinFieldValues']>> = [
      'names',
      'versions',
      'purls',
      'cpes',
      'bomRefs',
      'enabledStates',
      'excludedStates'
    ];

    for (const field of fields) {
      if (leftJoined[field] !== rightJoined[field]) {
        changedFields.push(field);
      }
    }

    return changedFields;
  }

  private joinFieldValues(components: ImportedSbomComponent[]): {
    bomRefs: string;
    cpes: string;
    enabledStates: string;
    excludedStates: string;
    names: string;
    purls: string;
    versions: string;
  } {
    const sorted = [...components].sort((left, right) => this.buildComponentSignature(left).localeCompare(this.buildComponentSignature(right)));
    return {
      bomRefs: sorted.map((component) => component.bomRef.trim()).join(','),
      cpes: sorted.map((component) => component.cpe.trim()).join(','),
      enabledStates: sorted.map((component) => (component.enabled ? 'enabled' : 'disabled')).join(','),
      excludedStates: sorted.map((component) => (component.excluded ? 'excluded' : 'included')).join(','),
      names: sorted.map((component) => `${component.name.trim()}|${component.normalizedName.trim()}`).join(','),
      purls: sorted.map((component) => component.purl.trim()).join(','),
      versions: sorted.map((component) => component.version.trim()).join(',')
    };
  }
}
