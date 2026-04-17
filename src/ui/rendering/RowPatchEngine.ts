export interface RowPatchPlanInput {
  currentKeys: readonly string[];
  dirtyKeys?: ReadonlySet<string>;
  forcePatchAll?: boolean;
  nextKeys: readonly string[];
}

export interface RowPatchPlan {
  createKeys: readonly string[];
  patchKeys: readonly string[];
  removeKeys: readonly string[];
}

export const buildRowPatchPlan = ({
  currentKeys,
  dirtyKeys,
  forcePatchAll = false,
  nextKeys
}: RowPatchPlanInput): RowPatchPlan => {
  const currentKeySet = new Set(currentKeys);
  const nextKeySet = new Set(nextKeys);
  const safeDirtyKeys = dirtyKeys ?? new Set<string>();

  const createKeys: string[] = [];
  const patchKeys: string[] = [];
  const removeKeys: string[] = [];

  for (const key of currentKeys) {
    if (!nextKeySet.has(key)) {
      removeKeys.push(key);
    }
  }

  for (const key of nextKeys) {
    if (!currentKeySet.has(key)) {
      createKeys.push(key);
      continue;
    }

    if (forcePatchAll || safeDirtyKeys.has(key)) {
      patchKeys.push(key);
    }
  }

  return {
    createKeys,
    patchKeys,
    removeKeys
  };
};
