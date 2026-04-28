export const FEED_TYPES = {
  GENERIC_JSON: 'generic_json',
  GITHUB_ADVISORY: 'github_advisory',
  GITHUB_REPO: 'github_repo',
  NVD: 'nvd',
  OSV: 'osv'
} as const;

export type FeedType = (typeof FEED_TYPES)[keyof typeof FEED_TYPES];

export interface FeedIdentity<TType extends FeedType = FeedType> {
  readonly id: string;
  readonly name: string;
  readonly type: TType;
}

interface BuiltInFeedDefinition<TType extends FeedType> extends FeedIdentity<TType> {
  readonly legacyCursorKey?: string;
  readonly legacySourceAliases?: readonly string[];
}

export const BUILT_IN_FEEDS = {
  GITHUB_ADVISORY: {
    id: 'github-advisories-default',
    legacyCursorKey: 'GitHub',
    legacySourceAliases: ['github'],
    name: 'GitHub',
    type: FEED_TYPES.GITHUB_ADVISORY
  },
  NVD: {
    id: 'nvd-default',
    legacyCursorKey: 'NVD',
    legacySourceAliases: [FEED_TYPES.NVD],
    name: 'NVD',
    type: FEED_TYPES.NVD
  },
  OSV: {
    id: 'osv-default',
    legacySourceAliases: [FEED_TYPES.OSV],
    name: 'OSV',
    type: FEED_TYPES.OSV
  }
} as const satisfies Record<string, BuiltInFeedDefinition<FeedType>>;
