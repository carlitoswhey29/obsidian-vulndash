const NUMERIC_SCORE_PATTERN = /^(?:\d+|\d*\.\d+)$/;

const roundToNearestTenth = (value: number): number => Math.round(value * 10) / 10;

const roundUpToTenth = (value: number): number => Math.ceil((value * 10) - 1e-8) / 10;

const clampScore = (value: number): number => Math.max(0, Math.min(10, value));

const parseNumericScore = (value: string): number | undefined => {
  const normalized = value.trim();
  if (!NUMERIC_SCORE_PATTERN.test(normalized)) {
    return undefined;
  }

  const parsed = Number.parseFloat(normalized);
  if (!Number.isFinite(parsed) || parsed < 0 || parsed > 10) {
    return undefined;
  }

  return parsed;
};

const parseMetricPairs = (vector: string, prefixPattern: RegExp): Readonly<Record<string, string>> | undefined => {
  const withoutPrefix = vector.trim().replace(prefixPattern, '');
  const segments = withoutPrefix.split('/').filter((segment) => segment.length > 0);
  if (segments.length === 0) {
    return undefined;
  }

  const metrics: Record<string, string> = {};
  for (const segment of segments) {
    const separatorIndex = segment.indexOf(':');
    if (separatorIndex <= 0 || separatorIndex >= segment.length - 1) {
      return undefined;
    }

    const key = segment.slice(0, separatorIndex).trim().toUpperCase();
    const value = segment.slice(separatorIndex + 1).trim().toUpperCase();
    if (!key || !value) {
      return undefined;
    }

    metrics[key] = value;
  }

  return metrics;
};

const parseCvssV3Score = (vector: string): number | undefined => {
  const metrics = parseMetricPairs(vector, /^CVSS:3\.[01]\//i);
  if (!metrics) {
    return undefined;
  }

  const attackVector = {
    N: 0.85,
    A: 0.62,
    L: 0.55,
    P: 0.2
  }[metrics.AV ?? ''];
  const attackComplexity = {
    L: 0.77,
    H: 0.44
  }[metrics.AC ?? ''];
  const userInteraction = {
    N: 0.85,
    R: 0.62
  }[metrics.UI ?? ''];
  const scope = metrics.S;
  const confidentiality = {
    H: 0.56,
    L: 0.22,
    N: 0
  }[metrics.C ?? ''];
  const integrity = {
    H: 0.56,
    L: 0.22,
    N: 0
  }[metrics.I ?? ''];
  const availability = {
    H: 0.56,
    L: 0.22,
    N: 0
  }[metrics.A ?? ''];

  if (
    attackVector === undefined
    || attackComplexity === undefined
    || userInteraction === undefined
    || (scope !== 'U' && scope !== 'C')
    || confidentiality === undefined
    || integrity === undefined
    || availability === undefined
  ) {
    return undefined;
  }

  const privilegesRequired = ({
    U: {
      N: 0.85,
      L: 0.62,
      H: 0.27
    },
    C: {
      N: 0.85,
      L: 0.68,
      H: 0.5
    }
  } as const)[scope][metrics.PR as 'N' | 'L' | 'H'];
  if (privilegesRequired === undefined) {
    return undefined;
  }

  const impactSubScore = 1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability));
  const impact = scope === 'U'
    ? 6.42 * impactSubScore
    : (7.52 * (impactSubScore - 0.029)) - (3.25 * Math.pow(impactSubScore - 0.02, 15));
  if (impact <= 0) {
    return 0;
  }

  const exploitability = 8.22 * attackVector * attackComplexity * privilegesRequired * userInteraction;
  const baseScore = scope === 'U'
    ? Math.min(impact + exploitability, 10)
    : Math.min(1.08 * (impact + exploitability), 10);

  return roundUpToTenth(clampScore(baseScore));
};

const parseCvssV2Score = (vector: string): number | undefined => {
  const metrics = parseMetricPairs(vector, /^(?:CVSS:2\.0\/|CVSS2#)/i);
  if (!metrics) {
    return undefined;
  }

  const accessVector = {
    L: 0.395,
    A: 0.646,
    N: 1
  }[metrics.AV ?? ''];
  const accessComplexity = {
    H: 0.35,
    M: 0.61,
    L: 0.71
  }[metrics.AC ?? ''];
  const authentication = {
    M: 0.45,
    S: 0.56,
    N: 0.704
  }[metrics.AU ?? ''];
  const confidentiality = {
    N: 0,
    P: 0.275,
    C: 0.66
  }[metrics.C ?? ''];
  const integrity = {
    N: 0,
    P: 0.275,
    C: 0.66
  }[metrics.I ?? ''];
  const availability = {
    N: 0,
    P: 0.275,
    C: 0.66
  }[metrics.A ?? ''];

  if (
    accessVector === undefined
    || accessComplexity === undefined
    || authentication === undefined
    || confidentiality === undefined
    || integrity === undefined
    || availability === undefined
  ) {
    return undefined;
  }

  const impact = 10.41 * (1 - ((1 - confidentiality) * (1 - integrity) * (1 - availability)));
  const exploitability = 20 * accessVector * accessComplexity * authentication;
  const impactFactor = impact === 0 ? 0 : 1.176;
  const baseScore = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * impactFactor;

  return roundToNearestTenth(clampScore(baseScore));
};

export const parseCvssScore = (value: string, type?: string): number | undefined => {
  const numericScore = parseNumericScore(value);
  if (numericScore !== undefined) {
    return numericScore;
  }

  const normalizedType = type?.trim().toUpperCase() ?? '';
  if (value.trim().toUpperCase().startsWith('CVSS:3.') || normalizedType.includes('V3')) {
    return parseCvssV3Score(value);
  }

  if (value.trim().toUpperCase().startsWith('CVSS:2.0/') || normalizedType.includes('V2')) {
    return parseCvssV2Score(value);
  }

  return undefined;
};
