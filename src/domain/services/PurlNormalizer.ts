export class PurlNormalizer {
    /**
     * Normalize a Package URL (PURL) into a deterministic canonical form.
     *
     * Normalization includes:
     * - Never throw on malformed input
     * - Normalize npm scoped packages (%40 -> @)
     * - Normalize casing for type / namespace / name
     * - Preserve version casing and content as much as possible
     * - Normalize qualifiers deterministically by lowercasing keys and sorting entries
     * - Keep delimiters structural: ?, &, =, #, /, @ are controlled only by reconstruction
     */
    public static normalize(purl: string | undefined | null): string | undefined {
        if (purl == null) {
            return undefined;
        }

        const raw = purl.trim();
        if (raw.length === 0) {
            return undefined;
        }

        if (!/^pkg:/i.test(raw)) {
            return PurlNormalizer.safeLooseNormalize(raw);
        }

        const parsed = PurlNormalizer.parsePurl(raw.substring(4));

        if (!parsed.type || !parsed.name) {
            return PurlNormalizer.safeLooseNormalize(raw);
        }

        const type = PurlNormalizer.normalizeType(parsed.type);
        const namespace = PurlNormalizer.normalizeNamespace(parsed.namespace);
        const name = PurlNormalizer.normalizeName(parsed.name);
        const version = PurlNormalizer.normalizeVersion(parsed.version);
        const qualifiers = PurlNormalizer.normalizeQualifiers(parsed.qualifiers);
        const subpath = PurlNormalizer.normalizeSubpath(parsed.subpath);

        let normalized = `pkg:${type}/`;

        if (namespace) {
            normalized += `${namespace}/`;
        }

        normalized += name;

        if (version) {
            normalized += `@${version}`;
        }

        if (qualifiers) {
            normalized += `?${qualifiers}`;
        }

        if (subpath) {
            normalized += `#${subpath}`;
        }

        return normalized;
    }

    private static parsePurl(value: string): ParsedPurl {
        let working = value.trim();

        let subpath: string | undefined;
        const hashIndex = working.indexOf('#');
        if (hashIndex >= 0) {
            subpath = working.substring(hashIndex + 1);
            working = working.substring(0, hashIndex);
        }

        let qualifiers: string | undefined;
        const queryIndex = working.indexOf('?');
        if (queryIndex >= 0) {
            qualifiers = working.substring(queryIndex + 1);
            working = working.substring(0, queryIndex);
        }

        let version: string | undefined;
        const versionIndex = PurlNormalizer.findVersionSeparator(working);
        if (versionIndex >= 0) {
            version = working.substring(versionIndex + 1);
            working = working.substring(0, versionIndex);
        }

        working = working.replace(/^\/+/, '').replace(/\/+$/, '');

        const firstSlash = working.indexOf('/');
        if (firstSlash < 0) {
            return {
                type: working,
                namespace: undefined,
                name: undefined,
                version,
                qualifiers,
                subpath,
            };
        }

        const type = working.substring(0, firstSlash);
        const remainder = working.substring(firstSlash + 1);

        const pathSegments = remainder
            .split('/')
            .map(segment => segment.trim())
            .filter(Boolean);

        if (pathSegments.length === 0) {
            return {
                type,
                namespace: undefined,
                name: undefined,
                version,
                qualifiers,
                subpath,
            };
        }

        const name = pathSegments[pathSegments.length - 1];
        const namespace =
            pathSegments.length > 1
                ? pathSegments.slice(0, pathSegments.length - 1).join('/')
                : undefined;

        return {
            type,
            namespace,
            name,
            version,
            qualifiers,
            subpath,
        };
    }

    /**
     * Find the @version separator, but avoid mistaking namespace scope markers
     * such as "@types" for a version delimiter.
     *
     * Examples:
     * - npm/@types/node@18.0.0  -> version separator is the last '@'
     * - npm/@angular/core       -> no version
     * - maven/org.example/app@1.0.0 -> version separator is the last '@'
     */
    private static findVersionSeparator(value: string): number {
        const lastAt = value.lastIndexOf('@');
        if (lastAt <= 0) {
            return -1;
        }

        const lastSlash = value.lastIndexOf('/');
        if (lastSlash > lastAt) {
            return -1;
        }

        return lastAt;
    }

    private static normalizeType(type: string): string {
        const decoded = PurlNormalizer.safeDecode(type).trim().toLowerCase();
        return PurlNormalizer.encodePathSegment(decoded);
    }

    private static normalizeNamespace(namespace: string | undefined): string | undefined {
        if (!namespace) {
            return undefined;
        }

        const normalized = namespace
            .split('/')
            .map(segment => PurlNormalizer.safeDecode(segment).trim().toLowerCase())
            .filter(Boolean)
            .map(segment => PurlNormalizer.encodePathSegment(segment, { preserveAtSign: true }))
            .join('/');

        return normalized || undefined;
    }

    private static normalizeName(name: string): string {
        const decoded = PurlNormalizer.safeDecode(name).trim().toLowerCase();
        return PurlNormalizer.encodePathSegment(decoded, { preserveAtSign: true });
    }

    private static normalizeVersion(version: string | undefined): string | undefined {
        if (!version) {
            return undefined;
        }

        const decoded = PurlNormalizer.safeDecode(version).trim();
        if (!decoded) {
            return undefined;
        }

        return PurlNormalizer.encodeVersion(decoded);
    }

    private static normalizeSubpath(subpath: string | undefined): string | undefined {
        if (!subpath) {
            return undefined;
        }

        const normalized = subpath
            .split('/')
            .map(segment => PurlNormalizer.safeDecode(segment).trim())
            .filter(Boolean)
            .map(segment => PurlNormalizer.encodeSubpathSegment(segment))
            .join('/');

        return normalized || undefined;
    }

    private static normalizeQualifiers(qualifiers: string | undefined): string | undefined {
        if (!qualifiers) {
            return undefined;
        }

        const entries: QualifierEntry[] = [];

        for (const pair of qualifiers.split('&')) {
            const trimmedPair = pair.trim();
            if (!trimmedPair) {
                continue;
            }

            const eqIndex = trimmedPair.indexOf('=');

            let rawKey: string;
            let rawValue: string;

            if (eqIndex < 0) {
                rawKey = trimmedPair;
                rawValue = '';
            } else {
                rawKey = trimmedPair.substring(0, eqIndex);
                rawValue = trimmedPair.substring(eqIndex + 1);
            }

            const decodedKey = PurlNormalizer.safeDecode(rawKey).trim().toLowerCase();
            const decodedValue = PurlNormalizer.safeDecode(rawValue).trim();

            if (!decodedKey) {
                continue;
            }

            entries.push({
                decodedKey,
                decodedValue,
                encodedKey: PurlNormalizer.encodeQualifierKey(decodedKey),
                encodedValue: PurlNormalizer.encodeQualifierValue(decodedValue),
            });
        }

        if (entries.length === 0) {
            return undefined;
        }

        entries.sort((a, b) => {
            const keyCompare = a.decodedKey.localeCompare(b.decodedKey);
            if (keyCompare !== 0) {
                return keyCompare;
            }

            return a.decodedValue.localeCompare(b.decodedValue);
        });

        return entries
            .map(entry => `${entry.encodedKey}=${entry.encodedValue}`)
            .join('&');
    }

    /**
     * Safely decode a URI component. If malformed percent-encoding exists,
     * fall back to a targeted replacement strategy instead of throwing.
     */
    private static safeDecode(value: string): string {
        if (!value) {
            return value;
        }

        try {
            return decodeURIComponent(value);
        } catch {
            return value
                .replace(/%40/gi, '@')
                .replace(/%2[fF]/g, '/')
                .replace(/%3[aA]/g, ':')
                .replace(/%23/gi, '#')
                .replace(/%3[fF]/g, '?')
                .replace(/%26/gi, '&')
                .replace(/%3[dD]/g, '=')
                .replace(/%2[bB]/g, '+')
                .replace(/%25/gi, '%')
                .replace(/%20/gi, ' ');
        }
    }

    /**
     * For non-PURL or malformed PURL-like strings, normalize loosely enough
     * to support deterministic matching without pretending strict spec fidelity.
     */
    private static safeLooseNormalize(value: string): string {
        const decoded = PurlNormalizer.safeDecode(value).trim().replace(/\s+/g, ' ');
        if (!decoded) {
            return undefined as unknown as string;
        }

        return decoded.replace(/\/{2,}/g, '/');
    }

    /**
     * Encode a path segment. Structural '/' is not allowed inside a segment.
     * For npm scopes in namespace/name, we preserve '@' for readability and matching.
     */
    private static encodePathSegment(
        value: string,
        options?: { preserveAtSign?: boolean }
    ): string {
        let encoded = encodeURIComponent(value);

        if (options?.preserveAtSign) {
            encoded = encoded.replace(/%40/gi, '@');
        }

        return encoded;
    }

    /**
     * Encode a version conservatively. We do not lowercase it.
     */
    private static encodeVersion(value: string): string {
        return encodeURIComponent(value);
    }

    /**
     * Encode a qualifier key. Keys are already lowercased before this point.
     */
    private static encodeQualifierKey(value: string): string {
        return encodeURIComponent(value);
    }

    /**
     * Encode a qualifier value safely so that '&' and '=' remain data, not delimiters.
     */
    private static encodeQualifierValue(value: string): string {
        return encodeURIComponent(value);
    }

    /**
     * Encode a subpath segment conservatively. '/' is handled structurally by join().
     */
    private static encodeSubpathSegment(value: string): string {
        return encodeURIComponent(value);
    }
}

interface ParsedPurl {
    type: string | undefined;
    namespace: string | undefined;
    name: string | undefined;
    version: string | undefined;
    qualifiers: string | undefined;
    subpath: string | undefined;
}

interface QualifierEntry {
    decodedKey: string;
    decodedValue: string;
    encodedKey: string;
    encodedValue: string;
}
