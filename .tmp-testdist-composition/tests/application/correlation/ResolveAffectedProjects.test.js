// tests/application/correlation/ResolveAffectedProjects.test.ts
import assert from "node:assert/strict";
import test from "node:test";

// src/application/sbom/ComponentIdentityService.ts
var UNNAMED_COMPONENT_PATTERN = /^unnamed (component|package)( \d+)?$/i;
var normalizeToken = (value) => value.trim().replace(/\s+/g, " ").toLowerCase();
var normalizePurl = (value) => normalizeToken(value);
var normalizeCpe = (value) => normalizeToken(value);
var normalizeComponentName = (value) => {
  if (!value) {
    return void 0;
  }
  const normalized = normalizeToken(value);
  if (!normalized || UNNAMED_COMPONENT_PATTERN.test(normalized)) {
    return void 0;
  }
  return normalized;
};
var normalizeVersion = (value) => {
  if (!value) {
    return void 0;
  }
  const normalized = normalizeToken(value);
  return normalized || void 0;
};
var ComponentIdentityService = class {
  normalizePurlValue(value) {
    return normalizePurl(value);
  }
  normalizeCpeValue(value) {
    return normalizeCpe(value);
  }
  normalizeComponentNameValue(value) {
    return normalizeComponentName(value);
  }
  normalizeVersionValue(value) {
    return normalizeVersion(value);
  }
  getNameVersionKeyFromParts(name, version) {
    const normalizedName = normalizeComponentName(name);
    const normalizedVersion = normalizeVersion(version);
    if (!normalizedName || !normalizedVersion) {
      return null;
    }
    return `name-version:${normalizedName}@${normalizedVersion}`;
  }
  getCanonicalKey(component) {
    const purl = component.purl?.trim();
    if (purl) {
      return `purl:${normalizePurl(purl)}`;
    }
    const cpe = component.cpe?.trim();
    if (cpe) {
      return `cpe:${normalizeCpe(cpe)}`;
    }
    const name = normalizeComponentName(component.name);
    const version = normalizeVersion(component.version);
    if (name && version) {
      return `name-version:${name}@${version}`;
    }
    if (name) {
      return `name:${name}`;
    }
    const fallbackParts = [
      component.supplier,
      component.license,
      component.notePath ?? void 0
    ].map((value) => value?.trim()).filter((value) => Boolean(value)).map((value) => normalizeToken(value));
    if (fallbackParts.length > 0) {
      return `unresolved:${fallbackParts.join("|")}`;
    }
    return "unresolved:component";
  }
};

// src/application/sbom/RelationshipNormalizer.ts
var evidenceRank = {
  purl: 0,
  cpe: 1,
  "name-version": 2,
  explicit: 3
};
var compareStrings = (left, right) => left.localeCompare(right);
var compareOptionalStrings = (left, right) => (left ?? "").localeCompare(right ?? "");
var severityRank = (severity) => {
  switch (severity) {
    case "CRITICAL":
      return 4;
    case "HIGH":
      return 3;
    case "MEDIUM":
      return 2;
    case "LOW":
      return 1;
    default:
      return 0;
  }
};
var RelationshipNormalizer = class {
  constructor(identityService = new ComponentIdentityService()) {
    this.identityService = identityService;
  }
  buildVulnerabilityRef(vulnerability) {
    return `${this.normalizeVulnerabilityToken(vulnerability.source)}::${this.normalizeVulnerabilityToken(vulnerability.id)}`;
  }
  normalizeRelationshipGraph(relationships, componentsByKey, vulnerabilitiesByRef) {
    const dedupedByPair = /* @__PURE__ */ new Map();
    for (const relationship of relationships) {
      const normalized = this.normalizeRelationship(relationship);
      const pairKey = `${normalized.componentKey}||${normalized.vulnerabilityRef}`;
      const existing = dedupedByPair.get(pairKey);
      if (!existing || evidenceRank[normalized.evidence] < evidenceRank[existing.evidence]) {
        dedupedByPair.set(pairKey, normalized);
      }
    }
    const normalizedRelationships = Array.from(dedupedByPair.values()).sort(
      (left, right) => compareStrings(left.componentKey, right.componentKey) || compareStrings(left.vulnerabilityRef, right.vulnerabilityRef) || evidenceRank[left.evidence] - evidenceRank[right.evidence]
    );
    const componentsByVulnerability = /* @__PURE__ */ new Map();
    const vulnerabilitiesByComponent = /* @__PURE__ */ new Map();
    for (const relationship of normalizedRelationships) {
      const component = componentsByKey.get(relationship.componentKey);
      const vulnerability = vulnerabilitiesByRef.get(relationship.vulnerabilityRef);
      if (!component || !vulnerability) {
        continue;
      }
      const relatedComponent = this.toRelatedComponentSummary(component, relationship.evidence);
      const relatedVulnerability = this.toRelatedVulnerabilitySummary(vulnerability, relationship.evidence);
      const componentList = componentsByVulnerability.get(relationship.vulnerabilityRef) ?? [];
      componentList.push(relatedComponent);
      componentsByVulnerability.set(relationship.vulnerabilityRef, componentList);
      const vulnerabilityList = vulnerabilitiesByComponent.get(relationship.componentKey) ?? [];
      vulnerabilityList.push(relatedVulnerability);
      vulnerabilitiesByComponent.set(relationship.componentKey, vulnerabilityList);
    }
    for (const [key, entries] of componentsByVulnerability) {
      componentsByVulnerability.set(key, entries.sort(
        (left, right) => evidenceRank[left.evidence] - evidenceRank[right.evidence] || compareStrings(left.name, right.name) || compareOptionalStrings(left.version, right.version) || compareStrings(left.key, right.key)
      ));
    }
    for (const [key, entries] of vulnerabilitiesByComponent) {
      vulnerabilitiesByComponent.set(key, entries.sort(
        (left, right) => evidenceRank[left.evidence] - evidenceRank[right.evidence] || severityRank(right.severity) - severityRank(left.severity) || compareStrings(left.source, right.source) || compareStrings(left.id, right.id)
      ));
    }
    return {
      componentsByVulnerability,
      relationships: normalizedRelationships,
      vulnerabilitiesByComponent
    };
  }
  buildVulnerabilityIdentity(vulnerability, notePath) {
    const identifiers = new Set([
      vulnerability.id,
      vulnerability.metadata?.cveId ?? "",
      vulnerability.metadata?.ghsaId ?? "",
      ...vulnerability.metadata?.identifiers ?? [],
      ...vulnerability.metadata?.aliases ?? []
    ].map((value) => this.normalizeVulnerabilityToken(value)).filter(Boolean));
    return {
      id: vulnerability.id,
      identifiers: Array.from(identifiers).sort(compareStrings),
      ...notePath ? { notePath } : {},
      ref: this.buildVulnerabilityRef(vulnerability),
      source: vulnerability.source
    };
  }
  buildPurlKey(value) {
    return `purl:${this.identityService.normalizePurlValue(value)}`;
  }
  buildCpeKey(value) {
    return `cpe:${this.identityService.normalizeCpeValue(value)}`;
  }
  buildNameVersionKey(name, version) {
    return this.identityService.getNameVersionKeyFromParts(name, version);
  }
  normalizeVulnerabilityToken(value) {
    return value.trim().replace(/\s+/g, " ").toLowerCase();
  }
  normalizeRelationship(relationship) {
    return {
      componentKey: relationship.componentKey.trim().toLowerCase(),
      evidence: relationship.evidence,
      vulnerabilityId: relationship.vulnerabilityId.trim(),
      vulnerabilityRef: relationship.vulnerabilityRef.trim().toLowerCase(),
      vulnerabilitySource: relationship.vulnerabilitySource.trim()
    };
  }
  toRelatedComponentSummary(component, evidence) {
    const summary = {
      evidence,
      key: component.key,
      name: component.name,
      vulnerabilityCount: component.vulnerabilityCount
    };
    if (component.version) {
      summary.version = component.version;
    }
    if (component.purl) {
      summary.purl = component.purl;
    }
    if (component.cpe) {
      summary.cpe = component.cpe;
    }
    if (component.notePath !== void 0) {
      summary.notePath = component.notePath;
    }
    if (component.highestSeverity) {
      summary.highestSeverity = component.highestSeverity;
    }
    return summary;
  }
  toRelatedVulnerabilitySummary(vulnerability, evidence) {
    const summary = {
      cvssScore: vulnerability.cvssScore,
      evidence,
      id: vulnerability.id,
      referenceCount: vulnerability.references.length,
      severity: vulnerability.severity,
      source: vulnerability.source,
      title: vulnerability.title
    };
    if (vulnerability.notePath) {
      summary.notePath = vulnerability.notePath;
    }
    return summary;
  }
};

// src/domain/correlation/AffectedProjectResolution.ts
var EMPTY_AFFECTED_PROJECT_RESOLUTION = {
  affectedProjects: [],
  unmappedSboms: []
};

// src/application/correlation/ResolveAffectedProjects.ts
var compareAffectedProjects = (left, right) => left.status.localeCompare(right.status) || left.displayName.localeCompare(right.displayName) || left.notePath.localeCompare(right.notePath);
var compareUnmappedSboms = (left, right) => left.sbomLabel.localeCompare(right.sbomLabel) || left.sbomId.localeCompare(right.sbomId);
var ResolveAffectedProjects = class {
  constructor(mappingRepository, projectNoteLookup, relationshipNormalizer = new RelationshipNormalizer()) {
    this.mappingRepository = mappingRepository;
    this.projectNoteLookup = projectNoteLookup;
    this.relationshipNormalizer = relationshipNormalizer;
  }
  async execute(input) {
    if (input.vulnerabilities.length === 0) {
      return /* @__PURE__ */ new Map();
    }
    const mappings = await this.mappingRepository.list();
    const mappingsBySbomId = new Map(mappings.map((mapping) => [mapping.sbomId, mapping.projectNote]));
    const noteStates = await this.projectNoteLookup.getByPaths(mappings.map((mapping) => mapping.projectNote));
    const sbomsById = new Map(input.sboms.map((sbom) => [sbom.id, sbom]));
    const results = /* @__PURE__ */ new Map();
    for (const vulnerability of input.vulnerabilities) {
      const vulnerabilityRef = this.relationshipNormalizer.buildVulnerabilityRef(vulnerability);
      const relatedComponents = input.relationships.componentsByVulnerability.get(vulnerabilityRef) ?? [];
      if (relatedComponents.length === 0) {
        results.set(vulnerabilityRef, EMPTY_AFFECTED_PROJECT_RESOLUTION);
        continue;
      }
      const matchedSbomIds = /* @__PURE__ */ new Set();
      for (const component of relatedComponents) {
        for (const sbomId of input.componentIndex.getSbomIdsForComponent(component.key)) {
          matchedSbomIds.add(sbomId);
        }
      }
      if (matchedSbomIds.size === 0) {
        results.set(vulnerabilityRef, EMPTY_AFFECTED_PROJECT_RESOLUTION);
        continue;
      }
      const aggregatedProjects = /* @__PURE__ */ new Map();
      const unmappedSboms = /* @__PURE__ */ new Map();
      for (const sbomId of matchedSbomIds) {
        const sbom = sbomsById.get(sbomId);
        if (!sbom) {
          continue;
        }
        const mapping = mappingsBySbomId.get(sbomId);
        if (!mapping) {
          unmappedSboms.set(sbomId, {
            sbomId,
            sbomLabel: sbom.label
          });
          continue;
        }
        const noteState = noteStates.get(mapping.notePath) ?? {
          displayName: mapping.displayName ?? sbom.label,
          notePath: mapping.notePath,
          status: "broken"
        };
        const existing = aggregatedProjects.get(noteState.notePath);
        if (existing) {
          existing.sourceSbomIds.add(sbom.id);
          existing.sourceSbomLabels.add(sbom.label);
          continue;
        }
        aggregatedProjects.set(noteState.notePath, {
          displayName: noteState.displayName,
          notePath: noteState.notePath,
          sourceSbomIds: /* @__PURE__ */ new Set([sbom.id]),
          sourceSbomLabels: /* @__PURE__ */ new Set([sbom.label]),
          status: noteState.status
        });
      }
      results.set(vulnerabilityRef, {
        affectedProjects: Array.from(aggregatedProjects.values()).map((project) => ({
          displayName: project.displayName,
          notePath: project.notePath,
          sourceSbomIds: Array.from(project.sourceSbomIds).sort((left, right) => left.localeCompare(right)),
          sourceSbomLabels: Array.from(project.sourceSbomLabels).sort((left, right) => left.localeCompare(right)),
          status: project.status
        })).sort(compareAffectedProjects),
        unmappedSboms: Array.from(unmappedSboms.values()).sort(compareUnmappedSboms)
      });
    }
    return results;
  }
};

// src/domain/correlation/ProjectNoteReference.ts
var normalizeProjectNotePathValue = (value) => value.trim().replace(/\\/g, "/").replace(/\/+/g, "/").replace(/^\.?\//, "");
var createProjectNoteReference = (notePath, displayName) => {
  const normalizedPath = normalizeProjectNotePathValue(notePath);
  if (!normalizedPath) {
    throw new Error("Project note path is required.");
  }
  const normalizedDisplayName = displayName?.trim();
  if (!normalizedDisplayName) {
    return {
      notePath: normalizedPath
    };
  }
  return {
    displayName: normalizedDisplayName,
    notePath: normalizedPath
  };
};

// src/domain/correlation/SbomProjectMapping.ts
var createSbomProjectMapping = (sbomId, projectNote) => {
  const normalizedSbomId = sbomId.trim();
  if (!normalizedSbomId) {
    throw new Error("SBOM identifier is required.");
  }
  return {
    projectNote,
    sbomId: normalizedSbomId
  };
};

// tests/application/correlation/ResolveAffectedProjects.test.ts
var createVulnerability = (overrides = {}) => ({
  affectedProducts: ["portal"],
  cvssScore: 9.1,
  id: "CVE-2026-1000",
  publishedAt: "2026-04-10T00:00:00.000Z",
  references: [],
  severity: "CRITICAL",
  source: "NVD",
  summary: "demo",
  title: "demo vuln",
  updatedAt: "2026-04-10T00:00:00.000Z",
  ...overrides
});
var repository = {
  deleteBySbomId: async () => void 0,
  getBySbomId: async () => null,
  list: async () => [
    createSbomProjectMapping("sbom-1", createProjectNoteReference("Projects/Portal.md", "Portal Platform")),
    createSbomProjectMapping("sbom-2", createProjectNoteReference("Projects/Portal.md", "Portal Platform")),
    createSbomProjectMapping("sbom-4", createProjectNoteReference("Projects/Missing.md", "Legacy Platform"))
  ],
  replaceNotePath: async () => 0,
  save: async () => void 0
};
var lookup = {
  getByPaths: async () => /* @__PURE__ */ new Map([
    ["Projects/Portal.md", {
      displayName: "Portal Platform",
      notePath: "Projects/Portal.md",
      status: "linked"
    }],
    ["Projects/Missing.md", {
      displayName: "Legacy Platform",
      notePath: "Projects/Missing.md",
      status: "broken"
    }]
  ])
};
test("ResolveAffectedProjects deduplicates shared project notes and surfaces unmapped sboms", async () => {
  const resolver = new ResolveAffectedProjects(repository, lookup);
  const vulnerability = createVulnerability();
  const graph = {
    componentsByVulnerability: /* @__PURE__ */ new Map([[
      "nvd::cve-2026-1000",
      [{
        evidence: "purl",
        key: "pkg:npm/portal@1.0.0",
        name: "portal",
        vulnerabilityCount: 1
      }]
    ]]),
    relationships: [],
    vulnerabilitiesByComponent: /* @__PURE__ */ new Map()
  };
  const result = await resolver.execute({
    componentIndex: {
      getSbomIdsForComponent: () => ["sbom-1", "sbom-2", "sbom-3"]
    },
    relationships: graph,
    sboms: [
      { id: "sbom-1", label: "Portal API" },
      { id: "sbom-2", label: "Portal Web" },
      { id: "sbom-3", label: "Gateway" }
    ],
    vulnerabilities: [vulnerability]
  });
  const resolution = result.get("nvd::cve-2026-1000");
  assert.ok(resolution);
  assert.equal(resolution?.affectedProjects.length, 1);
  assert.deepEqual(resolution?.affectedProjects[0]?.sourceSbomLabels, ["Portal API", "Portal Web"]);
  assert.deepEqual(resolution?.unmappedSboms, [{ sbomId: "sbom-3", sbomLabel: "Gateway" }]);
});
test("ResolveAffectedProjects preserves broken note mappings for repair flows", async () => {
  const resolver = new ResolveAffectedProjects(repository, lookup);
  const vulnerability = createVulnerability({ id: "CVE-2026-2000" });
  const graph = {
    componentsByVulnerability: /* @__PURE__ */ new Map([[
      "nvd::cve-2026-2000",
      [{
        evidence: "purl",
        key: "pkg:npm/legacy@1.0.0",
        name: "legacy",
        vulnerabilityCount: 1
      }]
    ]]),
    relationships: [],
    vulnerabilitiesByComponent: /* @__PURE__ */ new Map()
  };
  const result = await resolver.execute({
    componentIndex: {
      getSbomIdsForComponent: () => ["sbom-4"]
    },
    relationships: graph,
    sboms: [{ id: "sbom-4", label: "Legacy Portal" }],
    vulnerabilities: [vulnerability]
  });
  assert.equal(result.get("nvd::cve-2026-2000")?.affectedProjects[0]?.status, "broken");
});
