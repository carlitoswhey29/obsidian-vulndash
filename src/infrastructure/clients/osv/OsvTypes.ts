export interface OsvPackagePayload {
  readonly name?: string;
  readonly ecosystem?: string;
  readonly purl?: string;
}

export interface OsvBatchQueryItem {
  readonly commit?: string;
  readonly version?: string;
  readonly package?: OsvPackagePayload;
  readonly page_token?: string;
}

export interface OsvBatchRequest {
  readonly queries: readonly OsvBatchQueryItem[];
}

export interface OsvSeverityPayload {
  readonly type: string;
  readonly score: string;
}

export interface OsvDatabaseSpecificPayload {
  readonly severity?: string;
  readonly source?: string;
  readonly [key: string]: unknown;
}

export interface OsvEcosystemSpecificPayload {
  readonly severity?: string;
  readonly [key: string]: unknown;
}

export interface OsvReferencePayload {
  readonly type: string;
  readonly url: string;
}

export interface OsvAffectedRangeEventPayload {
  readonly introduced?: string;
  readonly fixed?: string;
  readonly last_affected?: string;
  readonly limit?: string;
}

export interface OsvAffectedRangePayload {
  readonly type: string;
  readonly repo?: string;
  readonly events: readonly OsvAffectedRangeEventPayload[];
  readonly database_specific?: OsvDatabaseSpecificPayload;
}

export interface OsvAffectedPayload {
  readonly package?: OsvPackagePayload;
  readonly severity?: readonly OsvSeverityPayload[];
  readonly ranges?: readonly OsvAffectedRangePayload[];
  readonly versions?: readonly string[];
  readonly ecosystem_specific?: OsvEcosystemSpecificPayload;
  readonly database_specific?: OsvDatabaseSpecificPayload;
}

export interface OsvVulnerabilityPayload {
  readonly id: string;
  readonly modified: string;
  readonly published?: string;
  readonly withdrawn?: string;
  readonly summary?: string;
  readonly details?: string;
  readonly aliases?: readonly string[];
  readonly related?: readonly string[];
  readonly upstream?: readonly string[];
  readonly references?: readonly OsvReferencePayload[];
  readonly affected?: readonly OsvAffectedPayload[];
  readonly severity?: readonly OsvSeverityPayload[];
  readonly database_specific?: OsvDatabaseSpecificPayload;
  readonly schema_version?: string;
}

export interface OsvBatchResultItem {
  readonly vulns?: readonly OsvVulnerabilityPayload[];
  readonly next_page_token?: string;
}

export interface OsvBatchResponse {
  readonly results: readonly OsvBatchResultItem[];
}
