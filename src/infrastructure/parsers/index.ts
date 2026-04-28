import { SbomParserFactory } from './SbomParserFactory';
import type { ParseSbomOptions } from './SbomParser';

const defaultSbomParserFactory = new SbomParserFactory();

export type ParseSbomJsonOptions = ParseSbomOptions;

export const parseSbomJson = (
  json: unknown,
  options: ParseSbomJsonOptions
)=>
  defaultSbomParserFactory.parse(json, options);
