import type { Report } from '../types.js';
import { formatJunit } from './junit.js';
import { formatMarkdown } from './markdown.js';
import { formatSarif } from './sarif.js';
import { formatText, type TextOptions } from './text.js';

/** The output formats. */
export type ReportFormat = 'text' | 'json' | 'md' | 'sarif' | 'junit';

/** Every format. */
export const FORMATS: readonly ReportFormat[] = ['text', 'json', 'md', 'sarif', 'junit'];

/** Renders a report in one of the formats. */
export function formatReport(report: Report, format: ReportFormat, options: TextOptions = {}): string {
  switch (format) {
    case 'json': return `${JSON.stringify(report, null, 2)}\n`;
    case 'md': return formatMarkdown(report);
    case 'sarif': return formatSarif(report);
    case 'junit': return formatJunit(report);
    default: return formatText(report, options);
  }
}

export { formatJunit, formatMarkdown, formatSarif, formatText, type TextOptions };
