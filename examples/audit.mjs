// Audit an app from a script: node examples/audit.mjs 3000
// Prints the text report and exits 1 when anything is in "Fix now".
import { auditPort, formatReport, PortAuditError } from '@bydtech/port-audit';

const target = process.argv[2] ?? '3000';
try {
  const report = await auditPort(target, { rate: 10 });
  process.stdout.write(formatReport(report, 'text'));
  for (const f of report.findings) {
    // Each finding carries its OWASP mapping, e.g. { top10: ['A02:2025'], api: ['API8:2023'], asvs: ['3.4.3'], cwe: [] }
    if (f.priority === 'fix-now') process.exitCode = 1;
  }
} catch (error) {
  if (error instanceof PortAuditError) {
    console.error(`${error.code}: ${error.message}`);
    process.exitCode = 2;
  } else throw error;
}
