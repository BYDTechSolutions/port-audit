#!/usr/bin/env node
import { main } from './cli-main.js';

const code = await main(process.argv.slice(2), {
  stdout: (t) => process.stdout.write(t),
  stderr: (t) => process.stderr.write(t),
  env: process.env,
  stdoutIsTTY: !!process.stdout.isTTY,
  stderrIsTTY: !!process.stderr.isTTY,
  columns: process.stdout.columns,
});
process.exitCode = code;
