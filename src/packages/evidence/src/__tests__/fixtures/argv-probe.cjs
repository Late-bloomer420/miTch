const { writeFileSync } = require('node:fs');
writeFileSync(process.env.EVIDENCE_ARGV_CAPTURE, JSON.stringify(process.argv.slice(2)));
