// What osv.dev knows about the published images: their operating-system packages, as osv-scanner
// reads them, and the .NET runtime they run on, which no scanner reads.
//
//   node tools/ci/image-report.mjs --image <name>=<scan.json>[,<runtimes.txt>] [--image …] [--weekly]
//
// <scan.json> is `osv-scanner scan image --format json`. <runtimes.txt> holds one ".NET shared
// framework and its version" per line ("Microsoft.AspNetCore.App 10.0.13"), as image-scan.sh reads
// them out of the image; it is empty for an image with no shared runtime (a self-contained app,
// or no .NET at all). PROJECT names the project in messages; it defaults to the repository's name.
//
// Why both. osv-scanner reads an image's dpkg database and finds nothing of .NET: the runtime under
// /usr/share/dotnet is not a package there, and a project's .deps.json leaves out every assembly the
// runtime provides. Measured 2026-10-14 on TaricHive: the 2.19.8 dependency files did not name
// System.Security.Cryptography.Pkcs at all, while the 10.0.12 runtime that served it had fourteen
// open advisories on osv.dev (as Microsoft.NETCore.App.Runtime.* and Microsoft.AspNetCore.App.Runtime.*).
// So the runtime is asked about by name and version, read from the image itself.
//
// What fails the run (and is sent as "firing"): a finding somebody can act on today. An operating-
// system or library vulnerability of severity 7 or more (or of no stated severity) with a fix, or a runtime advisory fixed in a
// runtime whose base image already exists. Everything else is counted, and said once a week
// (--weekly, or a run by hand) as a notice: an image of Ubuntu always carries known vulnerabilities
// with no fix yet, and a message a day about them would be read by nobody.
//
// Kept identical in every repository that uses it; TaricHive's copy is the one to change.

import { readFileSync, existsSync } from 'node:fs';
import { post } from './relay.mjs';

const args = process.argv.slice(2);
const values = (name) => args.flatMap((a, i) => (a === name && args[i + 1] ? [args[i + 1]] : []));
const weekly = args.includes('--weekly');
const project = process.env.PROJECT || (process.env.GITHUB_REPOSITORY ?? 'this project').split('/').pop();
const actionableSeverity = 7;

// Which osv.dev package answers for which shared framework, and which base image ships its fix.
const packs = {
  'Microsoft.NETCore.App': { pack: 'Microsoft.NETCore.App.Runtime.linux-x64', image: 'dotnet/runtime' },
  'Microsoft.AspNetCore.App': { pack: 'Microsoft.AspNetCore.App.Runtime.linux-x64', image: 'dotnet/aspnet' },
};

// "10.0.13" against "10.0.12", numerically per part.
function newer(a, b) {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++)
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  return false;
}

/** The operating-system findings of one osv-scanner JSON file: one per source package and advisory. */
function osFindings(image, file) {
  const findings = new Map();
  for (const result of JSON.parse(readFileSync(file, 'utf8')).results ?? []) {
    for (const p of result.packages ?? []) {
      const ecosystem = (p.package.ecosystem ?? '').split(':').slice(0, 2).join(':');   // "Ubuntu:24.04"
      const severity = new Map();
      for (const g of p.groups ?? [])
        for (const id of g.ids ?? []) severity.set(id, Number.parseFloat(g.max_severity) || 0);
      for (const v of p.vulnerabilities ?? []) {
        const fixed = (v.affected ?? []).some((a) => (a.package?.ecosystem ?? '').startsWith(ecosystem)
          && (a.ranges ?? []).some((r) => (r.events ?? []).some((e) => e.fixed)));
        const key = `${p.package.name} ${v.id}`;
        const seen = findings.get(key);
        findings.set(key, { image, name: p.package.name, version: p.package.version, id: v.id,
          severity: Math.max(severity.get(v.id) ?? 0, seen?.severity ?? 0), fixed: fixed || (seen?.fixed ?? false) });
      }
    }
  }
  return [...findings.values()];
}

/** The shared frameworks an image carries, as image-scan.sh wrote them. */
function runtimesOf(file) {
  if (!file || !existsSync(file)) return [];
  return readFileSync(file, 'utf8').split('\n').map((l) => l.trim().split(/\s+/))
    .filter(([name, version]) => packs[name] && /^\d+\.\d+\.\d+$/.test(version ?? ''))
    .map(([name, version]) => ({ name, version }));
}

const latestTags = new Map();
/** The newest tag of a base image with this major.minor, from the registry. */
async function latestTag(image, version) {
  const [major, minor] = version.split('.');
  if (!latestTags.has(image)) {
    const response = await fetch(`https://mcr.microsoft.com/v2/${image}/tags/list`);
    if (!response.ok) throw new Error(`Tag list of ${image}: HTTP ${response.status}`);
    latestTags.set(image, (await response.json()).tags ?? []);
  }
  return latestTags.get(image)
    .filter((t) => new RegExp(`^${major}\\.${minor}\\.\\d+$`).test(t))
    .reduce((best, t) => (newer(t, best) ? t : best), version);
}

/** osv.dev's advisories for one shared framework at one version, with the version that fixes each. */
async function runtimeAdvisories({ name, version }) {
  const { pack } = packs[name];
  const response = await fetch('https://api.osv.dev/v1/query', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package: { ecosystem: 'NuGet', name: pack }, version }),
  });
  if (!response.ok) throw new Error(`osv.dev answered HTTP ${response.status} for ${pack}`);
  const [major, minor] = version.split('.');
  return ((await response.json()).vulns ?? []).map((v) => ({
    id: v.id,
    cve: (v.aliases ?? []).find((a) => a.startsWith('CVE-')) ?? '',
    severity: v.database_specific?.severity ?? '?',
    summary: (v.summary ?? '').replace(/^Microsoft Security Advisory \S+ - /, ''),
    fixedIn: (v.affected ?? []).filter((a) => a.package?.name === pack)
      .flatMap((a) => (a.ranges ?? []).flatMap((r) => r.events ?? []))
      .map((e) => e.fixed).find((f) => f && f.startsWith(`${major}.${minor}.`)),
  }));
}

const os = [];
const runtime = [];   // one entry per image, framework and advisory
const unread = [];
for (const spec of values('--image')) {
  const [image, files] = spec.split('=');
  const [scan, runtimes] = files.split(',');
  os.push(...osFindings(image, scan));
  const frameworks = runtimesOf(runtimes);
  if (!frameworks.length) unread.push(image);
  for (const fw of frameworks) {
    const latest = await latestTag(packs[fw.name].image, fw.version);
    console.log(`${image}: ${fw.name} ${fw.version} (newest base image ${latest}).`);
    for (const a of await runtimeAdvisories(fw))
      runtime.push({ ...a, image, framework: fw.name, version: fw.version, latest });
  }
}
if (unread.length)
  console.log(`No shared .NET runtime read from: ${unread.join(', ')} (self-contained or not .NET; its runtime is not checked here).`);

// No score is not a low score: most Go standard-library advisories carry none, and each has a fix.
const osActionable = os.filter((f) => f.fixed && (f.severity >= actionableSeverity || f.severity === 0));
const runtimeActionable = runtime.filter((a) => a.fixedIn && !newer(a.fixedIn, a.latest));
const firing = [
  ...runtimeActionable.map((a) => `${a.image}: ${a.framework} ${a.version}: ${a.id} ${a.cve} (${a.severity}) ${a.summary}; fixed in ${a.fixedIn}, base image ${a.latest} exists`),
  ...osActionable.map((f) => `${f.image}: ${f.name} ${f.version}: ${f.id} (${f.severity}), a fixed package exists`),
];

for (const a of runtime) console.log(`  ${a.image} ${a.framework} ${a.version}: ${a.id} ${a.cve} ${a.severity}: ${a.summary} (fixed in ${a.fixedIn ?? '?'})`);
for (const image of new Set(os.map((f) => f.image))) {
  const mine = os.filter((f) => f.image === image);
  console.log(`${image}: ${mine.length} findings (system packages and libraries), ${mine.filter((f) => f.fixed).length} with a fixed package, `
    + `${mine.filter((f) => f.severity >= actionableSeverity).length} of severity ${actionableSeverity} or more.`);
}

if (firing.length) {
  console.log(`To act on: ${firing.length}\n${firing.join('\n')}`);
  await post('firing', `${project}: ${firing.length} image finding(s) with a fix available`, firing.join('\n'));
} else {
  console.log('To act on: nothing.');
}

if (weekly) {
  const lines = [];
  const waiting = runtime.filter((a) => !runtimeActionable.includes(a));
  for (const key of new Set(waiting.map((a) => `${a.image} ${a.framework} ${a.version}`))) {
    const mine = waiting.filter((a) => `${a.image} ${a.framework} ${a.version}` === key);
    lines.push(`${key}: ${mine.length} advisories (${[...new Set(mine.map((a) => a.severity))].join(', ')}), `
      + `fixed in ${[...new Set(mine.map((a) => a.fixedIn ?? '?'))].join(', ')}; no such base image yet`);
  }
  for (const image of new Set(os.map((f) => f.image))) {
    const mine = os.filter((f) => f.image === image && !osActionable.includes(f));
    if (mine.length)
      lines.push(`${image}: ${mine.length} known vulnerabilities without a fix to take `
        + `(${mine.filter((f) => f.severity >= 9).length} critical, ${mine.filter((f) => f.severity >= 7 && f.severity < 9).length} high)`);
  }
  if (lines.length) {
    console.log(`Known, nothing to take yet:\n${lines.join('\n')}`);
    await post('notice', `${project}: what the images carry that has no fix yet`, lines.join('\n'));
  } else if (!firing.length) {
    // The weekly report says so when it is clean, or a clean image would never be heard of at all.
    const scanned = values('--image').map((spec) => spec.split('=')[0]).join(', ');
    console.log('Known: nothing.');
    await post('notice', `${project}: nothing known in the images`, `osv.dev knows no vulnerability in ${scanned}.`);
  }
}

process.exit(firing.length ? 1 : 0);
