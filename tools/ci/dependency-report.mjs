// Reads what `dotnet list package` wrote and says what is vulnerable and what is behind.
//
// Dependabot did this on GitHub until the code moved to the forge. Its pull requests still open
// there, where no build runs, and the forge's mirror closes them on the next push: 35 of 39 were
// closed unseen between August and October 2026. This is the signal that replaced them.
//
//   node tools/ci/dependency-report.mjs --vulnerable v.json [--outdated o.json] [--images [Dockerfile,…]]
//
// A vulnerable package is reported on every run and fails it. What is merely behind is reported
// only when --outdated or --images is given, which the workflow does once a week. --images reads
// the Dockerfiles named after it (default Dockerfile,Dockerfile.mcp) for pinned Microsoft base
// images, in FROM lines and in ARG defaults. PROJECT names the project in messages; it defaults
// to the repository's name.
//
// Kept identical in every repository that uses it; TaricHive's copy is the one to change.
// With ALERT_RELAY_URL and ALERT_RELAY_TOKEN set the report goes to the alert room as well. The
// workflow reads that token from SecretHive with the job's own forge token; nothing is stored.

import { readFileSync } from 'node:fs';
import { post } from './relay.mjs';

const args = process.argv.slice(2);
const value = (name) => { const i = args.indexOf(name); return i < 0 ? null : args[i + 1]; };
const project = process.env.PROJECT || (process.env.GITHUB_REPOSITORY ?? 'this project').split('/').pop();

// The MCP SDK is upgraded on purpose and never because a newer one exists: its releases carry
// protocol changes. A known vulnerability in it is still reported.
const upgradedDeliberately = [/^ModelContextProtocol/];

function packages(file, wanted) {
  if (!file) return [];
  const found = new Map();
  for (const project of JSON.parse(readFileSync(file, 'utf8')).projects ?? []) {
    for (const framework of project.frameworks ?? []) {
      for (const [kind, list] of [['direct', framework.topLevelPackages], ['transitive', framework.transitivePackages]]) {
        for (const p of list ?? []) {
          if (!wanted(p)) continue;
          const key = `${p.id} ${p.resolvedVersion}`;
          const entry = found.get(key) ?? { ...p, kind, projects: new Set() };
          if (kind === 'direct') entry.kind = 'direct';
          entry.projects.add(project.path.split(/[\\/]/).pop().replace(/\.csproj$/, ''));
          found.set(key, entry);
        }
      }
    }
  }
  return [...found.values()].sort((a, b) => a.id.localeCompare(b.id));
}

// "10.0.12" against "10.0.9": numeric per part, so 12 is newer than 9.
function newer(a, b) {
  const x = a.split('.').map(Number), y = b.split('.').map(Number);
  for (let i = 0; i < Math.max(x.length, y.length); i++) {
    if ((x[i] ?? 0) !== (y[i] ?? 0)) return (x[i] ?? 0) > (y[i] ?? 0);
  }
  return false;
}

// The base images are pinned to a patch release on purpose. Nothing says when the pin has aged
// except this: the newest tag of the same major.minor in the registry.
async function staleImages() {
  const stale = [];
  const seen = new Set();
  const named = value('--images');
  const files = named && !named.startsWith('--') ? named.split(',') : ['Dockerfile', 'Dockerfile.mcp'];
  for (const file of files) {
    // "FROM mcr…/dotnet/aspnet:10.0.13 AS runtime" and "ARG RUNTIME_IMAGE=mcr…/dotnet/aspnet:10.0.13-noble-chiseled".
    // A floating tag ("sdk:10.0") has no patch to age and is left alone.
    const pattern = /^(?:FROM\s+(?:--platform=\S+\s+)?|ARG\s+\w+=)mcr\.microsoft\.com\/(\S+?):(\d+)\.(\d+)\.(\d+)((?:-[a-z0-9]+)*)\b/gm;
    for (const m of readFileSync(file, 'utf8').matchAll(pattern)) {
      const [, repository, major, minor, patch, suffix] = m;
      const pinned = `${major}.${minor}.${patch}`;
      if (seen.has(`${repository}:${pinned}${suffix}`)) continue;
      seen.add(`${repository}:${pinned}${suffix}`);
      const response = await fetch(`https://mcr.microsoft.com/v2/${repository}/tags/list`);
      if (!response.ok) throw new Error(`Tag list of ${repository}: HTTP ${response.status}`);
      const latest = ((await response.json()).tags ?? [])
        .filter((t) => new RegExp(`^${major}\\.${minor}\\.\\d+${suffix.replace(/-/g, '\\-')}$`).test(t))
        .map((t) => t.slice(0, t.length - suffix.length))
        .reduce((best, t) => (newer(t, best) ? t : best), pinned);
      if (latest !== pinned) stale.push(`${repository} ${pinned}${suffix} -> ${latest}${suffix}`);
    }
  }
  return stale;
}


const vulnerable = packages(value('--vulnerable'), (p) => (p.vulnerabilities ?? []).length > 0);
const outdated = packages(value('--outdated'), (p) => p.latestVersion && p.latestVersion !== p.resolvedVersion
  && !upgradedDeliberately.some((r) => r.test(p.id)));
const images = args.includes('--images') ? await staleImages() : [];

if (vulnerable.length) {
  const lines = vulnerable.map((p) => `${p.id} ${p.resolvedVersion} (${p.kind}, ${[...p.projects].join(', ')}): `
    + p.vulnerabilities.map((v) => `${v.severity} ${v.advisoryurl}`).join('; '));
  console.log(`Vulnerable packages: ${vulnerable.length}\n${lines.join('\n')}`);
  await post('firing', `${project}: ${vulnerable.length} package(s) with a known vulnerability`, lines.join('\n'));
} else {
  console.log('Vulnerable packages: none.');
}

if (outdated.length || images.length) {
  const lines = [
    ...outdated.map((p) => `${p.id} ${p.resolvedVersion} -> ${p.latestVersion} (${[...p.projects].join(', ')})`),
    ...images.map((i) => `base image ${i}`),
  ];
  console.log(`Behind: ${lines.length}\n${lines.join('\n')}`);
  await post('notice', `${project}: ${lines.length} dependency update(s) waiting`, lines.join('\n'));
} else if (value('--outdated') || args.includes('--images')) {
  console.log('Behind: nothing.');
}

process.exit(vulnerable.length ? 1 : 0);
