// The pages in a real browser: headless Chrome driven over the DevTools protocol, with nothing installed from npm.
//
//   node tests/browser/smoke.mjs <base url> <bootstrap token file> [screenshot folder]
//
// Signs in as the first admin, makes a vault and a secret, opens it in the panel beside the list, reveals and copies
// it, and finds both reads in the audit trail. Throughout it fails on anything the browser itself complains about: a
// Content-Security-Policy report, a console error, an uncaught exception, or a page connection that is not a
// WebSocket. Then it checks that the pages fit a phone. Exit code 0 only when every check held.
//
// Chrome is the one in CHROME, or google-chrome on the path. Needs Node 22 or later (WebSocket built in).
import { spawn } from 'node:child_process';
import { mkdtempSync, readFileSync, existsSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [base, tokenFile, shots] = process.argv.slice(2);
if (!base || !tokenFile) {
  console.error('usage: node smoke.mjs <base url> <bootstrap token file> [screenshot folder]');
  process.exit(2);
}
const token = readFileSync(tokenFile, 'utf8').trim();
const value = 'generated-value-' + Math.random().toString(36).slice(2, 10);
const password = 'generated-password-' + Math.random().toString(36).slice(2, 12);

// Chrome on a port of its own choosing; it writes the port into its profile folder.
const profile = mkdtempSync(join(tmpdir(), 'secrethive-chrome-'));
const chrome = spawn(process.env.CHROME || 'google-chrome', [
  '--headless=new', '--remote-debugging-port=0', `--user-data-dir=${profile}`, '--ignore-certificate-errors',
  '--no-first-run', '--no-default-browser-check', '--disable-gpu', '--no-sandbox', '--window-size=1360,900', 'about:blank',
], { stdio: 'ignore' });
const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));
let port;
for (let i = 0; i < 100 && !port; i++) {
  const file = join(profile, 'DevToolsActivePort');
  if (existsSync(file)) port = readFileSync(file, 'utf8').split('\n')[0].trim();
  else await sleep(100);
}
if (!port) throw new Error('Chrome did not start');

const target = await (await fetch(`http://127.0.0.1:${port}/json/new?about:blank`, { method: 'PUT' })).json();
const ws = new WebSocket(target.webSocketDebuggerUrl);
await new Promise((resolve, reject) => { ws.addEventListener('open', resolve); ws.addEventListener('error', reject); });

let id = 0;
const pending = new Map();
const complaints = [];
const sockets = [];
let documentHeaders = {};
ws.addEventListener('message', event => {
  const message = JSON.parse(event.data);
  if (message.id && pending.has(message.id)) {
    pending.get(message.id)(message);
    pending.delete(message.id);
    return;
  }
  const p = message.params;
  switch (message.method) {
    case 'Audits.issueAdded':
      if (p.issue.code === 'ContentSecurityPolicyIssue') {
        const detail = p.issue.details.contentSecurityPolicyIssueDetails;
        complaints.push(`CSP: ${detail.violatedDirective} blocked ${detail.blockedURL ?? 'inline code'}`);
      }
      break;
    case 'Log.entryAdded':
      if (p.entry.level === 'error') complaints.push(`log (${p.entry.source}): ${p.entry.text}`);
      break;
    case 'Runtime.consoleAPICalled':
      if (p.type === 'error') complaints.push('console: ' + p.args.map(arg => arg.value ?? arg.description).join(' '));
      break;
    case 'Runtime.exceptionThrown':
      complaints.push('exception: ' + (p.exceptionDetails.exception?.description ?? p.exceptionDetails.text));
      break;
    case 'Network.webSocketCreated':
      sockets.push(p.url);
      break;
    case 'Network.responseReceived':
    case 'Network.responseReceivedExtraInfo':
      if (message.method.endsWith('ExtraInfo') || p.type === 'Document') {
        for (const [k, v] of Object.entries(message.method.endsWith('ExtraInfo') ? p.headers : p.response.headers)) {
          if (k.toLowerCase() === 'content-security-policy') documentHeaders['content-security-policy'] = v;
        }
      }
      break;
  }
});
const send = (method, params = {}) => new Promise(resolve => {
  const mine = ++id;
  pending.set(mine, resolve);
  ws.send(JSON.stringify({ id: mine, method, params }));
});

let failed = 0;
const report = (what, ok, detail = '') => {
  console.log(`${ok ? 'ok  ' : 'FAIL'} ${what}${ok || !detail ? '' : ': ' + detail}`);
  if (!ok) failed++;
};
const js = async expression => {
  const reply = await send('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true, userGesture: true });
  if (reply.result?.exceptionDetails) throw new Error(reply.result.exceptionDetails.exception?.description ?? reply.result.exceptionDetails.text);
  return reply.result?.result?.value;
};
const text = () => js('document.body.innerText');
const until = async (expression, what) => {
  for (let i = 0; i < 80; i++) {
    if (await js(expression).catch(() => false)) return;
    await sleep(250);
  }
  throw new Error(`timed out waiting for ${what} on ${await js('location.pathname')}`);
};
// Waits for the new document, not the old one that still says it is complete.
const go = async path => {
  await js('window.leaving = true');
  await send('Page.navigate', { url: base + path });
  await until(`!window.leaving && document.readyState === 'complete'`, 'the page to load');
};
// Blazor binds on "change": set the value and say so.
const type = (selector, text) => js(`(() => { const el = document.querySelector(${JSON.stringify(selector)}); el.value = ${JSON.stringify(text)}; el.dispatchEvent(new Event('change', { bubbles: true })); return true; })()`);
// A button by what it says, including the words kept for screen readers on an icon button.
const click = (label, scope = 'document') => js(`(() => { const el = [...${scope}.querySelectorAll('button, a')].find(b => b.textContent.trim() === ${JSON.stringify(label)}); if (!el) throw new Error('no button ' + ${JSON.stringify(label)}); el.click(); return true; })()`);
const shot = async name => {
  if (shots) writeFileSync(join(shots, `${name}.png`), Buffer.from((await send('Page.captureScreenshot', {})).result.data, 'base64'));
};
const quiet = (what) => {
  report(`${what}: the browser complained about nothing`, complaints.length === 0, complaints.join(' | '));
  complaints.length = 0;
};

try {
  for (const domain of ['Page', 'Runtime', 'Log', 'Audits', 'Network']) await send(`${domain}.enable`);
  await send('Browser.grantPermissions', { origin: new URL(base).origin, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
  await send('Page.bringToFront');

  await go('/');
  report('without a session the pages send the browser to the sign-in form', (await js('location.pathname')) === '/login');

  // The policy, as the browser received it with the sign-in page.
  const policy = documentHeaders['content-security-policy'] ?? '';
  report('the sign-in page carries a policy that runs only the server\'s own scripts and is never framed',
    policy.includes("script-src 'self'") && !/script-src[^;]*unsafe/.test(policy) && policy.includes("frame-ancestors 'none'"), policy || 'no policy');

  // And the browser keeps to it: a script put on the page does not run, and that is reported.
  const ran = await js(`(() => { const s = document.createElement('script'); s.textContent = 'window.injected = true'; document.head.appendChild(s); return window.injected === true; })()`);
  await sleep(300);
  report('a script injected into the page is refused by the browser', !ran && complaints.some(c => c.startsWith('CSP: script-src')), complaints.join(' | ') || 'no report');
  complaints.length = 0;
  await js(`(() => { document.querySelector('#username').value = 'admin'; const p = document.querySelector('#password'); p.value = ${JSON.stringify(token)}; p.form.submit(); return true; })()`);
  await until(`location.pathname === '/account/password' && !!document.querySelector('#again')`, 'the password form');
  await js(`(() => { document.querySelector('#current').value = ${JSON.stringify(token)}; document.querySelector('#new').value = ${JSON.stringify(password)}; document.querySelector('#again').value = ${JSON.stringify(password)}; document.querySelector('#new').form.submit(); return true; })()`);
  await until(`document.querySelector('h1')?.textContent === 'Vaults'`, 'the vault list');
  report('the first admin signs in and chooses a password', true);
  quiet('signing in');

  await until(`!!document.querySelector('.sh-btn-primary')`, 'the page to be interactive');
  await click('New vault');
  await until(`!!document.querySelector('.sh-dialog input.sh-mono')`, 'the new vault form');
  await type('.sh-dialog input.sh-mono', 'shop');
  await click('Create vault');
  await until(`!document.querySelector('.sh-dialog')`, 'the form to close');
  await go('/vaults/shop');
  await until(`!!document.querySelector('.sh-btn-primary')`, 'the vault page');
  await click('New secret');
  await until(`!!document.querySelector('.sh-dialog textarea')`, 'the new secret form');
  await type('.sh-dialog input.sh-mono', 'api-key');
  await type('.sh-dialog textarea', value);
  await click('Create secret');
  await until(`!document.querySelector('.sh-dialog')`, 'the form to close');
  report('a vault and a secret are made through the pages', true);
  quiet('making a vault and a secret');

  await go('/vaults/shop?secret=api-key');
  await until(`!!document.querySelector('.sh-panel .sh-secret')`, 'the panel');
  report('the panel opens beside the list without the value on the page', !(await text()).includes(value));
  await click('Reveal', `document.querySelector('.sh-panel')`);
  await until(`document.body.innerText.includes(${JSON.stringify(value)})`, 'the revealed value');
  report('reveal shows the value', true);
  await shot('panel-revealed');
  await click('Hide', `document.querySelector('.sh-panel')`);
  await until(`!document.body.innerText.includes(${JSON.stringify(value)})`, 'the value to go');
  await click('Copy', `document.querySelector('.sh-panel')`);
  await until(`[...document.querySelectorAll('.sh-panel .sh-sr')].some(s => s.textContent === 'Copied') || !!document.querySelector('.sh-panel .sh-alert')`, 'the copy');
  report('copy puts the value on the clipboard', (await js('navigator.clipboard.readText()').catch(e => 'refused: ' + e.message)) === value);
  quiet('revealing and copying');

  report('the page connection is a WebSocket', sockets.some(url => url.includes('/_blazor')), sockets.join(', ') || 'none opened');

  await go('/admin/audit');
  await until(`document.querySelector('h1')?.textContent === 'Audit trail' && document.body.innerText.includes('secret.value.read')`, 'the audit trail');
  const reads = await js(`(document.body.innerText.match(/secret\\.value\\.read/g) || []).length`);
  report(`the reveal and the copy are both on record (${reads} reads)`, reads >= 2);
  report('the audit trail holds no value', !(await text()).includes(value));
  quiet('the audit trail');

  // A phone: nothing wider than the screen, and still nothing to complain about.
  await send('Emulation.setDeviceMetricsOverride', { width: 390, height: 800, deviceScaleFactor: 2, mobile: true });
  for (const path of ['/', '/vaults/shop', '/vaults/shop?secret=api-key', '/vaults/shop/secrets/api-key', '/admin/audit', '/admin/system']) {
    await go(path);
    await until(`!!document.querySelector('h1, .sh-panel h2')`, path);
    await sleep(300);
    const [client, scroll] = await js(`[document.documentElement.clientWidth, document.documentElement.scrollWidth]`);
    report(`${path} fits a ${client}px screen (content ${scroll}px)`, scroll <= client);
  }
  await shot('phone-panel');
  quiet('the pages on a phone');
} catch (error) {
  const where = await js(`location.pathname + ': ' + document.body.innerText.slice(0, 200).replace(/\s+/g, ' ')`).catch(() => '?');
  report('the walk through the pages finished', false, `${error.message.split('\n')[0]} (on ${where})`);
  await shot('failure').catch(() => {});
} finally {
  ws.close();
  chrome.kill();
  await sleep(300);
  try { rmSync(profile, { recursive: true, force: true }); } catch { }
}

console.log(failed === 0 ? 'every check held' : `${failed} check(s) failed`);
process.exit(failed === 0 ? 0 : 1);
