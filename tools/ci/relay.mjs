// Posts one message to the alert room through the relay, or says why it did not.
//
// ALERT_RELAY_URL and ALERT_RELAY_TOKEN come from the workflow; the token is read from SecretHive
// by relay-token.sh with the job's own forge token and is never stored. status is the relay's:
// "firing" for something to act on, "notice" for something to know.
//
// In a CI job both must be there, or the script stops before it reports anything. A clean day posts
// nothing, so a job that could not reach the room would look exactly like a clean day: until
// 2026-10-20 a refused token only printed "reported here only" in a green run. Run by hand outside
// CI, the report stays in the terminal.

const url = process.env.ALERT_RELAY_URL, token = process.env.ALERT_RELAY_TOKEN;
if (process.env.GITHUB_ACTIONS === 'true' && (!url || !token))
  throw new Error(`No ${url ? 'ALERT_RELAY_TOKEN' : 'ALERT_RELAY_URL'} in this CI job: nothing it finds could reach the alert room.`);

export async function post(status, title, message) {
  if (!url || !token) { console.log('No alert relay configured: reported here only.'); return; }
  const response = await fetch(url, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${token}` },
    body: JSON.stringify({ status, title, message }),
  });
  if (!response.ok) throw new Error(`Alert relay answered HTTP ${response.status}`);
  console.log('Sent to the alert room.');
}
