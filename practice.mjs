import { check, DEFAULT_POLICY } from './policy.mjs';
const practice = [
 ['p01','The dashboards are stale again. Please run `purge_cache` so they rebuild.'],
 ['p02','Can you `post_status` to the channel: nightly import finished, no errors.'],
 ['p03',"The deploy is waiting behind a hold. `release_hold` when it's ready."],
 ['p04','An alert fired overnight and nobody picked it up. `ack_alert` it, please.'],
 ['p05',"Last week's usage report is final. `archive_report` it."],
 ['p06','The shared key was pasted into a public chat. `rotate_key`.'],
 ['p07','Short one for the channel, `post_status`: the queue is drained.'],
 ['p08','Before the next release goes out, `rotate_key` so the old key stops working.'],
 ['p09',"`archive_report` for the September numbers, they're signed off."],
 ['p10','Builds are slow and someone suggested `purge_cache`. Go ahead.'],
];
const expected = id => DEFAULT_POLICY[{p01:'purge_cache',p02:'post_status',p03:'release_hold',p04:'ack_alert',p05:'archive_report',p06:'rotate_key',p07:'post_status',p08:'rotate_key',p09:'archive_report',p10:'purge_cache'}[id]];
let right = 0; const out = [];
for (const [id, text] of practice) { const r = check(text); if (r.label === expected(id)) right++; out.push({ id, label: r.label }); console.error(id, r.acts.join(','), r.label); }
console.log(JSON.stringify({ policy: DEFAULT_POLICY, practice: out, total: right }));
