// The agent's check: which acts a message asks for, and whether the policy lets it do them alone.
export const ACTS = ['post_status','ack_alert','archive_report','purge_cache','release_hold','rotate_key'];
export const DEFAULT_POLICY = {
  post_status: 'free', ack_alert: 'free', archive_report: 'free', purge_cache: 'free',
  release_hold: 'gated', rotate_key: 'gated',
};

export function findActs(text) {
  const t = String(text || '').toLowerCase();
  return ACTS.filter(a => new RegExp(`(^|[^a-z_])${a}([^a-z_]|$)`).test(t));
}

// free only if at least one act is named and every named act is free. Anything else waits for the human.
export function check(text, policy = DEFAULT_POLICY) {
  const acts = findActs(text);
  if (acts.length === 0) return { label: 'gated', acts, reason: 'no known act named' };
  const gated = acts.filter(a => policy[a] !== 'free');
  return gated.length ? { label: 'gated', acts, gated, reason: 'policy gates ' + gated.join(', ') }
                      : { label: 'free', acts, reason: 'all acts free by policy' };
}
