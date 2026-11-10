// Steam sign-in (OpenID 2.0) + trading card import for Steam Card Clash.
// Deploy on Vercel. Env vars: SESSION_SECRET (required), STEAM_API_KEY (optional, for display name).
const crypto = require('crypto');
const SECRET = process.env.SESSION_SECRET || '';
const b64 = s => Buffer.from(s).toString('base64url');
const sign = p => crypto.createHmac('sha256', SECRET).update(p).digest('base64url');
const makeToken = id => { const p = b64(JSON.stringify({ id, exp: Date.now() + 7 * 864e5 })); return p + '.' + sign(p); };
function readToken(req) {
  const m = (req.headers.cookie || '').match(/(?:^|;\s*)sid=([^;]+)/);
  if (!m) return null;
  const [p, sig] = m[1].split('.');
  if (!p || !sig) return null;
  const good = sign(p);
  if (sig.length !== good.length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(good))) return null;
  try { const d = JSON.parse(Buffer.from(p, 'base64url').toString()); return d.exp > Date.now() ? d.id : null; } catch { return null; }
}

const EL = ['Fire', 'Water', 'Nature'];
const SK = ['Cardstorm', 'Holo Slam', 'Trade Offer', 'Mint Condition', 'Booster Burst', 'Badge Crafter'];
const FXS = ['burn', 'weak', 'stun', null];
const esc = s => String(s).replace(/[<>&"']/g, '');
function hash(str) { let h = 2166136261; for (const c of str) { h ^= c.charCodeAt(0); h = Math.imul(h, 16777619); } return h >>> 0; }
// Turn a Steam trading card into a game card. Stats come from a hash of the card, so they never change.
function toCard(d) {
  const h = hash(d.classid + ':' + d.name);
  const foil = (d.tags || []).some(t => t.category === 'cardborder' && t.internal_name === 'cardborder_1');
  const r = foil ? 'Foil' : (h % 10 < 6 ? 'Common' : h % 10 < 9 ? 'Rare' : 'Epic');
  const k = { Common: 1, Rare: 1.1, Epic: 1.2, Foil: 1.3 }[r];
  const g = (n, m) => (h >>> n) % m;
  const icon = String(d.icon_url || '').replace(/[^\w-]/g, '');
  return {
    id: 'c' + d.classid,
    name: esc(d.name).replace(/\s*\(Foil\)$/i, ''),
    em: `<img class="ci" src="https://community.cloudflare.steamstatic.com/economy/image/${icon}/96fx96f" alt="">`,
    el: EL[h % 3], r,
    atk: Math.round((6 + g(3, 9)) * k), def: Math.round((3 + g(7, 8)) * k),
    hp: Math.round((30 + g(11, 21)) * k), spd: 2 + g(15, 9),
    sk: SK[g(19, SK.length)], fx: FXS[g(23, 4)]
  };
}

async function loadCards(id) {
  const map = new Map(); let start = '';
  for (let i = 0; i < 3; i++) {
    const r = await fetch(`https://steamcommunity.com/inventory/${id}/753/6?l=english&count=2000${start ? '&start_assetid=' + start : ''}`);
    if (r.status === 403) return { status: 403, body: { error: 'private' } };
    if (r.status === 429) return { status: 429, body: { error: 'rate' } };
    if (!r.ok) return { status: 502, body: { error: 'steam' } };
    const j = await r.json();
    if (!j) return { status: 403, body: { error: 'private' } };
    if (!j.descriptions) break;
    for (const d of j.descriptions) if ((d.tags || []).some(t => t.internal_name === 'item_class_2') && !map.has(d.classid)) map.set(d.classid, d);
    if (!j.more_items) break;
    start = j.last_assetid;
  }
  const order = { Foil: 0, Epic: 1, Rare: 2, Common: 3 };
  const cards = [...map.values()].map(toCard).sort((a, b) => order[a.r] - order[b.r]).slice(0, 60);
  return { status: 200, body: { cards } };
}

module.exports = async (req, res) => {
  const u = new URL(req.url, 'http://x'), a = u.searchParams.get('action');
  const origin = `https://${req.headers['x-forwarded-host'] || req.headers.host}`;
  const json = (s, b) => { res.status(s).setHeader('Content-Type', 'application/json'); res.end(JSON.stringify(b)); };
  if (!SECRET) return json(500, { error: 'SESSION_SECRET is not set' });
  const back = `${origin}/api/steam?action=callback`;

  if (a === 'login') {
    const q = new URLSearchParams({
      'openid.ns': 'http://specs.openid.net/auth/2.0', 'openid.mode': 'checkid_setup',
      'openid.return_to': back, 'openid.realm': origin,
      'openid.identity': 'http://specs.openid.net/auth/2.0/identifier_select',
      'openid.claimed_id': 'http://specs.openid.net/auth/2.0/identifier_select'
    });
    res.writeHead(302, { Location: 'https://steamcommunity.com/openid/login?' + q });
    return res.end();
  }
  if (a === 'callback') {
    const p = new URLSearchParams();
    for (const [k, v] of u.searchParams) if (k.startsWith('openid.')) p.set(k, v);
    const m = /^https:\/\/steamcommunity\.com\/openid\/id\/(\d{17})$/.exec(p.get('openid.claimed_id') || '');
    if (!m || p.get('openid.return_to') !== back) return json(400, { error: 'bad login' });
    p.set('openid.mode', 'check_authentication');
    const v = await fetch('https://steamcommunity.com/openid/login', { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: p });
    if (!(await v.text()).includes('is_valid:true')) return json(401, { error: 'Steam did not verify the login' });
    res.writeHead(302, { Location: '/', 'Set-Cookie': `sid=${makeToken(m[1])}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=604800` });
    return res.end();
  }
  if (a === 'logout') {
    res.writeHead(302, { Location: '/', 'Set-Cookie': 'sid=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0' });
    return res.end();
  }
  const id = readToken(req);
  if (!id) return json(401, { error: 'not signed in' });
  if (a === 'me') {
    let name = null, avatar = null;
    if (process.env.STEAM_API_KEY) {
      try {
        const r = await fetch(`https://api.steampowered.com/ISteamUser/GetPlayerSummaries/v2/?key=${process.env.STEAM_API_KEY}&steamids=${id}`);
        const pl = (await r.json()).response.players[0]; name = pl.personaname; avatar = pl.avatarmedium;
      } catch {}
    }
    res.setHeader('Cache-Control', 'no-store');
    return json(200, { steamid: id, name: name || 'Steam user ' + id.slice(-4), avatar });
  }
  if (a === 'cards') {
    const r = await loadCards(id);
    res.setHeader('Cache-Control', 'private, max-age=300');
    return json(r.status, r.body);
  }
  json(404, { error: 'unknown action' });
};
