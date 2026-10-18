const express = require('express');
const path = require('path');
const { Pool } = require('pg');
const jwt = require('jsonwebtoken');

const app = express();
const port = process.env.PORT || 3000;
const pool = new Pool({ connectionString: process.env.DATABASE_URL });

// The platform signs user-identity tokens with an RSA private key it never
// shares. Containers get only the PUBLIC half, so this app can verify who a
// user is but cannot mint an identity — and neither can any other app.
const JWT_PUBLIC_KEY = (process.env.USERNODE_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Tokens are minted for one app: the audience is this app's numeric id, so a
// token issued for a different app is rejected below rather than accepted as
// a valid user.
const APP_AUDIENCE = process.env.USERNODE_APP_ID
  ? 'usernode:app:' + process.env.USERNODE_APP_ID
  : null;

// Visitors with no Homeroom account ("guests") may look around this app at
// its own address, read-only (every public app). The platform marks
// them with a token of their own: ES256, signed by a key of its own (its
// public half is USERNODE_GUEST_JWT_PUBLIC_KEY), this audience, `pur:
// 'guest'`, `guest: true`, and no id or username. Such a visitor is
// `req.guest`, never `req.user`, and every write they try is answered 401
// `account_required`, which the bridge turns into "Make an account to
// continue".
const GUEST_AUDIENCE = APP_AUDIENCE ? APP_AUDIENCE + ':guest' : null;
const GUEST_PUBLIC_KEY = (process.env.USERNODE_GUEST_JWT_PUBLIC_KEY || '')
  .replace(/\\n/g, '\n');

// Paths that stay open without authentication. Add a path here (and add it
// with `app.get`/`app.post` below) if you deliberately want it public.
// Everything else requires a valid platform-issued JWT.
const PUBLIC_API_PATHS = new Set(['/health']);

app.use(express.json());

// The platform's three centrally hosted files — the bridge, the native UI
// kit and the Tailwind runtime — are reachable at these paths on this app's
// OWN origin, so index.html can load them with a RELATIVE path and never
// name the platform's hostname. A hostname baked into an app is what breaks
// every app at once when the platform's domain moves.
//
// In production and on a staging preview the platform's edge answers these
// before the request ever reaches this process (a per-app Ingress rule on
// Kubernetes, the wildcard site's matcher on the docker runtime). This
// handler is what makes the same relative paths work under a plain
// `node server.js`, where there is no edge in front of the app at all.
//
// Registered BEFORE the auth middleware because these three files are
// public: the platform serves them anonymously from any app origin, and a
// login redirect arriving where a <script> was expected is exactly the
// failure a relative path is meant to avoid.
// The platform's origin, at RUNTIME, and ONLY from the variable the platform
// injects. No hostname is written into this file: a baked-in one is what left
// the whole fleet pointing at a domain the platform had moved away from.
// Unset only outside the platform (a plain local `node server.js`) — set
// USERNODE_PLATFORM_ORIGIN there too if you want the hosted assets locally.
const PLATFORM_ORIGIN = (process.env.USERNODE_PLATFORM_ORIGIN || '')
  .replace(/\/+$/, '');

app.get(/^\/usernode-(?:bridge|native|tailwind)\//, async (req, res) => {
  try {
    if (!PLATFORM_ORIGIN) return res.sendStatus(503);
    const upstream = await fetch(PLATFORM_ORIGIN + req.path);
    if (!upstream.ok) return res.sendStatus(upstream.status);
    const type = upstream.headers.get('content-type');
    if (type) res.type(type);
    // max-age=0 with revalidation, never a long TTL: the whole point of
    // central hosting is that a platform-side fix lands on the next load.
    res.set('Cache-Control', 'public, max-age=0, must-revalidate');
    return res.send(Buffer.from(await upstream.arrayBuffer()));
  } catch (err) {
    console.warn('hosted asset fetch failed: ' + err.message);
    return res.sendStatus(502);
  }
});

// "Now" for this request, as a Date: `req.now`, set for every request by
// the middleware below. Read the day and the time through it (and
// `usernode.now()` in the page), never `new Date()` or SQL's NOW(),
// wherever they decide what shows: a reminder, a rota, a deadline.
// Production always gets the real time. A staging preview may be shown as of
// a chosen moment: the platform opens it with `?un-now=<ISO time>`, and the
// page sends `usernode.now()` on as the `x-usernode-now` header. Only a
// staging container reads either. See "Time-dependent features" in the
// platform conventions.
const IS_STAGING = process.env.USERNODE_ENV === 'staging';
const PREVIEW_NOW = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/;
function requestNow(req) {
  const raw = IS_STAGING ? (req.headers['x-usernode-now'] || req.query['un-now']) : null;
  return typeof raw === 'string' && PREVIEW_NOW.test(raw) ? new Date(raw) : new Date();
}

// Verify platform-issued JWT if one was passed, then enforce auth on
// anything not explicitly marked public. The iframe adds `?token=…`
// on load; the frontend script forwards the token via `x-usernode-token`
// on subsequent fetches.
app.use((req, res, next) => {
  req.now = requestNow(req);
  const token = req.query.token || req.headers['x-usernode-token'];
  if (token && JWT_PUBLIC_KEY && APP_AUDIENCE) {
    try {
      // Pin the algorithm, issuer and audience. Without `algorithms` a
      // caller could hand us an HS256 token signed with the public PEM
      // (which every app knows) and forge any user.
      const claims = jwt.verify(token, JWT_PUBLIC_KEY, {
        algorithms: ['RS256'],
        issuer: 'usernode',
        audience: APP_AUDIENCE,
      });
      // `pur` names what the token is for. Only user-identity tokens
      // authenticate a person here.
      if (claims && claims.pur === 'iframe') req.user = claims;
    } catch {}
  }
  if (!req.user && token && GUEST_PUBLIC_KEY && GUEST_AUDIENCE) {
    try {
      const guest = jwt.verify(token, GUEST_PUBLIC_KEY, {
        algorithms: ['ES256'],
        issuer: 'usernode',
        audience: GUEST_AUDIENCE,
      });
      if (guest && guest.pur === 'guest' && guest.guest === true) req.guest = true;
    } catch {}
  }

  // Static assets (CSS/JS/images) are always served; the API and the HTML
  // shell are gated so direct hits to the staging/prod subdomain don't
  // leak app data to the public internet. A guest may READ: every GET,
  // `/api/*` included, so read routes must not assume req.user (use
  // `req.user ? req.user.id : null`). Every write needs an account.
  if (req.method !== 'GET' || req.path.startsWith('/api/')) {
    if (PUBLIC_API_PATHS.has(req.path)) return next();
    if (!req.user && req.guest) {
      if (req.method === 'GET' || req.method === 'HEAD') return next();
      return res.status(401).json({ error: 'account_required' });
    }
    if (!req.user) return res.status(401).json({ error: 'Not authenticated' });
  }
  next();
});

// ── ChaosRoom ──────────────────────────────────────────────────────────────
// Rival trading houses. The player runs one house; the game runs the other
// eight. Content rules swap the war for a market rivalry: soldiers are
// workers, weapons are tools, and an attack is a market-day challenge.

const TURN_MS = 30 * 60 * 1000; // one turn every 30 minutes
const TRIBUTE_PER_WORKER = 3;   // gold each worker pays every turn
const WORKER_COST = 200;        // gold to hire one worker
const RIVAL_GROWTH_STRENGTH = 4;   // strength each rival gains per turn
const RIVAL_GROWTH_GOLD = 600;     // gold each rival gains per turn
const LEDGER_LIMIT = 50;

const TOOL_DEFS = [
  { key: 'cart', name: 'Hand Cart', price: 1000, bonus: 3 },
  { key: 'plough', name: 'Iron Plough', price: 2400, bonus: 6 },
  { key: 'mill', name: 'Mill Wheel', price: 5000, bonus: 15 },
];
const TOOL_BY_KEY = Object.fromEntries(TOOL_DEFS.map((t) => [t.key, t]));

// Starting strength is 50 workers, so the rivals' bases spread from 60% to
// 140% of it: four houses start weaker than yours, four stronger.
const RIVAL_BASES = [
  ['House Ysolt', 70, 2600], ['House Varek', 67, 2400], ['House Holt', 63, 2200],
  ['House Brannoc', 58, 2000], ['House Marrow', 52, 1800], ['House Quill', 45, 1600],
  ['House Fenwick', 38, 1400], ['House Odile', 30, 1200],
];

// The staging demo's rivals, as the drawn screen shows them at turn 87:
// [name, base_strength, base_gold, gold_taken]. Rival gold at turn T is
// base_gold + 600×T − gold_taken, so gold_taken is what the demo house has
// historically won off each of them.
const DEMO_TURN = 87;
const DEMO_RIVALS = [
  ['House Ysolt', 1172, 9700, 0], ['House Brannoc', 1107, 6600, 3500],
  ['House Marrow', 1054, 6000, 10300], ['House Varek', 832, 4000, 16800],
  ['House Holt', 592, 2000, 31600], ['House Quill', 464, 1200, 37600],
  ['House Fenwick', 320, 600, 43600], ['House Odile', 192, 300, 47400],
];

// The guest view's example houses: a fixed set, nothing written anywhere.
const GUEST_RIVALS = [
  { name: 'House Ysolt', strength: 1520, gold: 61900 },
  { name: 'House Brannoc', strength: 1455, gold: 55300 },
  { name: 'House Marrow', strength: 1402, gold: 47900 },
  { name: 'House Varek', strength: 1180, gold: 39400 },
  { name: 'House Holt', strength: 940, gold: 22600 },
  { name: 'House Quill', strength: 812, gold: 15800 },
  { name: 'House Fenwick', strength: 668, gold: 9200 },
  { name: 'House Odile', strength: 540, gold: 5100 },
];

const SCHEMA = `
  CREATE TABLE IF NOT EXISTS houses (
    id bigserial PRIMARY KEY,
    user_id text NOT NULL,
    username text NOT NULL,
    demo boolean NOT NULL DEFAULT false,
    gold bigint NOT NULL,
    workers int NOT NULL,
    founded_at timestamptz NOT NULL,
    ticked_turn int NOT NULL DEFAULT 1,
    UNIQUE (user_id, demo)
  );
  CREATE TABLE IF NOT EXISTS house_tools (
    house_id bigint NOT NULL REFERENCES houses(id) ON DELETE CASCADE,
    tool_key text NOT NULL,
    count int NOT NULL DEFAULT 0,
    PRIMARY KEY (house_id, tool_key)
  );
  CREATE TABLE IF NOT EXISTS rivals (
    id bigserial PRIMARY KEY,
    house_id bigint NOT NULL REFERENCES houses(id) ON DELETE CASCADE,
    name text NOT NULL,
    base_strength int NOT NULL,
    base_gold bigint NOT NULL,
    gold_taken bigint NOT NULL DEFAULT 0,
    last_met_turn int NOT NULL DEFAULT 0
  );
  CREATE TABLE IF NOT EXISTS ledger (
    id bigserial PRIMARY KEY,
    house_id bigint NOT NULL REFERENCES houses(id) ON DELETE CASCADE,
    turn int NOT NULL,
    part_of_day text NOT NULL,
    kind text NOT NULL,
    text text NOT NULL,
    gold_delta bigint NOT NULL DEFAULT 0,
    workers_delta int NOT NULL DEFAULT 0,
    tools_delta int NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now()
  );
  CREATE INDEX IF NOT EXISTS ledger_house_idx ON ledger (house_id, id DESC);
  CREATE INDEX IF NOT EXISTS rivals_house_idx ON rivals (house_id);
`;

// No table carries anything beyond a username, so none is staging:private.

class ApiError extends Error {
  constructor(status, message) { super(message); this.status = status; }
}

const fmt = (n) => Number(n).toLocaleString('en-US');

// The turn number is worked out from the founding moment, so time passing
// is the clock: turn = floor((now − founded_at) / 30 min) + 1.
function turnOf(house, now) {
  return Math.max(1, Math.floor((now.getTime() - house.founded_at.getTime()) / TURN_MS) + 1);
}

// A turn's part of the day, from how far into the turn the moment falls:
// a turn is a day in miniature — dawn, noon, dusk.
function partOfDay(house, when) {
  const mins = ((when.getTime() - house.founded_at.getTime()) % TURN_MS) / 60000;
  return mins < 10 ? 'dawn' : mins < 20 ? 'noon' : 'dusk';
}

const rivalStrength = (r, turn) => r.base_strength + RIVAL_GROWTH_STRENGTH * turn;
const rivalGold = (r, turn) => Math.max(0, Number(r.base_gold) + RIVAL_GROWTH_GOLD * turn - Number(r.gold_taken));

async function addLedger(client, house, turn, when, kind, text, goldDelta, workersDelta, toolsDelta) {
  await client.query(
    `INSERT INTO ledger (house_id, turn, part_of_day, kind, text, gold_delta, workers_delta, tools_delta, created_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
    [house.id, turn, partOfDay(house, when), kind, text, goldDelta, workersDelta || 0, toolsDelta || 0, when],
  );
}

// Found a house for a first-time player: 10,000 gold, 50 workers, and the
// game's eight rivals, none of them met yet.
async function foundHouse(client, user, demo, now) {
  const username = user.username || 'the founder';
  const { rows: [house] } = await client.query(
    `INSERT INTO houses (user_id, username, demo, gold, workers, founded_at, ticked_turn)
     VALUES ($1, $2, $3, $4, $5, $6, 1) RETURNING *`,
    [user.id, username, demo, 10000, 50, now],
  );
  for (const [name, baseStrength, baseGold] of RIVAL_BASES) {
    await client.query(
      `INSERT INTO rivals (house_id, name, base_strength, base_gold) VALUES ($1, $2, $3, $4)`,
      [house.id, name, baseStrength, baseGold],
    );
  }
  await addLedger(client, house, 1, now, 'founded',
    `The house was founded with 50 workers and 10,000 gold in the treasury.`, 10000, 0, 0);
  return house;
}

// The staging demo (see "A first version's populated demo" in the platform
// conventions): the viewer's own house set up mid-game at turn 87, written
// once, idempotently. Founded 86 turns ago with 5 minutes of turn 87 gone,
// and the dozen ledger entries the screen shows. Every control works on it.
async function seedDemoHouse(client, user, now) {
  const foundedAt = new Date(now.getTime() - (DEMO_TURN - 1) * TURN_MS - 5 * 60000);
  const username = user.username || 'the founder';
  const { rows: [house] } = await client.query(
    `INSERT INTO houses (user_id, username, demo, gold, workers, founded_at, ticked_turn)
     VALUES ($1, $2, true, $3, $4, $5, $6)
     ON CONFLICT (user_id, demo) DO NOTHING
     RETURNING *`,
    [user.id, username, 48250, 1326, foundedAt, DEMO_TURN],
  );
  if (!house) return null; // already seeded for this viewer

  for (const [name, baseStrength, baseGold, goldTaken] of DEMO_RIVALS) {
    await client.query(
      `INSERT INTO rivals (house_id, name, base_strength, base_gold, gold_taken, last_met_turn)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [house.id, name, baseStrength, baseGold, goldTaken, name === 'House Varek' ? DEMO_TURN : DEMO_TURN - 1],
    );
  }
  await client.query(
    `INSERT INTO house_tools (house_id, tool_key, count) VALUES ($1, 'cart', 3), ($1, 'plough', 6)`,
    [house.id],
  );

  // A moment inside turn T, at the given part of the day, for the seed's
  // chronicle timestamps.
  const inTurn = (t, part) => new Date(
    foundedAt.getTime() + (t - 1) * TURN_MS + { dawn: 5, noon: 15, dusk: 25 }[part] * 60000);
  // Oldest first, so the chronicle's ids ascend with the turns and
  // "newest first" falls out of the id ordering.
  const entries = [
    [80, 'noon', 'tribute', 'Your workers\' tribute filled the treasury.', 3654, 0, 0],
    [80, 'dawn', 'challenge_won', 'Your merchants outsold House Quill on market day and won 1,580 of their gold.', 1580, 0, 0],
    [81, 'dusk', 'tools', 'A Mill Wheel was raised on the stream.', -5000, 0, 1],
    [82, 'noon', 'tribute', 'Your workers\' tribute filled the treasury.', 3762, 0, 0],
    [82, 'dawn', 'recruit', 'Twenty new workers took up your colours.', -4000, 20, 0],
    [83, 'dawn', 'challenge_won', 'Your merchants outsold House Holt on market day and won 2,260 of their gold.', 2260, 0, 0],
    [84, 'noon', 'tribute', 'Your workers\' tribute filled the treasury.', 3870, 0, 0],
    [84, 'dusk', 'tools', 'A Hand Cart was bought for the yards.', -1000, 0, 1],
    [85, 'dawn', 'recruit', 'Thirty new workers took up your colours.', -6000, 30, 0],
    [85, 'dawn', 'challenge_held', 'House Ysolt\'s traders held the market. You won nothing this time.', 0, 0, 0],
    [86, 'noon', 'tribute', 'Your workers\' tribute filled the treasury.', 3978, 0, 0],
    [86, 'dusk', 'tools', 'The smiths delivered five Iron Ploughs to the fields.', -12000, 0, 5],
    [87, 'dawn', 'recruit', 'Forty-two new workers took up your colours.', -8400, 42, 0],
    [87, 'dawn', 'challenge_won', 'Your merchants outsold House Varek on market day and won 3,940 of their gold.', 3940, 0, 0],
  ];
  for (const [turn, part, kind, text, gold, workers, tools] of entries) {
    await addLedger(client, house, turn, inTurn(turn, part), kind, text, gold, workers, tools);
  }
  return house;
}

// Tribute for every turn since the last one that was ticked, written as one
// chronicle entry. Only gold arrives on its own: workers come from
// recruiting, rivals grow on their own curve (worked out when read).
async function tickHouse(client, house, now) {
  const turn = turnOf(house, now);
  if (turn <= house.ticked_turn) return turn;
  const missed = turn - house.ticked_turn;
  const tribute = TRIBUTE_PER_WORKER * house.workers * missed;
  if (tribute > 0) house.gold = Number(house.gold) + tribute;
  house.ticked_turn = turn;
  await client.query('UPDATE houses SET gold = $1, ticked_turn = $2 WHERE id = $3',
    [house.gold, turn, house.id]);
  if (tribute > 0) {
    await addLedger(client, house, turn, now, 'tribute',
      `Your workers' tribute filled the treasury.`, tribute, 0, 0);
  }
  return turn;
}

// The whole screen's state, after any founding and ticking: the house, its
// tools, strength and rank, all nine houses ranked by strength, when the
// next tribute lands, and the latest 50 chronicle entries.
async function loadState(client, house, now) {
  const turn = turnOf(house, now);
  const { rows: toolRows } = await client.query(
    'SELECT tool_key, count FROM house_tools WHERE house_id = $1', [house.id]);
  const toolCounts = {};
  let toolTotal = 0;
  let toolStrength = 0;
  for (const row of toolRows) {
    toolCounts[row.tool_key] = row.count;
    toolTotal += row.count;
    toolStrength += row.count * (TOOL_BY_KEY[row.tool_key]?.bonus || 0);
  }
  const strength = house.workers + toolStrength;

  const { rows: rivalRows } = await client.query(
    'SELECT * FROM rivals WHERE house_id = $1 ORDER BY id', [house.id]);
  const houses = rivalRows.map((r) => ({
    id: r.id,
    name: r.name,
    strength: rivalStrength(r, turn),
    gold: rivalGold(r, turn),
    met: r.last_met_turn >= turn,
    you: false,
  }));
  houses.push({ name: 'House of ' + house.username, strength, gold: Number(house.gold), met: false, you: true });
  houses.sort((a, b) => b.strength - a.strength || (a.you ? -1 : b.you ? 1 : 0));
  const me = houses.find((h) => h.you);
  const rank = houses.indexOf(me) + 1;

  const { rows: entryRows } = await client.query(
    `SELECT turn, part_of_day, kind, text, gold_delta, workers_delta, tools_delta
     FROM ledger WHERE house_id = $1 ORDER BY id DESC LIMIT $2`, [house.id, LEDGER_LIMIT]);

  return {
    house: {
      name: 'House of ' + house.username,
      gold: Number(house.gold),
      workers: house.workers,
      tools: toolTotal,
      founded: turn === 1 && house.ticked_turn === 1,
    },
    turn,
    tools: toolCounts,
    toolDefs: TOOL_DEFS,
    strength,
    rank,
    houseCount: houses.length,
    workerCost: WORKER_COST,
    nextTributeAt: new Date(house.founded_at.getTime() + turn * TURN_MS).toISOString(),
    houses,
    ledger: entryRows.map((e) => ({
      turn: e.turn,
      part: e.part_of_day,
      kind: e.kind,
      text: e.text,
      gold: Number(e.gold_delta),
      workers: e.workers_delta,
      tools: e.tools_delta,
    })),
  };
}

// Every write ticks first, then runs in one transaction with the house row
// locked, so two requests can never spend the same gold. The handler
// returns the action's report; a refusal throws an ApiError and nothing is
// spent.
async function withHouse(req, res, handler) {
  // Demo play reads and writes the viewer's demo house only, so staging
  // previews never touch the real house.
  const demo = IS_STAGING && req.query.demo === '1';
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    let house = demo
      ? await seedDemoHouse(client, req.user, req.now)
      : null;
    if (!house) {
      const { rows } = await client.query(
        'SELECT * FROM houses WHERE user_id = $1 AND demo = $2', [req.user.id, demo]);
      house = rows[0] || await foundHouse(client, req.user, demo, req.now);
    }
    const { rows: [locked] } = await client.query(
      'SELECT * FROM houses WHERE id = $1 FOR UPDATE', [house.id]);
    const turn = await tickHouse(client, locked, req.now);
    const report = await handler(client, locked, turn, req);
    // Re-read the row the handler just updated, so the state the client
    // gets carries the action's own numbers.
    const { rows: [fresh] } = await client.query(
      'SELECT * FROM houses WHERE id = $1', [locked.id]);
    const state = await loadState(client, fresh, req.now);
    await client.query('COMMIT');
    res.json(report ? { ...state, report } : state);
  } catch (err) {
    try { await client.query('ROLLBACK'); } catch {}
    if (err instanceof ApiError) return res.status(err.status).json({ error: err.message });
    console.error(err);
    return res.status(500).json({ error: 'Something went wrong. Nothing was spent.' });
  } finally {
    client.release();
  }
}

// Found (or load) the house and show it. A guest gets the example houses
// and nothing else, with nothing written.
app.get('/api/house', async (req, res) => {
  if (!req.user) return res.json({ house: null, houses: GUEST_RIVALS });
  try { await withHouse(req, res, () => {}); }
  catch (err) {
    console.error(err);
    return res.status(500).json({ error: 'The house could not be loaded.' });
  }
});

app.post('/api/recruit', (req, res) => withHouse(req, res, async (client, house, turn, req) => {
  const count = req.body && req.body.count;
  if (!Number.isInteger(count) || count < 1) {
    throw new ApiError(400, 'Choose how many workers to hire.');
  }
  const cost = WORKER_COST * count;
  if (Number(house.gold) < cost) {
    throw new ApiError(400, `The treasury cannot pay ${fmt(cost)} gold. Nothing was spent.`);
  }
  await client.query('UPDATE houses SET gold = gold - $1, workers = workers + $2 WHERE id = $3',
    [cost, count, house.id]);
  await addLedger(client, house, turn, req.now, 'recruit',
    `${fmt(count)} new workers took up your colours.`, -cost, count, 0);
  return null;
}));

app.post('/api/tools', (req, res) => withHouse(req, res, async (client, house, turn, req) => {
  const tool = TOOL_BY_KEY[req.body && req.body.tool];
  if (!tool) throw new ApiError(400, 'That tool is not for sale.');
  if (Number(house.gold) < tool.price) {
    throw new ApiError(400, `The treasury cannot pay ${fmt(tool.price)} gold. Nothing was spent.`);
  }
  await client.query('UPDATE houses SET gold = gold - $1 WHERE id = $2', [tool.price, house.id]);
  await client.query(
    `INSERT INTO house_tools (house_id, tool_key, count) VALUES ($1, $2, 1)
     ON CONFLICT (house_id, tool_key) DO UPDATE SET count = house_tools.count + 1`,
    [house.id, tool.key]);
  const article = /^[aeiou]/i.test(tool.name) ? 'An' : 'A';
  await addLedger(client, house, turn, req.now, 'tools',
    `${article} ${tool.name} was bought for the house's work for ${fmt(tool.price)} gold.`,
    -tool.price, 0, 1);
  return null;
}));

app.post('/api/challenge', (req, res) => withHouse(req, res, async (client, house, turn, req) => {
  const rivalId = req.body && req.body.rivalId;
  const { rows: [rival] } = await client.query(
    'SELECT * FROM rivals WHERE id = $1 AND house_id = $2', [rivalId, house.id]);
  if (!rival) throw new ApiError(404, 'That house is not one of your rivals.');
  if (rival.last_met_turn >= turn) {
    throw new ApiError(400, `${rival.name} has already been met this turn. Try again next turn.`);
  }
  const { rows: [fresh] } = await client.query(
    'SELECT workers FROM houses WHERE id = $1', [house.id]);
  const { rows: toolRows } = await client.query(
    'SELECT tool_key, count FROM house_tools WHERE house_id = $1', [house.id]);
  const myStrength = fresh.workers + toolRows.reduce(
    (sum, t) => sum + t.count * (TOOL_BY_KEY[t.tool_key]?.bonus || 0), 0);
  const theirStrength = rivalStrength(rival, turn);
  const won = myStrength > theirStrength;
  const moved = won ? Math.floor(rivalGold(rival, turn) / 10) : 0;

  await client.query('UPDATE rivals SET last_met_turn = $1, gold_taken = gold_taken + $2 WHERE id = $3',
    [turn, moved, rival.id]);
  let text;
  if (won) {
    await client.query('UPDATE houses SET gold = gold + $1 WHERE id = $2', [moved, house.id]);
    text = `Your merchants outsold ${rival.name} on market day and won ${fmt(moved)} of their gold.`;
    await addLedger(client, house, turn, req.now, 'challenge_won', text, moved, 0, 0);
  } else {
    text = `${rival.name}'s traders held the market. You won nothing this time.`;
    await addLedger(client, house, turn, req.now, 'challenge_held', text, 0, 0, 0);
  }
  return {
    rivalName: rival.name,
    yourStrength: myStrength,
    rivalStrength: theirStrength,
    won,
    gold: moved,
    part: partOfDay(house, req.now),
    text,
  };
}));

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// The template ships no favicon file; index.html carries an inline SVG
// icon instead. Answer 204 here so anything that still probes
// /favicon.ico (older browsers, direct visits) doesn't fall through to
// the auth-gated catch-all and surface a 401 in the console on every
// fresh load.
app.get('/favicon.ico', (_req, res) => res.status(204).end());

app.use(express.static(path.join(__dirname, 'public')));

// HTML shell: serve the app if authenticated. Unauthenticated top-level
// visits (share links pasted into a browser — Sec-Fetch-Dest: document)
// are sent to the platform's chromeless view of this app, where the shell
// embeds it with a real token so the link just works. Every other
// tokenless case (iframe loads with an expired token, old browsers
// without Sec-Fetch-*) gets the "open in Homeroom" landing page instead
// of a redirect, so the platform shell is never loaded INSIDE its own
// app iframe and stray visits still don't reveal the app.
app.get('*', (req, res) => {
  if (!req.user && !req.guest) {
    // Deep-link pass-through (platform #743): carry the visited
    // path+query into the chromeless view so share links land on the
    // shared screen, not Home. The clean platform route stores `path`
    // as one encoded query value so an inner ?, &, or = survives. The
    // shell decodes and validates it as relative-only before use. The
    // character test keeps the
    // value attribute-safe for the landing anchor below — anything
    // unusual falls back to the bare link.
    const deepPath = /^\/[A-Za-z0-9\-._~!$&()*+,;=:@\/%?]*$/.test(req.originalUrl)
      ? '?path=' + encodeURIComponent(req.originalUrl) : '';
    if (PLATFORM_ORIGIN && req.get('sec-fetch-dest') === 'document') {
      return res.redirect(302, PLATFORM_ORIGIN + '/app/chaosroom-7eaeba/full' + deepPath);
    }
    return res.status(401).send(`<!doctype html><meta charset=utf-8><title>Open in Homeroom</title>
<body style="font-family:system-ui;background:#09090b;color:#e4e4e7;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0">
  <div style="max-width:24rem;padding:2rem;text-align:center">
    <h1 style="font-size:1.25rem;margin:0 0 0.5rem">Open this app inside Homeroom</h1>
    <p style="color:#a1a1aa;font-size:0.9rem;margin:0 0 1.25rem">This page is served via the platform; direct visits aren't authenticated.</p>
    <a href="${PLATFORM_ORIGIN}/app/chaosroom-7eaeba/full${deepPath}" style="display:inline-block;padding:0.5rem 1rem;background:#7c3aed;color:white;border-radius:0.5rem;text-decoration:none;font-size:0.9rem">Open in Homeroom</a>
  </div>
</body>`);
  }
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const server = app.listen(port, () => console.log(`Listening on :${port}`));
// Let Envoy retire idle upstream connections at 60s, with a 15s margin.
server.keepAliveTimeout = 75_000;

// Boot: apply the schema, then report. A failed schema stops the app
// rather than serving a screen that cannot work.
(async () => {
  try { await pool.query(SCHEMA); }
  catch (err) { console.error('schema failed: ' + err.message); process.exit(1); }
})();

// Graceful shutdown: stop accepting connections, drain about 3 s, close
// the pool, exit.
let shuttingDown = false;
function shutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  const done = () => pool.end().then(() => process.exit(0));
  server.close(done);
  setTimeout(done, 3000).unref();
}
process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);
