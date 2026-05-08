// Função servidor — valida e salva pontuação com segurança total
// Segredo NUNCA exposto no frontend — usa sistema de desafio servidor

const SUPA_URL = process.env.SUPA_URL;
const SUPA_KEY = process.env.SUPA_SERVICE_KEY;
const MAX_SCORE         = 1000000;
const MAX_PLAY_MS       = 4 * 60 * 60 * 1000;
const CHALLENGE_MAX_AGE = 2 * 60 * 60 * 1000;
const MAX_PTS_PER_SEC   = 1500;
const RATE_LIMIT_MS     = 5 * 60 * 1000;

const ALLOWED_ORIGINS = [
  'https://www.revo2anos.com',
  'https://revo2anos.com'
];

export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (origin) {
    return res.status(403).json({ error: 'Origem não autorizada' });
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método não permitido' });

  const secret = process.env.SCORE_SECRET;
  if (!secret) return res.status(500).json({ error: 'Configuração ausente' });

  const { nickname, contact, score, timestamp, nonce, ts, sig } = req.body || {};

  // ── Validações básicas ──────────────────────────────────────────────────
  if (!nickname || !contact || score === undefined) {
    return res.status(400).json({ error: 'Campos obrigatórios ausentes' });
  }
  if (typeof score !== 'number' || score < 0 || score > MAX_SCORE) {
    return res.status(400).json({ error: 'Pontuação inválida' });
  }
  if (!contact.trim() || contact === 'não informado') {
    return res.status(400).json({ error: 'Contato obrigatório' });
  }

  const now = Date.now();
  const normalizedNick    = nickname.trim().substring(0, 16).toUpperCase();
  const normalizedContact = contact.trim().substring(0, 40).toLowerCase();

  // ── Verificação de banimento (nickname OU contato) ──────────────────────
  try {
    const banRes = await fetch(
      `${SUPA_URL}/rest/v1/banned?or=(nickname.eq.${encodeURIComponent(normalizedNick)},contact.eq.${encodeURIComponent(normalizedContact)})&banned_until=gte.${new Date(now).toISOString()}&select=nickname,contact,reason,banned_until&limit=1`,
      { headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` } }
    );
    if (banRes.ok) {
      const bans = await banRes.json();
      if (bans.length > 0) {
        const ban = bans[0];
        const minLeft = Math.ceil((new Date(ban.banned_until) - now) / 60000);
        console.warn(`BANIDO tentou jogar: nick=${normalizedNick} contact=${normalizedContact}`);
        return res.status(403).json({
          error: `Você está banido do ranking por conduta irregular. Desbloqueio em ${minLeft} minutos.`
        });
      }
    }
  } catch(e) {
    console.error('Ban check error:', e);
  }

  // ── Validação do timestamp da requisição ────────────────────────────────
  if (!timestamp || Math.abs(now - timestamp) > 10 * 60 * 1000) {
    return res.status(400).json({ error: 'Requisição expirada' });
  }

  // ── Validação do desafio servidor ───────────────────────────────────────
  if (!nonce || !ts || !sig) {
    return res.status(403).json({ error: 'Desafio ausente' });
  }
  if (typeof ts !== 'number' || Math.abs(now - ts) > CHALLENGE_MAX_AGE) {
    return res.status(400).json({ error: 'Desafio expirado' });
  }
  const expectedSig = await hmacSHA256(`${nonce}:${ts}`, secret);
  if (sig !== expectedSig) {
    console.warn(`FRAUDE desafio: nick=${normalizedNick} score=${score}`);
    return res.status(403).json({ error: 'Desafio inválido' });
  }

  // ── Tempo real pelo servidor ────────────────────────────────────────────
  const actualElapsedMs = now - ts;
  const minTimeMs = (score / MAX_PTS_PER_SEC) * 1000;

  if (actualElapsedMs < minTimeMs) {
    console.warn(`FRAUDE tempo: score=${score} em ${actualElapsedMs}ms (mín:${Math.round(minTimeMs)}ms) nick=${normalizedNick}`);
    // Bane automaticamente quem tenta burlar o tempo
    await autoban(normalizedNick, normalizedContact, `Fraude de tempo: ${score}pts em ${Math.round(actualElapsedMs/1000)}s`);
    return res.status(400).json({ error: 'Pontuação incompatível com o tempo de jogo. Você foi banido por 24h.' });
  }
  if (actualElapsedMs > MAX_PLAY_MS) {
    return res.status(400).json({ error: 'Sessão expirada, jogue novamente' });
  }

  // ── Rate limiting ───────────────────────────────────────────────────────
  try {
    const rateWindow = new Date(now - RATE_LIMIT_MS).toISOString();
    const rateRes = await fetch(
      `${SUPA_URL}/rest/v1/scores?nickname=eq.${encodeURIComponent(normalizedNick)}&created_at=gte.${rateWindow}&select=id&limit=1`,
      { headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` } }
    );
    if (rateRes.ok) {
      const recent = await rateRes.json();
      if (recent.length > 0) {
        return res.status(429).json({ error: 'Aguarde 5 minutos antes de enviar outra pontuação' });
      }
    }
  } catch(e) {
    console.error('Rate limit check error:', e);
  }

  // ── Salva no Supabase ───────────────────────────────────────────────────
  try {
    const r = await fetch(`${SUPA_URL}/rest/v1/scores`, {
      method: 'POST',
      headers: {
        'apikey': SUPA_KEY,
        'Authorization': `Bearer ${SUPA_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify({
        nickname: normalizedNick,
        contact:  contact.trim().substring(0, 40),
        score:    Math.floor(score)
      })
    });

    if (r.ok) return res.status(200).json({ ok: true });
    console.error('Supabase error:', await r.text());
    return res.status(500).json({ error: 'Erro ao salvar' });
  } catch (e) {
    console.error('Fetch error:', e);
    return res.status(500).json({ error: 'Erro interno' });
  }
}

// Bane automaticamente quem tenta fraude de tempo
async function autoban(nickname, contact, reason) {
  try {
    await fetch(`${SUPA_URL}/rest/v1/banned`, {
      method: 'POST',
      headers: {
        'apikey': SUPA_KEY,
        'Authorization': `Bearer ${SUPA_KEY}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify({ nickname, contact, reason })
    });
  } catch(e) {
    console.error('Autoban error:', e);
  }
}

async function hmacSHA256(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
