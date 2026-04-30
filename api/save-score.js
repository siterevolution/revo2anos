// Função servidor — valida e salva pontuação com segurança total
// Segredo NUNCA exposto no frontend — usa sistema de desafio servidor

const SUPA_URL = process.env.SUPA_URL;
const SUPA_KEY = process.env.SUPA_SERVICE_KEY;
const MAX_SCORE         = 1000000;
const MAX_PLAY_MS       = 4 * 60 * 60 * 1000; // máx 4h de sessão
const CHALLENGE_MAX_AGE = 20 * 60 * 1000;      // desafio expira em 20 min
const MAX_PTS_PER_SEC   = 1500; // margem segura acima do top legítimo (~940 pts/s)
const RATE_LIMIT_MS     = 5 * 60 * 1000; // 1 envio a cada 5 minutos por nickname

const ALLOWED_ORIGINS = [
  'https://www.revo2anos.com',
  'https://revo2anos.com'
];

export default async function handler(req, res) {
  // ── CORS — bloqueia origens externas ────────────────────────────────────
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

  const { nickname, contact, score, timestamp, playTime, nonce, ts, sig } = req.body || {};

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

  // ── Validação do timestamp da requisição ────────────────────────────────
  const now = Date.now();
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
    console.warn(`FRAUDE desafio: nick=${nickname} score=${score}`);
    return res.status(403).json({ error: 'Desafio inválido' });
  }

  // ── Validação de tempo REAL pelo servidor ───────────────────────────────
  // O desafio é emitido no início do jogo — o servidor sabe exatamente
  // quanto tempo passou desde lá. Ignora o que o cliente declara.
  const actualElapsedMs = now - ts;
  const minTimeMs = (score / MAX_PTS_PER_SEC) * 1000;

  if (actualElapsedMs < minTimeMs) {
    console.warn(`FRAUDE tempo real: score=${score} em ${actualElapsedMs}ms (mín: ${Math.round(minTimeMs)}ms) nick=${nickname}`);
    return res.status(400).json({ error: 'Pontuação incompatível com o tempo de jogo' });
  }
  if (actualElapsedMs > MAX_PLAY_MS) {
    console.warn(`FRAUDE sessão longa: ${actualElapsedMs}ms nick=${nickname}`);
    return res.status(400).json({ error: 'Sessão expirada, jogue novamente' });
  }

  // ── Rate limiting — máx 1 envio por nickname a cada 5 minutos ──────────
  const normalizedNick = nickname.trim().substring(0, 16).toUpperCase();
  try {
    const rateWindow = new Date(now - RATE_LIMIT_MS).toISOString();
    const rateRes = await fetch(
      `${SUPA_URL}/rest/v1/scores?nickname=eq.${encodeURIComponent(normalizedNick)}&created_at=gte.${rateWindow}&select=id&limit=1`,
      { headers: { 'apikey': SUPA_KEY, 'Authorization': `Bearer ${SUPA_KEY}` } }
    );
    if (rateRes.ok) {
      const recent = await rateRes.json();
      if (recent.length > 0) {
        console.warn(`RATE LIMIT: nick=${normalizedNick}`);
        return res.status(429).json({ error: 'Aguarde 5 minutos antes de enviar outra pontuação' });
      }
    }
  } catch(e) {
    // Se a checagem falhar, permite passar (não bloqueia jogador legítimo)
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

async function hmacSHA256(data, secret) {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
