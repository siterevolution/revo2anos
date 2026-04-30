// Função servidor — valida e salva pontuação com segurança
// A chave do Supabase fica APENAS aqui, nunca no frontend

const SUPA_URL = process.env.SUPA_URL;
const SUPA_KEY = process.env.SUPA_SERVICE_KEY; // chave secreta (service role)
const MAX_SCORE = 1000000;
const MAX_AGE_MS = 10 * 60 * 1000; // requisição expira em 10 minutos

export default async function handler(req, res) {
  // Só aceita POST
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Método não permitido' });
  }

  const { nickname, contact, score, timestamp, token } = req.body || {};

  // ── Validações básicas ──────────────────────────────────────────────────
  if (!nickname || !contact || score === undefined) {
    return res.status(400).json({ error: 'Campos obrigatórios ausentes' });
  }
  if (typeof score !== 'number' || score < 0 || score > MAX_SCORE) {
    return res.status(400).json({ error: 'Pontuação inválida' });
  }
  if (!contact || contact.trim() === '' || contact === 'não informado') {
    return res.status(400).json({ error: 'Contato obrigatório' });
  }

  // ── Validação de tempo (evita replay attacks) ───────────────────────────
  const now = Date.now();
  if (!timestamp || Math.abs(now - timestamp) > MAX_AGE_MS) {
    return res.status(400).json({ error: 'Requisição expirada' });
  }

  // ── Validação do token HMAC ─────────────────────────────────────────────
  const secret = process.env.SCORE_SECRET || 'REV2026';
  const expectedToken = await gerarToken(score, contact, timestamp, secret);
  if (token !== expectedToken) {
    return res.status(403).json({ error: 'Token inválido' });
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
        nickname: nickname.trim().substring(0, 16).toUpperCase(),
        contact: contact.trim().substring(0, 40),
        score: Math.floor(score)
      })
    });

    if (r.ok) {
      return res.status(200).json({ ok: true });
    } else {
      const err = await r.text();
      console.error('Supabase error:', err);
      return res.status(500).json({ error: 'Erro ao salvar' });
    }
  } catch (e) {
    console.error('Fetch error:', e);
    return res.status(500).json({ error: 'Erro interno' });
  }
}

// Gera token HMAC-SHA256
async function gerarToken(score, contact, timestamp, secret) {
  const encoder = new TextEncoder();
  const data = `${Math.floor(score)}:${contact.trim()}:${timestamp}`;
  const key = await crypto.subtle.importKey(
    'raw', encoder.encode(secret),
    { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']
  );
  const sig = await crypto.subtle.sign('HMAC', key, encoder.encode(data));
  return btoa(String.fromCharCode(...new Uint8Array(sig)));
}
