// Gera um desafio assinado pelo servidor — nunca expõe o segredo ao cliente
// O cliente usa esse desafio para provar que passou pelo nosso servidor

const ALLOWED_ORIGINS = [
  'https://www.revo2anos.com',
  'https://revo2anos.com'
];

export default async function handler(req, res) {
  // ── CORS — só aceita requests do próprio site ────────────────────────────
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  } else if (origin) {
    // Origem externa → bloqueia
    return res.status(403).json({ error: 'Origem não autorizada' });
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).end();

  const secret = process.env.SCORE_SECRET;
  if (!secret) return res.status(500).json({ error: 'Configuração ausente' });

  // Gera nonce aleatório + timestamp → assina com segredo do servidor
  const ts = Date.now();
  const nonce = Array.from(crypto.getRandomValues(new Uint8Array(16)))
    .map(b => b.toString(16).padStart(2, '0')).join('');

  const sig = await hmacSHA256(`${nonce}:${ts}`, secret);

  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.status(200).json({ nonce, ts, sig });
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
