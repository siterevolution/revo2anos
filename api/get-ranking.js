// Leitura do ranking — servidor busca do Supabase e retorna
// Nenhuma chave exposta no frontend

const SUPA_URL = process.env.SUPA_URL;
const SUPA_KEY = process.env.SUPA_SERVICE_KEY;

const ALLOWED_ORIGINS = [
  'https://www.revo2anos.com',
  'https://revo2anos.com'
];

export default async function handler(req, res) {
  // ── CORS — só permite o próprio site ────────────────────────────────────
  const origin = req.headers.origin || '';
  if (ALLOWED_ORIGINS.includes(origin)) {
    res.setHeader('Access-Control-Allow-Origin', origin);
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, OPTIONS');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'GET') return res.status(405).end();

  try {
    const r = await fetch(
      `${SUPA_URL}/rest/v1/best_scores?select=nickname,score&order=score.desc&limit=10`,
      {
        headers: {
          'apikey': SUPA_KEY,
          'Authorization': `Bearer ${SUPA_KEY}`
        }
      }
    );

    if (!r.ok) return res.status(500).json({ error: 'Erro ao buscar ranking' });

    const data = await r.json();

    // Cache de 30 segundos — evita sobrecarga no servidor
    res.setHeader('Cache-Control', 's-maxage=30, stale-while-revalidate');
    res.status(200).json(data);
  } catch(e) {
    res.status(500).json({ error: 'Erro interno' });
  }
}
