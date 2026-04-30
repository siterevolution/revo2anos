// Leitura do ranking — servidor busca do Supabase e retorna
// Nenhuma chave exposta no frontend

const SUPA_URL = process.env.SUPA_URL;
const SUPA_KEY = process.env.SUPA_SERVICE_KEY;

export default async function handler(req, res) {
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

    // Cache de 30 segundos — evita sobrecarga
    res.setHeader('Cache-Control', 's-maxage=30, stale-while-revalidate');
    res.status(200).json(data);
  } catch(e) {
    res.status(500).json({ error: 'Erro interno' });
  }
}
