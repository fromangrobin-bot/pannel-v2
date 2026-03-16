// netlify/functions/data-sync.js
// ─────────────────────────────────────────────
// Lecture et sauvegarde des données du dashboard
// GET  /api/data-sync  → renvoie les données de l'utilisateur
// POST /api/data-sync  → sauvegarde les données
// Header requis: Authorization: Bearer <token>
// ─────────────────────────────────────────────

const { Client } = require('pg');
const jwt = require('jsonwebtoken');

const HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Content-Type': 'application/json',
};

// Vérifie le token JWT et renvoie le userId
function verifyToken(event) {
  const authHeader = event.headers.authorization || event.headers.Authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return null;
  }
  const token = authHeader.slice(7);
  try {
    return jwt.verify(token, process.env.JWT_SECRET);
  } catch {
    return null;
  }
}

exports.handler = async (event) => {
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: HEADERS, body: '' };
  }

  // Vérifier l'authentification
  const decoded = verifyToken(event);
  if (!decoded) {
    return { statusCode: 401, headers: HEADERS, body: JSON.stringify({ error: 'Non authentifié' }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

  try {
    await client.connect();

    // ── GET : Charger les données ──────────────────
    if (event.httpMethod === 'GET') {
      const result = await client.query(
        'SELECT * FROM dashboard_data WHERE user_id = $1',
        [decoded.userId]
      );

      if (result.rows.length === 0) {
        // Première connexion depuis un nouvel appareil, créer la ligne
        await client.query('INSERT INTO dashboard_data (user_id) VALUES ($1)', [decoded.userId]);
        return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ data: {} }) };
      }

      const row = result.rows[0];
      return {
        statusCode: 200,
        headers: HEADERS,
        body: JSON.stringify({
          data: {
            todos:        row.todos        || {},
            notes:        row.notes        || [],
            objectives:   row.objectives   || [],
            transactions: row.transactions || [],
            recurrents:   row.recurrents   || [],
            favoris:      row.favoris      || [],
            quick_todos:  row.quick_todos  || [],
          },
          updated_at: row.updated_at,
        }),
      };
    }

    // ── POST : Sauvegarder les données ─────────────
    if (event.httpMethod === 'POST') {
      let body;
      try {
        body = JSON.parse(event.body);
      } catch {
        return { statusCode: 400, headers: HEADERS, body: JSON.stringify({ error: 'JSON invalide' }) };
      }

      const { todos, notes, objectives, transactions, recurrents, favoris, quick_todos } = body;

      // UPSERT : met à jour si existe, insère sinon
      await client.query(
        `INSERT INTO dashboard_data (user_id, todos, notes, objectives, transactions, recurrents, favoris, quick_todos, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
         ON CONFLICT (user_id)
         DO UPDATE SET
           todos        = EXCLUDED.todos,
           notes        = EXCLUDED.notes,
           objectives   = EXCLUDED.objectives,
           transactions = EXCLUDED.transactions,
           recurrents   = EXCLUDED.recurrents,
           favoris      = EXCLUDED.favoris,
           quick_todos  = EXCLUDED.quick_todos,
           updated_at   = NOW()`,
        [
          decoded.userId,
          JSON.stringify(todos        || {}),
          JSON.stringify(notes        || []),
          JSON.stringify(objectives   || []),
          JSON.stringify(transactions || []),
          JSON.stringify(recurrents   || []),
          JSON.stringify(favoris      || []),
          JSON.stringify(quick_todos  || []),
        ]
      );

      return { statusCode: 200, headers: HEADERS, body: JSON.stringify({ ok: true }) };
    }

    return { statusCode: 405, headers: HEADERS, body: JSON.stringify({ error: 'Méthode non autorisée' }) };

  } catch (err) {
    console.error('Erreur data-sync:', err);
    return { statusCode: 500, headers: HEADERS, body: JSON.stringify({ error: 'Erreur serveur' }) };
  } finally {
    await client.end();
  }
};
