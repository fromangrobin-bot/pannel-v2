// netlify/functions/auth-register.js
// ─────────────────────────────────────────────
// Inscription d'un nouvel utilisateur
// POST /api/auth-register
// Body: { email, password, name }
// ─────────────────────────────────────────────

const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Headers CORS — permet au dashboard d'appeler cette fonction
const HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
};

exports.handler = async (event) => {
  // Requête preflight CORS (navigateur vérifie avant d'envoyer)
  if (event.httpMethod === 'OPTIONS') {
    return { statusCode: 204, headers: HEADERS, body: '' };
  }

  if (event.httpMethod !== 'POST') {
    return { statusCode: 405, headers: HEADERS, body: JSON.stringify({ error: 'Méthode non autorisée' }) };
  }

  let body;
  try {
    body = JSON.parse(event.body);
  } catch {
    return { statusCode: 400, headers: HEADERS, body: JSON.stringify({ error: 'JSON invalide' }) };
  }

  const { email, password, name } = body;

  // Validation basique
  if (!email || !password) {
    return { statusCode: 400, headers: HEADERS, body: JSON.stringify({ error: 'Email et mot de passe requis' }) };
  }
  if (password.length < 8) {
    return { statusCode: 400, headers: HEADERS, body: JSON.stringify({ error: 'Mot de passe trop court (8 caractères min)' }) };
  }
  if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { statusCode: 400, headers: HEADERS, body: JSON.stringify({ error: 'Email invalide' }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

  try {
    await client.connect();

    // Vérifier si l'email existe déjà
    const exists = await client.query('SELECT id FROM users WHERE email = $1', [email.toLowerCase()]);
    if (exists.rows.length > 0) {
      return { statusCode: 409, headers: HEADERS, body: JSON.stringify({ error: 'Cet email est déjà utilisé' }) };
    }

    // Hasher le mot de passe (10 rounds = bon compromis sécurité/vitesse)
    const passwordHash = await bcrypt.hash(password, 10);

    // Créer l'utilisateur
    const result = await client.query(
      'INSERT INTO users (email, password_hash, name) VALUES ($1, $2, $3) RETURNING id, email, name',
      [email.toLowerCase(), passwordHash, name || email.split('@')[0]]
    );
    const user = result.rows[0];

    // Créer une ligne vide de données pour cet utilisateur
    await client.query(
      'INSERT INTO dashboard_data (user_id) VALUES ($1)',
      [user.id]
    );

    // Générer un token JWT valable 30 jours
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    return {
      statusCode: 201,
      headers: HEADERS,
      body: JSON.stringify({
        token,
        user: { id: user.id, email: user.email, name: user.name },
      }),
    };
  } catch (err) {
    console.error('Erreur register:', err);
    return { statusCode: 500, headers: HEADERS, body: JSON.stringify({ error: 'Erreur serveur' }) };
  } finally {
    await client.end();
  }
};
