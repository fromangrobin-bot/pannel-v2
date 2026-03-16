// netlify/functions/auth-login.js
// ─────────────────────────────────────────────
// Connexion d'un utilisateur existant
// POST /api/auth-login
// Body: { email, password }
// ─────────────────────────────────────────────

const { Client } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
};

exports.handler = async (event) => {
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

  const { email, password } = body;

  if (!email || !password) {
    return { statusCode: 400, headers: HEADERS, body: JSON.stringify({ error: 'Email et mot de passe requis' }) };
  }

  const client = new Client({ connectionString: process.env.DATABASE_URL, ssl: { rejectUnauthorized: false } });

  try {
    await client.connect();

    // Chercher l'utilisateur par email
    const result = await client.query(
      'SELECT id, email, name, password_hash FROM users WHERE email = $1',
      [email.toLowerCase()]
    );

    if (result.rows.length === 0) {
      // Message volontairement vague pour ne pas révéler si l'email existe
      return { statusCode: 401, headers: HEADERS, body: JSON.stringify({ error: 'Email ou mot de passe incorrect' }) };
    }

    const user = result.rows[0];

    // Comparer le mot de passe avec le hash stocké
    const passwordOk = await bcrypt.compare(password, user.password_hash);
    if (!passwordOk) {
      return { statusCode: 401, headers: HEADERS, body: JSON.stringify({ error: 'Email ou mot de passe incorrect' }) };
    }

    // Générer le token JWT (30 jours)
    const token = jwt.sign(
      { userId: user.id, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: '30d' }
    );

    return {
      statusCode: 200,
      headers: HEADERS,
      body: JSON.stringify({
        token,
        user: { id: user.id, email: user.email, name: user.name },
      }),
    };
  } catch (err) {
    console.error('Erreur login:', err);
    return { statusCode: 500, headers: HEADERS, body: JSON.stringify({ error: 'Erreur serveur' }) };
  } finally {
    await client.end();
  }
};
