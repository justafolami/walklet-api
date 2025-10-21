require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const { z } = require('zod');
const { supabase } = require('./db');
const { createToken, authMiddleware } = require('./auth');

const app = express();
const PORT = process.env.PORT || 4000;

// CORS: allow our frontend during dev
app.use(
  cors({
    origin: [
      /^http:\/\/localhost:3000$/,
      /^http:\/\/localhost:3001$/,
      /^http:\/\/127\.0\.0\.1:3000$/,
      /^http:\/\/127\.0\.0\.1:3001$/,
    ],
    credentials: true,
  })
);

app.use(express.json());

// Helpers
function mapUserRow(row) {
  return {
    id: row.id,
    email: row.email,
    age: row.age ?? null,
    weightKg: row.weight_kg !== null && row.weight_kg !== undefined ? Number(row.weight_kg) : null,
    heightCm: row.height_cm ?? null,
    walletAddress: row.wallet_address ?? null,
    createdAt: row.created_at,
  };
}

// Schemas (validates and cleans input)
const signupSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
  age: z.coerce.number().int().min(1).max(120).optional().nullable(),
  weightKg: z.coerce.number().min(1).max(1000).optional().nullable(),
  heightCm: z.coerce.number().int().min(50).max(250).optional().nullable(),
});

const loginSchema = z.object({
  email: z.string().email(),
  password: z.string().min(8),
});

// Root route
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'walklet-api',
    message: 'Welcome to Walklet API. Try GET /health',
    time: new Date().toISOString(),
  });
});

// Health
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'walklet-api',
    time: new Date().toISOString(),
  });
});

// Signup
app.post('/auth/signup', async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
  }

  try {
    const { email, password, age = null, weightKg = null, heightCm = null } = parsed.data;
    const normalizedEmail = email.trim().toLowerCase();

    // Hash password
    const passwordHash = await bcrypt.hash(password, 10);

    // Insert user
    const { data: user, error } = await supabase
      .from('users')
      .insert([
        {
          email: normalizedEmail,
          password_hash: passwordHash,
          age,
          weight_kg: weightKg,
          height_cm: heightCm,
          wallet_address: null,
        },
      ])
      .select('*')
      .single();

    if (error) {
      // Unique email conflict
      const msg = (error && error.message) || '';
      if (msg.toLowerCase().includes('duplicate') || msg.includes('users_email_lower_unique')) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      console.error('Signup insert error:', error);
      return res.status(500).json({ error: 'Signup failed' });
    }

    const token = createToken({ id: user.id, email: user.email });
    return res.status(201).json({ token, user: mapUserRow(user) });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Signup failed' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res.status(400).json({ error: 'Invalid input', details: parsed.error.flatten() });
  }

  try {
    const email = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;

    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('email', email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const token = createToken({ id: user.id, email: user.email });
    return res.status(200).json({ token, user: mapUserRow(user) });
  } catch (e) {
    console.error('Login error:', e);
    return res.status(500).json({ error: 'Login failed' });
  }
});

// Get current user (requires Bearer token)
app.get('/me', authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from('users')
      .select('*')
      .eq('id', req.user.sub)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: 'User not found' });
    }

    return res.status(200).json({ user: mapUserRow(user) });
  } catch (e) {
    console.error('Me route error:', e);
    return res.status(500).json({ error: 'Failed to fetch user' });
  }
});

// Start
app.listen(PORT, () => {
  console.log(`✅ Walklet API listening on http://localhost:${PORT}`);
});