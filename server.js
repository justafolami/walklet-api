import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import { z } from 'zod';
import { supabase } from './db.js';
import { authMiddleware, createToken } from './auth.js';
import { createAndEncryptWallet } from './wallet.js';

const app = express();
const PORT = process.env.PORT || 4000;

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
    username: row.username ?? null,
    age: row.age ?? null,
    weightKg:
      row.weight_kg !== null && row.weight_kg !== undefined
        ? Number(row.weight_kg)
        : null,
    heightCm: row.height_cm ?? null,
    walletAddress: row.wallet_address ?? null,
    createdAt: row.created_at,
  };
}

// Schemas
const signupSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(8),
});
const loginSchema = z.object({
  email: z.string().trim().email(),
  password: z.string().min(8),
});
const profileSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, 'Username must be at least 3 characters')
    .max(30, 'Username must be at most 30 characters')
    .regex(/^[a-zA-Z0-9_]+$/, 'Only letters, numbers, and underscores are allowed'),
  age: z.coerce.number().int().min(1).max(120).nullable().optional(),
  weightKg: z.coerce.number().min(1).max(1000).nullable().optional(),
  heightCm: z.coerce.number().int().min(50).max(250).nullable().optional(),
});

// Root + health
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'walklet-api',
    message: 'Welcome to Walklet API. Try GET /health',
    time: new Date().toISOString(),
  });
});
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'walklet-api',
    time: new Date().toISOString(),
  });
});

// Debug: token + protected
app.get('/debug/token', (req, res) => {
  const email = String(req.query.email || 'test@example.com');
  const sub = String(req.query.sub || 'debug-user');
  try {
    const token = createToken({ id: sub, email });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});
app.get('/debug/protected', authMiddleware, (req, res) => {
  return res.json({ ok: true, user: req.user });
});

// Signup (email+password) + wallet generation
app.post('/auth/signup', async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: 'Invalid input', details: parsed.error.flatten() });
  }

  try {
    const { email, password } = parsed.data;
    const normalizedEmail = email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(password, 10);

    // 1) Insert user
    const { data: user, error } = await supabase
      .from('users')
      .insert([
        {
          email: normalizedEmail,
          password_hash: passwordHash,
          age: null,
          weight_kg: null,
          height_cm: null,
          wallet_address: null,
          username: null,
        },
      ])
      .select('*')
      .single();

    if (error) {
      if (
        error.code === '23505' ||
        String(error.message).toLowerCase().includes('duplicate') ||
        String(error.message).includes('users_email_lower_unique')
      ) {
        return res.status(409).json({ error: 'Email already registered' });
      }
      console.error('Signup insert error:', error);
      return res.status(500).json({ error: 'Signup failed' });
    }

    // 2) Create + store wallet (encrypted)
    let updatedUser = user;
    try {
      const w = createAndEncryptWallet();
      const { data: user2, error: uerr } = await supabase
        .from('users')
        .update({
          wallet_address: w.address,
          wallet_encrypted: w.ciphertext,
          wallet_iv: w.iv,
          wallet_tag: w.tag,
          wallet_alg: w.alg,
          wallet_created_at: new Date().toISOString(),
        })
        .eq('id', user.id)
        .select('*')
        .single();
      if (uerr) {
        console.error('Wallet update error:', uerr);
      } else {
        updatedUser = user2;
      }
    } catch (e) {
      console.error('Wallet creation error:', e);
    }

    const token = createToken({ id: updatedUser.id, email: updatedUser.email });
    return res.status(201).json({ token, user: mapUserRow(updatedUser) });
  } catch (e) {
    console.error('Signup error:', e);
    return res.status(500).json({ error: 'Signup failed' });
  }
});

// Login
app.post('/auth/login', async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: 'Invalid input', details: parsed.error.flatten() });
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

// Current user
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

// Profile completion
app.post('/profile', authMiddleware, async (req, res) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: 'Invalid input', details: parsed.error.flatten() });
  }

  const { username, age = null, weightKg = null, heightCm = null } = parsed.data;

  try {
    const updates = { username, age, weight_kg: weightKg, height_cm: heightCm };

    const { data: user, error } = await supabase
      .from('users')
      .update(updates)
      .eq('id', req.user.sub)
      .select('*')
      .single();

    if (error) {
      if (
        error.code === '23505' ||
        String(error.message).includes('users_username_lower_unique')
      ) {
        return res.status(409).json({ error: 'Username already taken' });
      }
      console.error('Profile update error:', error);
      return res.status(500).json({ error: 'Profile update failed' });
    }

    return res.status(200).json({ user: mapUserRow(user) });
  } catch (e) {
    console.error('Profile error:', e);
    return res.status(500).json({ error: 'Profile update failed' });
  }
});

// Debug: manually create wallet for current user (dev only)
app.post('/debug/create-wallet', authMiddleware, async (req, res) => {
  try {
    const w = createAndEncryptWallet();
    const { data: user, error } = await supabase
      .from('users')
      .update({
        wallet_address: w.address,
        wallet_encrypted: w.ciphertext,
        wallet_iv: w.iv,
        wallet_tag: w.tag,
        wallet_alg: w.alg,
        wallet_created_at: new Date().toISOString(),
      })
      .eq('id', req.user.sub)
      .select('*')
      .single();

    if (error) {
      console.error('Debug wallet update error:', error);
      return res.status(500).json({ error: 'Update failed', detail: error.message });
    }

    return res.json({ ok: true, address: user.wallet_address });
  } catch (e) {
    console.error('Debug wallet creation error:', e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

app.listen(PORT, () => {
  console.log(`✅ Walklet API listening on http://localhost:${PORT}`);
});