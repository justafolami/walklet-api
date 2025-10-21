import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { authMiddleware, createToken } from './auth.js';

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

// Root route (friendly message)
app.get('/', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'walklet-api',
    message: 'Welcome to Walklet API. Try GET /health',
    time: new Date().toISOString(),
  });
});

// Health check
app.get('/health', (req, res) => {
  res.status(200).json({
    status: 'ok',
    service: 'walklet-api',
    time: new Date().toISOString(),
  });
});

// Debug: issue a token to test auth flow (dev only)
app.get('/debug/token', (req, res) => {
  const email = String(req.query.email || 'test@example.com');
  const sub = String(req.query.sub || 'debug-user');
  try {
    const token = createToken({ id: sub, email });
    return res.json({
      token,
      note: 'Use this token in Authorization header as: Bearer <token>',
    });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});

// Debug: protected route (requires Bearer token)
app.get('/debug/protected', authMiddleware, (req, res) => {
  return res.json({
    ok: true,
    user: req.user, // { sub, email, iat, exp }
  });
});

app.listen(PORT, () => {
  console.log(`✅ Walklet API listening on http://localhost:${PORT}`);
});