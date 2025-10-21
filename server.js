import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import { z } from "zod";
import { OAuth2Client } from "google-auth-library";
import { supabase } from "./db.js";
import { authMiddleware, createToken } from "./auth.js";
import { createAndEncryptWallet } from "./wallet.js";

const app = express();
const PORT = process.env.PORT || 4000;

const googleClientId = process.env.GOOGLE_CLIENT_ID || "";
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

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
const usernameRegex = /^[a-zA-Z0-9._-]+$/;
const profileSchema = z.object({
  username: z
    .string()
    .trim()
    .min(3, "Username must be at least 3 characters")
    .max(30, "Username must be at most 30 characters")
    .regex(
      usernameRegex,
      "Only letters, numbers, underscores (_), dots (.), and hyphens (-) are allowed"
    ),
  age: z.coerce.number().int().min(1).max(120).nullable().optional(),
  weightKg: z.coerce.number().min(0).max(1000).nullable().optional(),
  heightCm: z.coerce.number().int().min(50).max(250).nullable().optional(),
});
const walkSchema = z
  .object({
    startedAt: z
      .string()
      .refine((s) => !isNaN(Date.parse(s)), "Invalid startedAt"),
    endedAt: z.string().refine((s) => !isNaN(Date.parse(s)), "Invalid endedAt"),
    durationSec: z.number().int().min(0),
    distanceM: z.number().min(0),
    steps: z.number().int().min(0),
  })
  .refine((v) => Date.parse(v.endedAt) >= Date.parse(v.startedAt), {
    message: "endedAt must be after startedAt",
    path: ["endedAt"],
  });

// Root + health
app.get("/", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "walklet-api",
    message: "Welcome to Walklet API. Try GET /health",
    time: new Date().toISOString(),
  });
});
app.get("/health", (req, res) => {
  res.status(200).json({
    status: "ok",
    service: "walklet-api",
    time: new Date().toISOString(),
  });
});

// Debug
app.get("/debug/token", (req, res) => {
  const email = String(req.query.email || "test@example.com");
  const sub = String(req.query.sub || "debug-user");
  try {
    const token = createToken({ id: sub, email });
    return res.json({ token });
  } catch (e) {
    return res.status(500).json({ error: e.message });
  }
});
app.get("/debug/protected", authMiddleware, (req, res) => {
  return res.json({ ok: true, user: req.user });
});
app.post("/debug/create-wallet", authMiddleware, async (req, res) => {
  try {
    const w = createAndEncryptWallet();
    const { data: user, error } = await supabase
      .from("users")
      .update({
        wallet_address: w.address,
        wallet_encrypted: w.ciphertext,
        wallet_iv: w.iv,
        wallet_tag: w.tag,
        wallet_alg: w.alg,
        wallet_created_at: new Date().toISOString(),
      })
      .eq("id", req.user.sub)
      .select("*")
      .single();
    if (error) {
      console.error("Debug wallet update error:", error);
      return res
        .status(500)
        .json({ error: "Update failed", detail: error.message });
    }
    return res.json({ ok: true, address: user.wallet_address });
  } catch (e) {
    console.error("Debug wallet creation error:", e);
    return res.status(500).json({ error: e.message || String(e) });
  }
});

// Signup
app.post("/auth/signup", async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  try {
    const { email, password } = parsed.data;
    const normalizedEmail = email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(password, 10);

    const { data: user, error } = await supabase
      .from("users")
      .insert([{ email: normalizedEmail, password_hash: passwordHash }])
      .select("*")
      .single();

    if (error) {
      if (
        error.code === "23505" ||
        String(error.message).toLowerCase().includes("duplicate") ||
        String(error.message).includes("users_email_lower_unique")
      ) {
        return res.status(409).json({ error: "Email already registered" });
      }
      console.error("Signup insert error:", error);
      return res.status(500).json({ error: "Signup failed" });
    }

    // Create + store wallet
    let updatedUser = user;
    try {
      const w = createAndEncryptWallet();
      const { data: user2, error: uerr } = await supabase
        .from("users")
        .update({
          wallet_address: w.address,
          wallet_encrypted: w.ciphertext,
          wallet_iv: w.iv,
          wallet_tag: w.tag,
          wallet_alg: w.alg,
          wallet_created_at: new Date().toISOString(),
        })
        .eq("id", user.id)
        .select("*")
        .single();
      if (!uerr && user2) updatedUser = user2;
    } catch (e) {
      console.error("Wallet creation error:", e);
    }

    const token = createToken({ id: updatedUser.id, email: updatedUser.email });
    return res.status(201).json({ token, user: mapUserRow(updatedUser) });
  } catch (e) {
    console.error("Signup error:", e);
    return res.status(500).json({ error: "Signup failed" });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  try {
    const email = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;

    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) {
      return res.status(401).json({ error: "Invalid credentials" });
    }
    if (!user.password_hash) {
      return res
        .status(401)
        .json({ error: "Use Google Sign-In for this account" });
    }

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) {
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const token = createToken({ id: user.id, email: user.email });
    return res.status(200).json({ token, user: mapUserRow(user) });
  } catch (e) {
    console.error("Login error:", e);
    return res.status(500).json({ error: "Login failed" });
  }
});

// Google OAuth
app.post("/auth/google", async (req, res) => {
  try {
    if (!googleClient) {
      return res.status(500).json({ error: "Google client not configured" });
    }

    const bodySchema = z.object({ idToken: z.string().min(10) });
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success) {
      return res.status(400).json({ error: "Invalid idToken" });
    }

    const ticket = await googleClient.verifyIdToken({
      idToken: parsed.data.idToken,
      audience: googleClientId,
    });
    const payload = ticket.getPayload();
    if (!payload) {
      return res.status(401).json({ error: "Invalid Google token" });
    }

    const email = String(payload.email || "")
      .toLowerCase()
      .trim();
    const emailVerified = Boolean(payload.email_verified);
    if (!email || !emailVerified) {
      return res.status(401).json({ error: "Google email not verified" });
    }

    let { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();

    if (error || !user) {
      const { data: newUser, error: insErr } = await supabase
        .from("users")
        .insert([{ email, password_hash: "" }])
        .select("*")
        .single();
      if (insErr) {
        console.error("Google signup insert error:", insErr);
        return res.status(500).json({ error: "Signup failed" });
      }
      user = newUser;

      // Create wallet
      try {
        const w = createAndEncryptWallet();
        const { data: user2, error: uerr } = await supabase
          .from("users")
          .update({
            wallet_address: w.address,
            wallet_encrypted: w.ciphertext,
            wallet_iv: w.iv,
            wallet_tag: w.tag,
            wallet_alg: w.alg,
            wallet_created_at: new Date().toISOString(),
          })
          .eq("id", user.id)
          .select("*")
          .single();
        if (!uerr && user2) user = user2;
      } catch (e) {
        console.error("Wallet creation error (Google):", e);
      }
    }

    const token = createToken({ id: user.id, email: user.email });
    return res.status(200).json({ token, user: mapUserRow(user) });
  } catch (e) {
    console.error("Google auth error:", e);
    return res.status(500).json({ error: "Google auth failed" });
  }
});

// Set password (for Google-created accounts)
const setPwdSchema = z.object({ newPassword: z.string().min(8) });
app.post("/auth/set-password", authMiddleware, async (req, res) => {
  const parsed = setPwdSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id, email, password_hash")
      .eq("id", req.user.sub)
      .single();
    if (error || !user)
      return res.status(404).json({ error: "User not found" });

    if (user.password_hash && user.password_hash.length > 0) {
      return res
        .status(409)
        .json({ error: "Password already set. Use a password change flow." });
    }

    const passwordHash = await bcrypt.hash(parsed.data.newPassword, 10);
    const { error: upErr } = await supabase
      .from("users")
      .update({ password_hash: passwordHash })
      .eq("id", user.id);
    if (upErr) {
      console.error("Set password update error:", upErr);
      return res.status(500).json({ error: "Failed to set password" });
    }
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("Set password error:", e);
    return res.status(500).json({ error: "Failed to set password" });
  }
});

// Current user
app.get("/me", authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", req.user.sub)
      .single();

    if (error || !user) {
      return res.status(404).json({ error: "User not found" });
    }

    return res.status(200).json({ user: mapUserRow(user) });
  } catch (e) {
    console.error("Me route error:", e);
    return res.status(500).json({ error: "Failed to fetch user" });
  }
});

// Profile completion
app.post("/profile", authMiddleware, async (req, res) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }

  const username = parsed.data.username.trim().toLowerCase();
  const { age = null, weightKg = null, heightCm = null } = parsed.data;

  try {
    const updates = { username, age, weight_kg: weightKg, height_cm: heightCm };
    const { data: user, error } = await supabase
      .from("users")
      .update(updates)
      .eq("id", req.user.sub)
      .select("*")
      .single();

    if (error) {
      if (
        error.code === "23505" ||
        String(error.message).includes("users_username_lower_unique")
      ) {
        return res.status(409).json({ error: "Username already taken" });
      }
      console.error("Profile update error:", error);
      return res.status(500).json({ error: "Profile update failed" });
    }

    return res.status(200).json({ user: mapUserRow(user) });
  } catch (e) {
    console.error("Profile error:", e);
    return res.status(500).json({ error: "Profile update failed" });
  }
});

/* ---------- Walk sessions ---------- */

// Save a walk session (duplicate-safe)
app.post("/walks", authMiddleware, async (req, res) => {
  const parsed = walkSchema.safeParse(req.body);
  if (!parsed.success) {
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });
  }
  const { startedAt, endedAt, durationSec, distanceM, steps } = parsed.data;

  try {
    const { data: row, error } = await supabase
      .from("walk_sessions")
      .insert([
        {
          user_id: req.user.sub,
          started_at: new Date(startedAt).toISOString(),
          ended_at: new Date(endedAt).toISOString(),
          duration_sec: durationSec,
          distance_m: distanceM,
          steps,
        },
      ])
      .select("*")
      .single();

    if (error) {
      if (String(error.code) === "23505") {
        // Unique violation on (user_id, started_at) — treat as success
        return res.status(200).json({ ok: true, duplicate: true });
      }
      console.error("Insert walk error:", error);
      return res.status(500).json({ error: "Failed to save walk" });
    }

    return res.status(201).json({ walk: row });
  } catch (e) {
    console.error("Walk insert error:", e);
    return res.status(500).json({ error: "Failed to save walk" });
  }
});

// Totals for "today" by local timezone (tzOffsetMin = minutes east of UTC)
app.get("/walks/today", authMiddleware, async (req, res) => {
  try {
    const offsetMin = Number(req.query.tzOffsetMin ?? 0);
    const now = new Date();

    // Shift now into local time and compute local midnight
    const localNowMs = now.getTime() + offsetMin * 60 * 1000;
    const localMidnight = new Date(localNowMs);
    localMidnight.setUTCHours(0, 0, 0, 0);

    // Convert window back to UTC
    const startUtcMs = localMidnight.getTime() - offsetMin * 60 * 1000;
    const endUtcMs = startUtcMs + 24 * 60 * 60 * 1000;

    const startUtc = new Date(startUtcMs).toISOString();
    const endUtc = new Date(endUtcMs).toISOString();

    const { data: rows, error } = await supabase
      .from("walk_sessions")
      .select("steps, distance_m")
      .eq("user_id", req.user.sub)
      .gte("started_at", startUtc)
      .lt("started_at", endUtc);

    if (error) {
      console.error("Fetch today walks error:", error);
      return res.status(500).json({ error: "Failed to fetch today walks" });
    }

    let stepsToday = 0;
    let distanceM = 0;
    for (const r of rows || []) {
      stepsToday += Number(r.steps || 0);
      distanceM += Number(r.distance_m || 0);
    }

    return res.status(200).json({
      stepsToday,
      distanceM: Number(distanceM.toFixed(2)),
      sessionCount: rows?.length || 0,
      window: { startUtc, endUtc, tzOffsetMin: offsetMin },
    });
  } catch (e) {
    console.error("Today walks error:", e);
    return res.status(500).json({ error: "Failed to fetch today walks" });
  }
});

// List today's sessions by local timezone
app.get("/walks/list", authMiddleware, async (req, res) => {
  try {
    const offsetMin = Number(req.query.tzOffsetMin ?? 0);
    const now = new Date();

    const shiftedNow = new Date(now.getTime() + offsetMin * 60 * 1000);
    shiftedNow.setHours(0, 0, 0, 0);

    const startUtcMs = shiftedNow.getTime() - offsetMin * 60 * 1000;
    const endUtcMs = startUtcMs + 24 * 60 * 60 * 1000;

    const startUtc = new Date(startUtcMs).toISOString();
    const endUtc = new Date(endUtcMs).toISOString();

    const { data: rows, error } = await supabase
      .from("walk_sessions")
      .select("id, started_at, ended_at, duration_sec, distance_m, steps")
      .eq("user_id", req.user.sub)
      .gte("started_at", startUtc)
      .lt("started_at", endUtc)
      .order("started_at", { ascending: false });

    if (error) {
      console.error("Fetch today walk list error:", error);
      return res.status(500).json({ error: "Failed to fetch today walk list" });
    }

    const items = (rows || []).map((r) => ({
      id: r.id,
      startedAt: r.started_at,
      endedAt: r.ended_at,
      durationSec: r.duration_sec,
      distanceM: Number(r.distance_m || 0),
      steps: Number(r.steps || 0),
    }));

    return res.status(200).json({
      items,
      count: items.length,
      window: { startUtc, endUtc, tzOffsetMin: offsetMin },
    });
  } catch (e) {
    console.error("Today walk list error:", e);
    return res.status(500).json({ error: "Failed to fetch today walk list" });
  }
});

// Optional alias
app.get("/walk/list", authMiddleware, async (req, res) => {
  req.url =
    "/walks/list" +
    (req.url.includes("?") ? req.url.slice(req.url.indexOf("?")) : "");
  return app._router.handle(req, res);
});

app.listen(PORT, () => {
  console.log(`✅ Walklet API listening on http://localhost:${PORT}`);
});
