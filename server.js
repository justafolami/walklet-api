import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import { z } from "zod";
import multer from "multer";
import { OAuth2Client } from "google-auth-library";
import { supabase } from "./db.js";
import { authMiddleware, createToken } from "./auth.js";
import { createAndEncryptWallet } from "./wallet.js";
import { Wallet, getBytes, solidityPackedKeccak256, parseUnits } from "ethers";

/* ----------------------------- App bootstrap ----------------------------- */
const app = express();
const PORT = process.env.PORT || 4000;

// Multer (keep images in memory; we never store them)
const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }, // 5MB safety cap
});

// Google client (optional)
const googleClientId = (process.env.GOOGLE_CLIENT_ID || "").trim();
const googleClient = googleClientId ? new OAuth2Client(googleClientId) : null;

// CORS (dev)
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

/* ------------------------------ Dev helpers ------------------------------ */
const devGuard = (req, res, next) => {
  if (process.env.DEV_TOOLS === "1") return next();
  return res
    .status(403)
    .json({ error: "Dev tools disabled. Set DEV_TOOLS=1 in .env" });
};

app.get("/dev/info", (req, res) => {
  return res.status(200).json({ enabled: process.env.DEV_TOOLS === "1" });
});

/* -------------------------- Time window helpers -------------------------- */
// tzOffsetMin: minutes EAST of UTC (e.g., +60 for UTC+1)
function localWindowUtc(tzOffsetMin = 0) {
  const offsetMin = Number(tzOffsetMin || 0);
  const now = new Date();
  const localNowMs = now.getTime() + offsetMin * 60000;
  const localMidnight = new Date(localNowMs);
  localMidnight.setUTCHours(0, 0, 0, 0);
  const startUtcMs = localMidnight.getTime() - offsetMin * 60000;
  const endUtcMs = startUtcMs + 24 * 60 * 60 * 1000;
  return {
    startUtc: new Date(startUtcMs).toISOString(),
    endUtc: new Date(endUtcMs).toISOString(),
  };
}

/* --------------------------------- Schemas -------------------------------- */
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

const goalSchema = z.object({
  dailyStepGoal: z.coerce.number().int().min(0).max(200000),
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

const tzSchema = z.object({
  tzOffsetMin: z.coerce.number().optional().default(0),
});

const mealAnalyzeSchema = z.object({
  mealType: z.enum(["breakfast", "lunch", "dinner"]).optional(),
});

const usdaComputeSchema = z.object({
  items: z.array(
    z.object({
      name: z.string().min(1),
      grams: z.coerce.number().min(0).max(2000),
    })
  ),
});

/* ----------------------------- mapUser helper ---------------------------- */
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
    dailyStepGoal:
      row.daily_step_goal !== null && row.daily_step_goal !== undefined
        ? Number(row.daily_step_goal)
        : null,
    createdAt: row.created_at,
  };
}

/* ---------------------------- USDA + fallback ---------------------------- */
const USDA_API_KEY = (process.env.USDA_API_KEY || "").trim();
const usdaCache = new Map();
const PREFERRED_DATA_TYPES = [
  "Survey (FNDDS)",
  "SR Legacy",
  "Foundation",
  "Branded",
];

async function httpGetJson(url) {
  const r = await fetch(url);
  if (!r.ok) {
    const t = await r.text().catch(() => "");
    throw new Error(`USDA fetch failed (${r.status}): ${t}`);
  }
  return r.json();
}

async function usdaSearchFoodByName(name) {
  const key = `search:${String(name || "")
    .toLowerCase()
    .trim()}`;
  if (usdaCache.has(key)) return usdaCache.get(key);
  const q = encodeURIComponent(name);
  const url = `https://api.nal.usda.gov/fdc/v1/foods/search?query=${q}&pageSize=5&api_key=${USDA_API_KEY}`;
  const json = await httpGetJson(url);
  const foods = Array.isArray(json.foods) ? json.foods : [];
  foods.sort((a, b) => {
    const ai = PREFERRED_DATA_TYPES.indexOf(a.dataType || "zzz");
    const bi = PREFERRED_DATA_TYPES.indexOf(b.dataType || "zzz");
    if (ai !== bi) return ai - bi;
    const as = typeof a.score === "number" ? a.score : 0;
    const bs = typeof b.score === "number" ? b.score : 0;
    return bs - as;
  });
  const best = foods[0] || null;
  usdaCache.set(key, best);
  return best;
}

function extractPer100gFromFood(food) {
  const list = Array.isArray(food.foodNutrients) ? food.foodNutrients : [];
  const byNumber = (numStr) =>
    list.find((n) => {
      if (n.nutrientNumber && String(n.nutrientNumber) === String(numStr))
        return true;
      if (
        n.nutrient &&
        n.nutrient.number &&
        String(n.nutrient.number) === String(numStr)
      )
        return true;
      return false;
    });

  let kcal = 0;
  const n208 = byNumber(208); // kcal
  if (n208) {
    const amt = Number(n208.amount || n208.value || 0);
    const unit = (n208.unitName || n208.nutrient?.unitName || "").toLowerCase();
    kcal = unit === "kj" ? Math.round(amt / 4.184) : amt;
  } else {
    const n1008 = byNumber(1008); // kJ
    if (n1008) {
      const amt = Number(n1008.amount || n1008.value || 0);
      kcal = Math.round(amt / 4.184);
    }
  }

  const protein = Number(byNumber(203)?.amount || byNumber(203)?.value || 0);
  const carbs = Number(byNumber(205)?.amount || byNumber(205)?.value || 0);
  const fat = Number(byNumber(204)?.amount || byNumber(204)?.value || 0);

  if ((food.dataType || "").toLowerCase() === "branded") {
    const label = food.labelNutrients || {};
    const servingSize = Number(food.servingSize || 0);
    const unit = (food.servingSizeUnit || "").toLowerCase();
    if (
      servingSize > 0 &&
      (unit === "g" || unit === "gram" || unit === "grams")
    ) {
      const factor = 100 / servingSize;
      const lcal = Number(label.calories?.value || 0) * factor;
      const lpro = Number(label.protein?.value || 0) * factor;
      const lcar = Number(label.carbohydrates?.value || 0) * factor;
      const lfat = Number(label.fat?.value || 0) * factor;
      return {
        calories: lcal || kcal,
        protein_g: lpro || protein,
        carbs_g: lcar || carbs,
        fat_g: lfat || fat,
      };
    }
  }
  return { calories: kcal, protein_g: protein, carbs_g: carbs, fat_g: fat };
}

async function usdaPer100gByFdcId(fdcId) {
  const key = `per100:${fdcId}`;
  if (usdaCache.has(key)) return usdaCache.get(key);
  const url = `https://api.nal.usda.gov/fdc/v1/food/${fdcId}?api_key=${USDA_API_KEY}`; // singular "food"
  const json = await httpGetJson(url);
  const per100 = extractPer100gFromFood(json);
  usdaCache.set(key, per100);
  return per100;
}

function normalizeFoodName(name) {
  return String(name || "")
    .toLowerCase()
    .trim();
}

const NUTRITION_FALLBACK_PER_100G = {
  apple: { calories: 52, protein_g: 0.3, carbs_g: 14, fat_g: 0.2 },
  banana: { calories: 89, protein_g: 1.1, carbs_g: 23, fat_g: 0.3 },
  orange: { calories: 47, protein_g: 0.9, carbs_g: 12, fat_g: 0.1 },
  rice: { calories: 130, protein_g: 2.4, carbs_g: 28, fat_g: 0.3 },
  "chicken breast": { calories: 165, protein_g: 31, carbs_g: 0, fat_g: 3.6 },
  egg: { calories: 155, protein_g: 13, carbs_g: 1.1, fat_g: 11 },
  beef: { calories: 250, protein_g: 26, carbs_g: 0, fat_g: 15 },
  fish: { calories: 206, protein_g: 22, carbs_g: 0, fat_g: 12 },
  yogurt: { calories: 59, protein_g: 10, carbs_g: 3.6, fat_g: 0.4 },
  milk: { calories: 61, protein_g: 3.2, carbs_g: 4.8, fat_g: 3.3 },
  bread: { calories: 265, protein_g: 9, carbs_g: 49, fat_g: 3.2 },
  fries: { calories: 312, protein_g: 3.4, carbs_g: 41, fat_g: 15 },
  burger: { calories: 254, protein_g: 17, carbs_g: 30, fat_g: 9 },
  sandwich: { calories: 250, protein_g: 12, carbs_g: 28, fat_g: 9 },
  pizza: { calories: 266, protein_g: 11, carbs_g: 33, fat_g: 10 },
  donut: { calories: 452, protein_g: 4.9, carbs_g: 51, fat_g: 25 },
  cake: { calories: 350, protein_g: 4.0, carbs_g: 60, fat_g: 10 },

  bowl: { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
  cup: { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
  fork: { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
  knife: { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
  spoon: { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
  "dining table": { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
};
const DEFAULT_FALLBACK_KEY = "sandwich";

async function getPer100gForName(name) {
  const n = normalizeFoodName(name);
  if (NUTRITION_FALLBACK_PER_100G[n]) {
    return {
      per100: NUTRITION_FALLBACK_PER_100G[n],
      source: "fallback",
      meta: { description: n },
    };
  }
  if (USDA_API_KEY) {
    try {
      const search = await usdaSearchFoodByName(n);
      if (search?.fdcId) {
        const per100 = await usdaPer100gByFdcId(search.fdcId);
        const sum =
          (per100.calories || 0) +
          (per100.protein_g || 0) +
          (per100.carbs_g || 0) +
          (per100.fat_g || 0);
        if (sum > 0)
          return {
            per100,
            source: "usda",
            meta: {
              fdcId: search.fdcId,
              description: search.description,
              dataType: search.dataType,
            },
          };
      }
    } catch {
      // ignore and fallback
    }
  }
  return {
    per100: NUTRITION_FALLBACK_PER_100G[DEFAULT_FALLBACK_KEY],
    source: "fallback",
    meta: { description: DEFAULT_FALLBACK_KEY },
  };
}

/* ----------------------- Reward signer + reward config ----------------------- */
function isValidPk(pk) {
  return typeof pk === "string" && /^0x[0-9a-fA-F]{64}$/.test(pk.trim());
}
const CHAIN_ID = Number(process.env.CHAIN_ID || 84532);
const STPC_CONTRACT_ADDRESS = (process.env.STPC_CONTRACT_ADDRESS || "").trim();
const REWARD_STEPS_PER_STPC = Math.max(
  1,
  Number(process.env.REWARD_STEPS_PER_STPC || 10)
);
let rewardSigner = null;
const rawPk = (process.env.REWARD_SIGNER_PRIVATE_KEY || "").trim();
if (isValidPk(rawPk)) {
  try {
    rewardSigner = new Wallet(rawPk);
    console.log("[rewards] signer loaded:", rewardSigner.address);
  } catch (e) {
    console.warn("[rewards] invalid signer key:", e.message);
  }
} else {
  console.warn(
    "[rewards] REWARD_SIGNER_PRIVATE_KEY missing or invalid; voucher endpoints will be disabled"
  );
}

/* --------------------------------- Routes --------------------------------- */
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

// Auth: signup
app.post("/auth/signup", async (req, res) => {
  const parsed = signupSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

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

    // Create app wallet
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

// Auth: login
app.post("/auth/login", async (req, res) => {
  const parsed = loginSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  try {
    const email = parsed.data.email.trim().toLowerCase();
    const password = parsed.data.password;

    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("email", email)
      .single();
    if (error || !user)
      return res.status(401).json({ error: "Invalid credentials" });
    if (!user.password_hash)
      return res
        .status(401)
        .json({ error: "Use Google Sign-In for this account" });

    const ok = await bcrypt.compare(password, user.password_hash);
    if (!ok) return res.status(401).json({ error: "Invalid credentials" });

    const token = createToken({ id: user.id, email: user.email });
    return res.status(200).json({ token, user: mapUserRow(user) });
  } catch (e) {
    console.error("Login error:", e);
    return res.status(500).json({ error: "Login failed" });
  }
});

// Auth: Google (optional; safe to ignore if no key)
app.post("/auth/google", async (req, res) => {
  try {
    if (!googleClient)
      return res.status(500).json({ error: "Google client not configured" });

    const bodySchema = z.object({ idToken: z.string().min(10) });
    const parsed = bodySchema.safeParse(req.body);
    if (!parsed.success)
      return res.status(400).json({ error: "Invalid idToken" });

    const ticket = await googleClient.verifyIdToken({
      idToken: parsed.data.idToken,
      audience: googleClientId,
    });
    const payload = ticket.getPayload();
    if (!payload)
      return res.status(401).json({ error: "Invalid Google token" });

    const email = String(payload.email || "")
      .toLowerCase()
      .trim();
    const emailVerified = Boolean(payload.email_verified);
    if (!email || !emailVerified)
      return res.status(401).json({ error: "Google email not verified" });

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

// Auth: set password for Google-created accounts
const setPwdSchema = z.object({ newPassword: z.string().min(8) });
app.post("/auth/set-password", authMiddleware, async (req, res) => {
  const parsed = setPwdSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("id,email,password_hash")
      .eq("id", req.user.sub)
      .single();
    if (error || !user)
      return res.status(404).json({ error: "User not found" });
    if (user.password_hash && user.password_hash.length > 0)
      return res
        .status(409)
        .json({ error: "Password already set. Use a password change flow." });

    const passwordHash = await bcrypt.hash(parsed.data.newPassword, 10);
    const { error: upErr } = await supabase
      .from("users")
      .update({ password_hash: passwordHash })
      .eq("id", user.id);
    if (upErr) return res.status(500).json({ error: "Failed to set password" });
    return res.status(200).json({ ok: true });
  } catch (e) {
    console.error("Set password error:", e);
    return res.status(500).json({ error: "Failed to set password" });
  }
});

// Me
app.get("/me", authMiddleware, async (req, res) => {
  try {
    const { data: user, error } = await supabase
      .from("users")
      .select("*")
      .eq("id", req.user.sub)
      .single();
    if (error || !user)
      return res.status(404).json({ error: "User not found" });
    return res.status(200).json({ user: mapUserRow(user) });
  } catch (e) {
    console.error("Me route error:", e);
    return res.status(500).json({ error: "Failed to fetch user" });
  }
});

// Profile
app.post("/profile", authMiddleware, async (req, res) => {
  const parsed = profileSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  const username = parsed.data.username.trim().toLowerCase();
  const { age = null, weightKg = null, heightCm = null } = parsed.data;

  try {
    const { data: user, error } = await supabase
      .from("users")
      .update({ username, age, weight_kg: weightKg, height_cm: heightCm })
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

// Profile: daily goal
app.post("/profile/goal", authMiddleware, async (req, res) => {
  const parsed = goalSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  try {
    const { dailyStepGoal } = parsed.data;
    const { data: user, error } = await supabase
      .from("users")
      .update({ daily_step_goal: dailyStepGoal })
      .eq("id", req.user.sub)
      .select("*")
      .single();
    if (error) {
      console.error("Update goal error:", error);
      return res.status(500).json({ error: "Failed to update goal" });
    }
    return res
      .status(200)
      .json({ ok: true, dailyStepGoal: Number(user.daily_step_goal) });
  } catch (e) {
    console.error("Goal route error:", e);
    return res.status(500).json({ error: "Failed to update goal" });
  }
});

/* ------------------------------- Walk routes ------------------------------ */
app.post("/walks", authMiddleware, async (req, res) => {
  const parsed = walkSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  try {
    const { startedAt, endedAt, durationSec, distanceM, steps } = parsed.data;
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
      if (String(error.code) === "23505")
        return res.status(200).json({ ok: true, duplicate: true });
      console.error("Insert walk error:", error);
      return res.status(500).json({ error: "Failed to save walk" });
    }

    return res.status(201).json({ walk: row });
  } catch (e) {
    console.error("Walk insert error:", e);
    return res.status(500).json({ error: "Failed to save walk" });
  }
});

app.get("/walks/today", authMiddleware, async (req, res) => {
  try {
    const { tzOffsetMin = 0 } = tzSchema.parse(req.query);
    const { startUtc, endUtc } = localWindowUtc(tzOffsetMin);

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
      window: { startUtc, endUtc, tzOffsetMin },
    });
  } catch (e) {
    console.error("Today walks error:", e);
    return res.status(500).json({ error: "Failed to fetch today walks" });
  }
});

app.get("/walks/list", authMiddleware, async (req, res) => {
  try {
    const { tzOffsetMin = 0 } = tzSchema.parse(req.query);
    const { startUtc, endUtc } = localWindowUtc(tzOffsetMin);

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
      window: { startUtc, endUtc, tzOffsetMin },
    });
  } catch (e) {
    console.error("Today walk list error:", e);
    return res.status(500).json({ error: "Failed to fetch today walk list" });
  }
});

// Dev delete a walk
app.delete("/dev/walk/:id", authMiddleware, devGuard, async (req, res) => {
  try {
    const id = String(req.params.id);
    const { data: rows, error: selErr } = await supabase
      .from("walk_sessions")
      .select("id,user_id")
      .eq("id", id)
      .limit(1);
    if (selErr) return res.status(500).json({ error: "Lookup failed" });
    if (!rows || rows.length === 0)
      return res.status(404).json({ error: "Walk not found" });
    if (rows[0].user_id !== req.user.sub)
      return res.status(403).json({ error: "Not your walk" });

    const { error: delErr } = await supabase
      .from("walk_sessions")
      .delete()
      .eq("id", id);
    if (delErr) return res.status(500).json({ error: "Delete failed" });
    return res.status(200).json({ ok: true, id });
  } catch (e) {
    console.error("Dev delete walk error:", e);
    return res.status(500).json({ error: "Delete failed" });
  }
});

/* ------------------------------ Meal routes ------------------------------- */
// Live-only analyze (3/day), stubbed macros for now (no storage of images)
app.post(
  "/meals/analyze",
  authMiddleware,
  upload.single("image"),
  async (req, res) => {
    try {
      const liveHdr = String(req.headers["x-live-capture"] || "").trim();
      if (liveHdr !== "1")
        return res.status(400).json({
          error: "Live capture required (missing X-Live-Capture header)",
        });

      const { tzOffsetMin = 0 } = tzSchema.parse(req.query);
      const { mealType } = mealAnalyzeSchema.parse(req.body);

      if (!req.file)
        return res
          .status(400)
          .json({ error: "Missing image file (field: image)" });

      const capStr = String(req.body.capturedAt || "");
      const capAt = new Date(capStr);
      if (!(capAt instanceof Date) || isNaN(capAt.getTime()))
        return res.status(400).json({ error: "Missing or invalid capturedAt" });
      const ageMs = Math.abs(Date.now() - capAt.getTime());
      if (ageMs > 15_000)
        return res
          .status(400)
          .json({ error: "Capture too old — recapture and try again" });

      const { startUtc, endUtc } = localWindowUtc(tzOffsetMin);

      const { data: todayRows, error: cntErr } = await supabase
        .from("meal_analyses")
        .select("id, meal_type, created_at")
        .eq("user_id", req.user.sub)
        .gte("created_at", startUtc)
        .lt("created_at", endUtc);

      if (cntErr) {
        console.error("Count meals error:", cntErr);
        return res.status(500).json({ error: "Failed to check daily limit" });
      }

      const usedCount = (todayRows || []).length;
      if (usedCount >= 3)
        return res
          .status(429)
          .json({ error: "Daily limit reached (3 analyses per day)" });
      if (mealType) {
        const already = (todayRows || []).some((r) => r.meal_type === mealType);
        if (already)
          return res
            .status(409)
            .json({ error: `You already analyzed ${mealType} today` });
      }

      // Stub "AI" by file size
      const size = req.file.buffer.length || 1;
      const seed = size % 97;
      const protein = 10 + (seed % 31);
      const carbs = 15 + ((seed * 3) % 46);
      const fat = 5 + ((seed * 5) % 31);
      const calories = protein * 4 + carbs * 4 + fat * 9;

      let feedback = "Balanced meal.";
      if (protein >= 25) feedback = "Good source of protein!";
      if (fat >= 25 && protein < 20)
        feedback = "High in fats — consider leaner options.";
      if (carbs >= 45 && fat < 15)
        feedback = "Carb-heavy — pair with protein for balance.";

      const { data: saved, error: insErr } = await supabase
        .from("meal_analyses")
        .insert([
          {
            user_id: req.user.sub,
            meal_type: mealType || null,
            calories,
            protein_g: protein,
            carbs_g: carbs,
            fat_g: fat,
          },
        ])
        .select("*")
        .single();

      if (insErr) {
        console.error("Insert meal analysis error:", insErr);
        return res.status(500).json({ error: "Failed to record analysis" });
      }

      const remaining = Math.max(0, 3 - (usedCount + 1));
      const usedTypes = [
        ...new Set((todayRows || []).map((r) => r.meal_type).filter(Boolean)),
      ];
      if (mealType && !usedTypes.includes(mealType)) usedTypes.push(mealType);

      return res.status(200).json({
        analysis: {
          calories: Math.round(calories),
          protein_g: protein,
          carbs_g: carbs,
          fat_g: fat,
          feedback,
        },
        used: usedTypes,
        remaining,
      });
    } catch (e) {
      console.error("Analyze meal error:", e);
      return res.status(500).json({ error: "Analysis failed" });
    }
  }
);

// USDA compute (safe fallback)
app.post("/meals/compute", authMiddleware, async (req, res) => {
  const parsed = usdaComputeSchema.safeParse(req.body);
  if (!parsed.success)
    return res
      .status(400)
      .json({ error: "Invalid input", details: parsed.error.flatten() });

  try {
    let total = { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 };
    const breakdown = [];

    for (const it of parsed.data.items) {
      const { per100, source, meta } = await getPer100gForName(it.name);
      const factor = (it.grams || 0) / 100;

      const part = {
        name: normalizeFoodName(meta?.description || it.name),
        fdcId: meta?.fdcId || null,
        dataType: meta?.dataType || null,
        grams: it.grams,
        calories: +(per100.calories * factor).toFixed(1),
        protein_g: +(per100.protein_g * factor).toFixed(1),
        carbs_g: +(per100.carbs_g * factor).toFixed(1),
        fat_g: +(per100.fat_g * factor).toFixed(1),
        source,
      };
      breakdown.push(part);
      total.calories += part.calories;
      total.protein_g += part.protein_g;
      total.carbs_g += part.carbs_g;
      total.fat_g += part.fat_g;
    }

    total = {
      calories: Math.round(total.calories),
      protein_g: +total.protein_g.toFixed(1),
      carbs_g: +total.carbs_g.toFixed(1),
      fat_g: +total.fat_g.toFixed(1),
    };

    return res.status(200).json({ total, breakdown });
  } catch (e) {
    console.error("Compute meal (safe) error:", e);
    return res.status(200).json({
      total: { calories: 0, protein_g: 0, carbs_g: 0, fat_g: 0 },
      breakdown: [],
      note: "Fallback empty due to error.",
    });
  }
});

/* ------------------------------- Dev reset ------------------------------- */
const devResetSchema = z.object({
  types: z
    .array(z.enum(["walks", "meals", "profile", "wallet"]))
    .default(["walks", "meals"]),
  scope: z.enum(["today", "all"]).default("today"),
  tzOffsetMin: z.coerce.number().optional().default(0),
});

app.post("/dev/reset", authMiddleware, devGuard, async (req, res) => {
  try {
    const { types, scope, tzOffsetMin } = devResetSchema.parse(req.body);
    let startUtc = null,
      endUtc = null;
    if (scope === "today") {
      const win = localWindowUtc(tzOffsetMin);
      startUtc = win.startUtc;
      endUtc = win.endUtc;
    }
    const userId = req.user.sub;
    const out = {
      walksDeleted: 0,
      mealsDeleted: 0,
      profileCleared: false,
      walletCleared: false,
    };

    // walks
    if (types.includes("walks")) {
      let q = supabase.from("walk_sessions").select("id").eq("user_id", userId);
      if (scope === "today")
        q = q.gte("started_at", startUtc).lt("started_at", endUtc);
      const { data: rows, error } = await q;
      if (error) throw new Error("Fetch walks failed");
      const ids = (rows || []).map((r) => r.id);
      if (ids.length) {
        const { error: dErr } = await supabase
          .from("walk_sessions")
          .delete()
          .in("id", ids);
        if (dErr) throw new Error("Delete walks failed");
        out.walksDeleted = ids.length;
      }
    }

    // meals
    if (types.includes("meals")) {
      let q = supabase.from("meal_analyses").select("id").eq("user_id", userId);
      if (scope === "today")
        q = q.gte("created_at", startUtc).lt("created_at", endUtc);
      const { data: rows, error } = await q;
      if (error) throw new Error("Fetch meals failed");
      const ids = (rows || []).map((r) => r.id);
      if (ids.length) {
        const { error: dErr } = await supabase
          .from("meal_analyses")
          .delete()
          .in("id", ids);
        if (dErr) throw new Error("Delete meals failed");
        out.mealsDeleted = ids.length;
      }
    }

    // profile
    if (types.includes("profile")) {
      const { error: pErr } = await supabase
        .from("users")
        .update({ username: null, age: null, weight_kg: null, height_cm: null })
        .eq("id", userId);
      if (pErr) throw new Error("Profile clear failed");
      out.profileCleared = true;
    }

    // wallet
    if (types.includes("wallet")) {
      const { error: wErr } = await supabase
        .from("users")
        .update({
          wallet_address: null,
          wallet_encrypted: null,
          wallet_iv: null,
          wallet_tag: null,
          wallet_alg: null,
          wallet_created_at: null,
        })
        .eq("id", userId);
      if (wErr) throw new Error("Wallet clear failed");
      out.walletCleared = true;
    }

    return res.status(200).json({ ok: true, scope, tzOffsetMin, ...out });
  } catch (e) {
    console.error("Dev reset error:", e);
    return res.status(400).json({ error: e.message || "Reset failed" });
  }
});

/* ----------------------------- Rewards (dev) ----------------------------- */
// Per-user nonce helper
async function nextNonce(userId) {
  const { data: row, error } = await supabase
    .from("users")
    .select("last_reward_nonce")
    .eq("id", userId)
    .single();
  if (error) throw new Error("Nonce read failed");
  const prev = Number(row?.last_reward_nonce || 0);
  const next = prev + 1;
  const { error: upErr } = await supabase
    .from("users")
    .update({ last_reward_nonce: next })
    .eq("id", userId);
  if (upErr) throw new Error("Nonce update failed");
  return next;
}

// DEV: issue a walk voucher for testing (1 STPC per REWARD_STEPS_PER_STPC steps)
app.post(
  "/dev/rewards/voucher-walk",
  authMiddleware,
  devGuard,
  async (req, res) => {
    try {
      if (!rewardSigner)
        return res.status(500).json({ error: "No reward signer configured" });
      if (!STPC_CONTRACT_ADDRESS)
        return res.status(500).json({ error: "STPC_CONTRACT_ADDRESS missing" });

      const steps = Math.max(0, Number(req.body?.steps || 0));
      if (!Number.isFinite(steps))
        return res.status(400).json({ error: "Invalid steps" });

      const { data: userRow, error } = await supabase
        .from("users")
        .select("wallet_address")
        .eq("id", req.user.sub)
        .single();
      if (error) return res.status(500).json({ error: "User lookup failed" });

      const toAddr = String(
        req.body?.to || userRow?.wallet_address || ""
      ).trim();
      if (!toAddr || !toAddr.startsWith("0x") || toAddr.length !== 42) {
        return res.status(400).json({
          error: "Destination wallet address required (body.to or app wallet)",
        });
      }

      const stpc = Math.floor(steps / REWARD_STEPS_PER_STPC);
      if (stpc <= 0) {
        return res.status(400).json({
          error: `Not enough steps for a reward. Need at least ${REWARD_STEPS_PER_STPC} steps`,
        });
      }

      const amountWei = parseUnits(String(stpc), 18);
      const nonce = await nextNonce(req.user.sub);

      const digest = solidityPackedKeccak256(
        ["string", "address", "uint256", "address", "uint256", "uint256"],
        [
          "WALKLET_REWARD",
          STPC_CONTRACT_ADDRESS,
          CHAIN_ID,
          toAddr,
          amountWei,
          nonce,
        ]
      );

      const signature = await rewardSigner.signMessage(getBytes(digest));

      return res.status(200).json({
        contractAddress: STPC_CONTRACT_ADDRESS,
        chainId: CHAIN_ID,
        user: toAddr,
        amount: amountWei.toString(),
        nonce,
        signature,
        stpc,
        stepsPerStpc: REWARD_STEPS_PER_STPC,
      });
    } catch (e) {
      console.error("Voucher walk error:", e);
      return res.status(500).json({ error: "Failed to create voucher" });
    }
  }
);

/* --------------------------------- Listen -------------------------------- */
app.listen(PORT, () => {
  console.log(`✅ Walklet API listening on http://localhost:${PORT}`);
});
