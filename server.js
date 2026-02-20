// server.js
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");

// Put servicekey.json in same folder, or use an absolute path
const serviceAccount = require("./servicekey.json");

admin.initializeApp({
  credential: admin.credential.cert(serviceAccount),
});

const db = admin.firestore();

const app = express();
app.use(cors());
app.use(express.json());

// -----------------------------
// LOGIN: verify Firebase ID token
// POST /auth/login
// header: Authorization: Bearer <FIREBASE_ID_TOKEN>
// -----------------------------
app.post("/auth/login", async (req, res) => {
  try {
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer (.+)$/);
    if (!match) {
      return res.status(401).json({ ok: false, error: "missing_bearer_token" });
    }

    const idToken = match[1];
    const decoded = await admin.auth().verifyIdToken(idToken);

    return res.json({
      ok: true,
      uid: decoded.uid,
      email: decoded.email || null,
    });
  } catch (err) {
    return res
      .status(401)
      .json({ ok: false, error: "invalid_token", message: err.message });
  }
});

// -----------------------------
// Protected route middleware
// -----------------------------
async function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization || "";
    const match = authHeader.match(/^Bearer (.+)$/);
    if (!match)
      return res
        .status(401)
        .json({ ok: false, error: "missing_bearer_token" });

    const decoded = await admin.auth().verifyIdToken(match[1]);
    req.user = decoded;
    next();
  } catch (e) {
    return res
      .status(401)
      .json({ ok: false, error: "unauthorized", message: e.message });
  }
}

app.get("/me", requireAuth, (req, res) => {
  res.json({ ok: true, uid: req.user.uid, email: req.user.email || null });
});

// -----------------------------
// Helpers
// -----------------------------
function parsePositiveInt(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n <= 0) return null;
  return n;
}

function clampInt(value, min, max) {
  const n = Number(value);
  if (!Number.isInteger(n)) return null;
  if (n < min || n > max) return null;
  return n;
}

function normalizeProjectId(projectId) {
  // allow slug-like ids: letters, numbers, dash, underscore
  if (typeof projectId !== "string") return null;
  const p = projectId.trim();
  if (!p) return null;
  if (p.length > 64) return null;
  if (!/^[a-zA-Z0-9_-]+$/.test(p)) return null;
  return p;
}

function normalizeScreeningId(screeningId) {
  // allow string or number; store as string; no slashes
  if (screeningId == null) return null;
  const s = String(screeningId).trim();
  if (!s) return null;
  if (s.length > 64) return null;
  if (s.includes("/")) return null;
  return s;
}

function screeningIdToNumIfNumeric(screeningIdStr) {
  if (!/^\d+$/.test(screeningIdStr)) return null;
  const n = Number(screeningIdStr);
  if (!Number.isSafeInteger(n) || n <= 0) return null;
  return n;
}

function parseDateToTimestamp(dateValue) {
  // Accept ISO date ("2026-01-30"), full ISO datetime, or epoch ms number
  if (typeof dateValue === "number") {
    const d = new Date(dateValue);
    if (isNaN(d.getTime())) return null;
    return admin.firestore.Timestamp.fromDate(d);
  }
  if (typeof dateValue === "string") {
    const d = new Date(dateValue);
    if (isNaN(d.getTime())) return null;
    return admin.firestore.Timestamp.fromDate(d);
  }
  // Allow Firestore Timestamp passthrough (rare, but safe)
  if (dateValue && typeof dateValue === "object") {
    if (typeof dateValue.toDate === "function") {
      const d = dateValue.toDate();
      if (!isNaN(d.getTime())) return admin.firestore.Timestamp.fromDate(d);
    }
  }
  return null;
}

function tsToMs(ts) {
  if (!ts) return null;
  if (typeof ts === "string") {
    const d = new Date(ts);
    if (!isNaN(d.getTime())) return d.getTime();
    return null;
  }
  if (typeof ts === "number") return ts;
  if (ts instanceof Date) return isNaN(ts.getTime()) ? null : ts.getTime();
  if (typeof ts.toMillis === "function") return ts.toMillis();
  if (typeof ts.seconds === "number") return ts.seconds * 1000;
  if (typeof ts._seconds === "number") return ts._seconds * 1000;
  return null;
}

function msToTimestamp(ms) {
  const d = new Date(ms);
  return admin.firestore.Timestamp.fromDate(d);
}

function projectRef(projectId) {
  return db.collection("redcap_data").doc(projectId);
}

function screeningRef(projectId, screeningId) {
  return projectRef(projectId).collection("screenings").doc(screeningId);
}

// -------- Project Steps Config (NEW) --------
const DEFAULT_MAX_STEPS = 50; // safety limit

function makeDefaultStepOrder(stepCount) {
  const n = clampInt(stepCount, 1, DEFAULT_MAX_STEPS) || 10;
  return Array.from({ length: n }, (_, i) => String(i + 1));
}

function sanitizeStepAliases(stepAliases, allowedStepKeys) {
  // Expect: { "1": "Consent", "2": "Screened", ... }
  if (stepAliases == null) return null;
  if (typeof stepAliases !== "object" || Array.isArray(stepAliases)) return null;

  const allowed = new Set((allowedStepKeys || []).map(String));
  const out = {};
  for (const [k, v] of Object.entries(stepAliases)) {
    const key = String(k);
    if (!allowed.has(key)) continue;
    if (v == null) continue;
    const label = String(v).trim();
    if (!label) continue;
    if (label.length > 48) continue;
    out[key] = label;
  }
  return out;
}

function sanitizeStepRules(stepRules, allowedStepKeys) {
  // stepRules: { "1": { canSkip, minWaitDays, maxDaysToReport }, ... }
  if (stepRules == null) return null;
  if (typeof stepRules !== "object" || Array.isArray(stepRules)) return null;

  const allowed = new Set((allowedStepKeys || []).map(String));
  const out = {};
  for (const [k, rule] of Object.entries(stepRules)) {
    const key = String(k);
    if (!allowed.has(key)) continue;
    if (!rule || typeof rule !== "object" || Array.isArray(rule)) continue;

    const canSkip = !!rule.canSkip;

    const minWaitDays =
      rule.minWaitDays == null ? 0 : clampInt(rule.minWaitDays, 0, 3650) ?? 0;

    // deadline (auto-withdraw) days after previous completed step for THIS step
    // null/undefined => no deadline
    let maxDaysToReport = null;
    if (rule.maxDaysToReport != null && rule.maxDaysToReport !== "") {
      const md = clampInt(rule.maxDaysToReport, 1, 3650);
      if (md != null) maxDaysToReport = md;
    }

    out[key] = { canSkip, minWaitDays, maxDaysToReport };
  }
  return out;
}

function sanitizeStepOrder(stepOrder) {
  if (!Array.isArray(stepOrder)) return null;
  const keys = stepOrder.map((x) => String(x).trim()).filter(Boolean);
  if (!keys.length) return null;
  if (keys.length > DEFAULT_MAX_STEPS) return null;

  const seen = new Set();
  for (const k of keys) {
    if (!/^\d+$/.test(k)) return null; // numeric keys only for now (simple + compatible)
    if (seen.has(k)) return null;
    seen.add(k);
  }
  return keys;
}

function getStepTsFromScreening(screeningData, stepKey) {
  const obj = screeningData?.steps?.[String(stepKey)];
  if (!obj) return null;
  // stored as { date: Timestamp }
  const ts = obj?.date ?? obj;
  return ts || null;
}

function isWithdrawnScreening(screeningData) {
  return !!screeningData?.withdrewAt;
}
// -----------------------------
// Analytics helpers (NEW)
// -----------------------------

const DAY_MS = 24 * 60 * 60 * 1000;
const WEEK_MS = 7 * DAY_MS;

function pad2(n) {
  return String(n).padStart(2, "0");
}

function toISODateUTC(ms) {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${pad2(d.getUTCMonth() + 1)}-${pad2(d.getUTCDate())}`;
}

// date-only UTC midnight for a given ms
function utcMidnightMs(ms) {
  const d = new Date(ms);
  return Date.UTC(d.getUTCFullYear(), d.getUTCMonth(), d.getUTCDate());
}

// Monday week start at 00:00 UTC
function mondayWeekStartMs(ms) {
  const mid = utcMidnightMs(ms);
  const d = new Date(mid);
  const day = d.getUTCDay(); // 0=Sun,1=Mon,...6=Sat
  const daysSinceMon = (day + 6) % 7; // Mon->0, Tue->1, ..., Sun->6
  return mid - daysSinceMon * DAY_MS;
}

function mondayWeekStartStrFromMs(ms) {
  return toISODateUTC(mondayWeekStartMs(ms));
}

function weeksDiffFromAnchor(anchorStartStr, weekStartStr) {
  // both are YYYY-MM-DD Monday
  const a = Date.parse(`${anchorStartStr}T00:00:00.000Z`);
  const w = Date.parse(`${weekStartStr}T00:00:00.000Z`);
  return Math.round((w - a) / WEEK_MS);
}

function addWeeksStr(weekStartStr, weeks) {
  const base = Date.parse(`${weekStartStr}T00:00:00.000Z`);
  return toISODateUTC(base + weeks * WEEK_MS);
}

function clampFloat(x, min, max) {
  if (x == null || Number.isNaN(Number(x))) return null;
  const n = Number(x);
  return Math.max(min, Math.min(max, n));
}

function safeNumber(x, fallback = 0) {
  const n = Number(x);
  return Number.isFinite(n) ? n : fallback;
}

function getAnalyticsConfig(projectCfg) {
  const a = projectCfg?.analytics && typeof projectCfg.analytics === "object" ? projectCfg.analytics : {};
  return {
    anchorStart: typeof a.anchorStart === "string" ? a.anchorStart : null,
    // optional Excel-like override: { "3": 3, "4": 6, ... } (week_index values)
    startOverrides: (a.startOverrides && typeof a.startOverrides === "object") ? a.startOverrides : {},
    // optional per-step intervals (days from previous step): { "2": 5, "3": 10, ... }
    transitionIntervalsDays: (a.transitionIntervalsDays && typeof a.transitionIntervalsDays === "object")
      ? a.transitionIntervalsDays
      : {},
    // optional targets
    studyTargets: (a.studyTargets && typeof a.studyTargets === "object") ? a.studyTargets : {},
    weeksRemaining: a.weeksRemaining != null ? clampInt(a.weeksRemaining, 1, 5000) : 70,
    // if you truly need Excel’s odd roster rule, set true (not recommended)
    excelRosterMode: !!a.excelRosterMode,
  };
}

// Default interval behavior that matches your SQL hardcodes:
// step2=5, step3=10, step4=15, ...
function defaultDaysFromPrevByIndex(stepIndex /* 0-based in stepOrder */) {
  // stepIndex=1 => step2 => 5 days
  return stepIndex <= 0 ? 0 : stepIndex * 5;
}

function computeDaysFromPrev(stepKey, stepIndex, analyticsCfg) {
  const raw = analyticsCfg?.transitionIntervalsDays?.[String(stepKey)];
  const n = clampInt(raw, 0, 3650);
  if (n != null) return n;
  return defaultDaysFromPrevByIndex(stepIndex);
}

function getMsFromStepObj(stepObj) {
  // stepObj could be { date: Timestamp } or Timestamp-ish
  const ts = stepObj?.date ?? stepObj;
  return tsToMs(ts);
}

// Extract per-screening max date per step + withdrew
function buildPatientMaxRows(screenings, stepOrder) {
  // returns Map(recordId => { recordId, withdrewMs, stepMsByKey })
  const out = new Map();

  for (const s of screenings) {
    const recordId = String(s.screeningId || s.id || "").trim();
    if (!recordId) continue;

    const cur = out.get(recordId) || { recordId, withdrewMs: null, stepMsByKey: {} };

    // withdrew
    const wms = tsToMs(s.withdrewAt);
    if (wms != null) cur.withdrewMs = cur.withdrewMs == null ? wms : Math.max(cur.withdrewMs, wms);

    // steps
    const steps = s.steps || {};
    for (const k of stepOrder) {
      const ms = getMsFromStepObj(steps[String(k)]);
      if (ms == null) continue;

      const prev = cur.stepMsByKey[String(k)];
      cur.stepMsByKey[String(k)] = prev == null ? ms : Math.max(prev, ms);
    }

    out.set(recordId, cur);
  }

  return out;
}

// Determine anchorStart from projectCfg.analytics.anchorStart OR earliest step1 date (Monday)
async function getOrComputeAnchorStart(pid, projectCfg, screenings) {
  const analyticsCfg = getAnalyticsConfig(projectCfg);

  if (analyticsCfg.anchorStart) return analyticsCfg.anchorStart;

  const stepOrder = projectCfg.stepOrder || [];
  const firstStepKey = stepOrder[0];
  if (!firstStepKey) return mondayWeekStartStrFromMs(Date.now()); // fallback

  let earliestMs = null;
  for (const s of screenings) {
    const ms = getMsFromStepObj(s?.steps?.[String(firstStepKey)]);
    if (ms == null) continue;
    earliestMs = earliestMs == null ? ms : Math.min(earliestMs, ms);
  }

  const anchor = earliestMs != null ? mondayWeekStartStrFromMs(earliestMs) : mondayWeekStartStrFromMs(Date.now());

  // best-effort persist (not in a transaction)
  try {
    await projectRef(pid).set(
      {
        analytics: { anchorStart: anchor },
        updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  } catch (e) {
    // ignore persistence failures; still return computed anchor
  }

  return anchor;
}

// Build count-by-week series per step (Monday weeks), with filled zeros
function buildWeeklyCountSeries(stepOrder, anchorStartStr, screenings) {
  // countsByStepKey: Map(stepKey -> Map(weekStartStr -> Set(recordIds)))
  const countsByStepKey = new Map();
  for (const k of stepOrder) countsByStepKey.set(String(k), new Map());

  // collect distinct record ids per week per step
  for (const s of screenings) {
    const recordId = String(s.screeningId || s.id || "").trim();
    if (!recordId) continue;

    const steps = s.steps || {};
    for (const stepKey of stepOrder) {
      const ms = getMsFromStepObj(steps[String(stepKey)]);
      if (ms == null) continue;
      const wk = mondayWeekStartStrFromMs(ms);

      const stepMap = countsByStepKey.get(String(stepKey));
      if (!stepMap) continue;

      let set = stepMap.get(wk);
      if (!set) {
        set = new Set();
        stepMap.set(wk, set);
      }
      set.add(recordId);
    }
  }

  // determine global max week to align series length across steps
  let globalMaxWeekMs = Date.parse(`${anchorStartStr}T00:00:00.000Z`);
  let globalMinWeekMs = globalMaxWeekMs;

  for (const [stepKey, m] of countsByStepKey.entries()) {
    for (const wk of m.keys()) {
      const ms = Date.parse(`${wk}T00:00:00.000Z`);
      if (!Number.isFinite(ms)) continue;
      globalMinWeekMs = Math.min(globalMinWeekMs, ms);
      globalMaxWeekMs = Math.max(globalMaxWeekMs, ms);
    }
  }

  // If no events, keep small range
  if (!Number.isFinite(globalMinWeekMs) || !Number.isFinite(globalMaxWeekMs)) {
    globalMinWeekMs = Date.parse(`${anchorStartStr}T00:00:00.000Z`);
    globalMaxWeekMs = globalMinWeekMs;
  }

  // Build per-step filled series from globalMin..globalMax (weekly)
  const globalMinStr = toISODateUTC(globalMinWeekMs);
  const globalMaxStr = toISODateUTC(globalMaxWeekMs);
  const totalWeeks = weeksDiffFromAnchor(globalMinStr, globalMaxStr) + 1;

  const resultByStep = {};

  for (const stepKey of stepOrder) {
    const stepMap = countsByStepKey.get(String(stepKey)) || new Map();

    // series array
    const rows = [];
    for (let i = 0; i < totalWeeks; i++) {
      const weekStart = addWeeksStr(globalMinStr, i);
      const count = stepMap.get(weekStart)?.size || 0;

      const weekIndex = weeksDiffFromAnchor(anchorStartStr, weekStart) + 1;

      rows.push({
        step_number: String(stepKey),
        week_index: weekIndex,
        week_start: weekStart,
        count_week: count,
      });
    }

    resultByStep[String(stepKey)] = rows;
  }

  return {
    globalMinWeekStart: globalMinStr,
    globalMaxWeekStart: globalMaxStr,
    byStep: resultByStep,
  };
}

function addPoissonControlStatsPerStep(countSeriesRows, analyticsCfg, anchorStartStr) {
  // Determine observed bounds + effective start + mean/ucl/lcl over display window
  const rows = countSeriesRows;

  let firstNonZero = null;
  let lastObserved = null;

  for (const r of rows) {
    if (r.count_week > 0) {
      firstNonZero = firstNonZero == null ? r.week_index : Math.min(firstNonZero, r.week_index);
      lastObserved = lastObserved == null ? r.week_index : Math.max(lastObserved, r.week_index);
    }
  }

  // if no events at all, keep null stats
  if (firstNonZero == null || lastObserved == null) {
    return rows.map((r) => ({
      ...r,
      observed_first_nonzero_week_index: null,
      observed_last_week_index: null,
      effective_start_index: null,
      shifted_week: null,
      in_display_window: false,
      mean: null,
      sample_stdev: null,
      sigma: 3,
      ucl: null,
      lcl: null,
      flag_outside_3sigma_poisson: false,
    }));
  }

  const stepKey = rows[0]?.step_number;
  const override = analyticsCfg?.startOverrides?.[String(stepKey)];
  const overrideInt = clampInt(override, 1, 1000000);

  const effectiveStart = overrideInt != null ? Math.max(firstNonZero, overrideInt) : firstNonZero;

  // compute mean over [effectiveStart..lastObserved] including zeros
  let sum = 0;
  let n = 0;
  for (const r of rows) {
    if (r.week_index >= effectiveStart && r.week_index <= lastObserved) {
      sum += r.count_week;
      n += 1;
    }
  }
  const mean = n > 0 ? sum / n : 0;
  const sigma = 3;
  const stdev = Math.sqrt(mean); // Poisson approx
  const ucl = mean + sigma * Math.sqrt(mean);
  const lcl = Math.max(mean - sigma * Math.sqrt(mean), 0);

  return rows.map((r) => {
    const inWindow = r.week_index >= effectiveStart && r.week_index <= lastObserved;
    const shifted = inWindow ? (r.week_index - effectiveStart + 1) : null;

    const flag = mean != null
      ? (r.count_week > ucl || r.count_week < lcl)
      : false;

    return {
      ...r,
      observed_first_nonzero_week_index: firstNonZero,
      observed_last_week_index: lastObserved,
      effective_start_index: effectiveStart,
      shifted_week: shifted,
      in_display_window: inWindow,
      mean,
      sample_stdev: stdev,
      sigma,
      ucl,
      lcl,
      flag_outside_3sigma_poisson: flag,
    };
  });
}

// Build percent-possible series (per step >=2 by default), aligned to Monday weeks
function buildPercentPossibleSeries(stepOrder, anchorStartStr, screenings, projectCfg, asOfMs) {
  const analyticsCfg = getAnalyticsConfig(projectCfg);
  const asOf = asOfMs != null ? asOfMs : Date.now();

  // counts by week from real completions (same as count chart)
  const weeklyCounts = buildWeeklyCountSeries(stepOrder, anchorStartStr, screenings);

  // patient-level max per step
  const patientMap = buildPatientMaxRows(screenings, stepOrder);

  // Build availability windows for each (stepIndex>=1)
  // availabilityByStepKey: Map(stepKey -> Array<{recordId,startMs,endMs}>)
  const availabilityByStepKey = new Map();
  for (let i = 1; i < stepOrder.length; i++) {
    availabilityByStepKey.set(String(stepOrder[i]), []);
  }

  for (const p of patientMap.values()) {
    const withdrewMs = p.withdrewMs;

    for (let i = 1; i < stepOrder.length; i++) {
      const priorKey = String(stepOrder[i - 1]);
      const currKey = String(stepOrder[i]);

      const priorMs = p.stepMsByKey[priorKey] ?? null;
      const currMs = p.stepMsByKey[currKey] ?? null;

      if (priorMs == null) continue;

      // Excel roster mode (optional): require curr or withdrew to exist (NOT recommended)
      if (analyticsCfg.excelRosterMode) {
        if (currMs == null && withdrewMs == null) continue;
      }

      const daysFromPrev = computeDaysFromPrev(currKey, i, analyticsCfg);
      const startAvailableMs = utcMidnightMs(priorMs) + daysFromPrev * DAY_MS;

      // endAvailable = min(curr, withdrew, asOf)
      let endAvailableMs = utcMidnightMs(asOf);
      if (currMs != null) endAvailableMs = Math.min(endAvailableMs, utcMidnightMs(currMs));
      if (withdrewMs != null) endAvailableMs = Math.min(endAvailableMs, utcMidnightMs(withdrewMs));

      if (endAvailableMs < startAvailableMs) continue;

      availabilityByStepKey.get(currKey).push({
        recordId: p.recordId,
        startMs: startAvailableMs,
        endMs: endAvailableMs,
      });
    }
  }

  // For each step >=2 and each week row, compute possible overlap
  const byStep = {};

  for (let i = 1; i < stepOrder.length; i++) {
    const stepKey = String(stepOrder[i]);
    const rows = weeklyCounts.byStep[stepKey] || [];
    const avail = availabilityByStepKey.get(stepKey) || [];

    const out = rows.map((r) => {
      const wkStartMs = Date.parse(`${r.week_start}T00:00:00.000Z`);
      const wkEndMs = wkStartMs + 6 * DAY_MS;

      const eligible = new Set();
      for (const a of avail) {
        if (a.startMs <= wkEndMs && a.endMs >= wkStartMs) eligible.add(a.recordId);
      }

      const possible = eligible.size;
      const pct = possible > 0 ? r.count_week / possible : 0;

      return {
        step_number: stepKey,
        week_index: r.week_index,
        week_start: r.week_start,
        week_end: toISODateUTC(wkEndMs),
        count_week: r.count_week,
        possible,
        pct_possible: pct,
      };
    });

    byStep[stepKey] = out;
  }

  return { byStep };
}

// Percent control chart bounds using last-5-zero trim idea (like your SQL) but with sane N
function addPercentControlStats(pctRows, sigma = 3) {
  const rows = pctRows;

  // 1) min/max week_index where count_week > 0
  let minNonZero = null;
  let maxNonZero = null;
  for (const r of rows) {
    if (r.count_week > 0) {
      minNonZero = minNonZero == null ? r.week_index : Math.min(minNonZero, r.week_index);
      maxNonZero = maxNonZero == null ? r.week_index : Math.max(maxNonZero, r.week_index);
    }
  }
  if (minNonZero == null || maxNonZero == null) {
    return rows.map((r) => ({
      ...r,
      min_nonzero_week: null,
      max_nonzero_week: null,
      last_5_start: null,
      first_zero_index_in_last5: null,
      trim_at: null,
      mean: null,
      sample_stdev: null,
      ucl: null,
      lcl: null,
    }));
  }

  const last5Start = Math.max(maxNonZero - 4, minNonZero);

  let firstZeroInLast5 = null;
  for (const r of rows) {
    if (r.week_index >= last5Start && r.week_index <= maxNonZero && r.count_week === 0) {
      firstZeroInLast5 = firstZeroInLast5 == null ? r.week_index : Math.min(firstZeroInLast5, r.week_index);
    }
  }

  const trimAt = firstZeroInLast5 != null ? (firstZeroInLast5 - 1) : maxNonZero;

  // compute mean over [minNonZero..trimAt]
  let sum = 0;
  let n = 0;
  for (const r of rows) {
    if (r.week_index >= minNonZero && r.week_index <= trimAt) {
      sum += r.pct_possible;
      n += 1;
    }
  }
  const mean = n > 0 ? sum / n : 0;

  // proportion stdev (binomial-ish): sqrt(p(1-p)/N)
  const stdev = n > 0 ? Math.sqrt(mean * (1 - mean) / n) : null;
  const ucl = stdev != null ? Math.min(1, mean + sigma * stdev) : null;
  const lcl = stdev != null ? Math.max(0, mean - sigma * stdev) : null;

  return rows
    .filter((r) => r.week_index <= trimAt)
    .map((r) => ({
      ...r,
      min_nonzero_week: minNonZero,
      max_nonzero_week: maxNonZero,
      last_5_start: last5Start,
      first_zero_index_in_last5: firstZeroInLast5,
      trim_at: trimAt,
      mean,
      sample_stdev: stdev,
      ucl,
      lcl,
    }));
}

function computeDashboardSummary(stepOrder, countControlByStep, pctControlByStep, projectCfg) {
  const analyticsCfg = getAnalyticsConfig(projectCfg);

  // totals_to_date per step
  const totals = {};
  const lastWeekCount = {};
  const lastWeekIndex = {};

  for (const stepKey of stepOrder) {
    const rows = countControlByStep[String(stepKey)] || [];
    let total = 0;

    let lw = null;
    let lwc = 0;
    for (const r of rows) {
      total += r.count_week;
      if (lw == null || r.week_index > lw) {
        lw = r.week_index;
        lwc = r.count_week;
      }
    }

    totals[String(stepKey)] = total;
    lastWeekIndex[String(stepKey)] = lw;
    lastWeekCount[String(stepKey)] = lwc;
  }

  // last_row_rate from pct control chart (trimmed)
  const lastWeekRate = {};
  for (const stepKey of stepOrder) {
    const rows = pctControlByStep[String(stepKey)] || [];
    if (!rows.length) {
      lastWeekRate[String(stepKey)] = null;
      continue;
    }
    const last = rows[rows.length - 1];
    lastWeekRate[String(stepKey)] = safeNumber(last.pct_possible, 0);
  }

  const weeksRemaining = analyticsCfg.weeksRemaining || 70;

  const summary = stepOrder.map((stepKey) => {
    const targetRaw = analyticsCfg.studyTargets?.[String(stepKey)];
    const studyTarget = clampInt(targetRaw, 0, 1000000000) ?? 0;

    const totalToDate = totals[String(stepKey)] || 0;
    const toReach = studyTarget - totalToDate;
    const weeklyTarget = Math.round((toReach) / weeksRemaining);

    const lwCount = lastWeekCount[String(stepKey)] || 0;

    const countStatus =
      weeklyTarget > 0 ? (lwCount / weeklyTarget) : (-lwCount + 1);

    // overall_rate = total(step)/total(prev step)
    // (like your SQL; if prev is 0 => null)
    let overallRate = null;
    const idx = stepOrder.indexOf(String(stepKey));
    if (idx > 0) {
      const prevTotal = totals[String(stepOrder[idx - 1])] || 0;
      overallRate = prevTotal > 0 ? (totalToDate / prevTotal) : null;
    }

    const lwr = idx === 0 ? null : (lastWeekRate[String(stepKey)] ?? null);

    return {
      Step: String(stepKey),
      Study_Target: studyTarget,
      Total_to_Date: totalToDate,
      To_Reach_Target: toReach,
      Weekly_Target: weeklyTarget,
      Last_Week_Count: lwCount,
      Count_Status: countStatus,
      Overall_Rate: overallRate,
      Last_Week_Rate: lwr,
    };
  });

  // Funnel values: totals_to_date and pct vs step1
  const base = totals[String(stepOrder[0])] || 0;
  const funnel = stepOrder.map((stepKey) => {
    const val = totals[String(stepKey)] || 0;
    const pct = base > 0 ? (val / base) : 0;
    return { step: String(stepKey), total: val, pct_of_step1: pct };
  });

  return { summary, funnel };
}
// Ensure project exists (create minimal if missing) + ensure step config exists
async function ensureProjectExistsTx(tx, projectDocRef, projectId, user) {
  const snap = await tx.get(projectDocRef);
  const now = admin.firestore.FieldValue.serverTimestamp();

  if (!snap.exists) {
    const stepOrder = makeDefaultStepOrder(10);
    const stepRules = {};
    for (const k of stepOrder) {
      stepRules[k] = { canSkip: false, minWaitDays: 0, maxDaysToReport: null };
    }

    tx.set(
      projectDocRef,
      {
        projectId,
        name: projectId,
        stepCount: stepOrder.length,
        stepOrder,
        stepAliases: {},
        stepRules,
        createdAt: now,
        updatedAt: now,
        createdBy: user?.uid || null,
      },
      { merge: true }
    );
  } else {
    // ensure existing doc has stepOrder / stepCount
    const data = snap.data() || {};
    const nowPatch = { updatedAt: now };

    let stepOrder = Array.isArray(data.stepOrder)
      ? sanitizeStepOrder(data.stepOrder)
      : null;

    // fallback to legacy: stepCount or default 10
    if (!stepOrder) {
      const sc = clampInt(data.stepCount, 1, DEFAULT_MAX_STEPS) || 10;
      stepOrder = makeDefaultStepOrder(sc);
      nowPatch.stepOrder = stepOrder;
    }

    const stepCount = stepOrder.length;
    if (data.stepCount !== stepCount) nowPatch.stepCount = stepCount;

    if (data.stepAliases == null) nowPatch.stepAliases = {};
    if (data.stepRules == null) {
      const stepRules = {};
      for (const k of stepOrder) {
        stepRules[k] = { canSkip: false, minWaitDays: 0, maxDaysToReport: null };
      }
      nowPatch.stepRules = stepRules;
    }

    // Only write if needed
    if (Object.keys(nowPatch).length > 1) {
      tx.set(projectDocRef, nowPatch, { merge: true });
    }
  }
}

async function getProjectConfigOrThrow(pid) {
  const snap = await projectRef(pid).get();
  if (!snap.exists) {
    const err = new Error("Project not found");
    err.statusCode = 404;
    throw err;
  }
  const cfg = snap.data() || {};

  const stepOrder = sanitizeStepOrder(cfg.stepOrder) || makeDefaultStepOrder(cfg.stepCount || 10);
  const stepCount = stepOrder.length;

  const stepRules = sanitizeStepRules(cfg.stepRules || {}, stepOrder) || {};
  // fill missing rules with defaults
  for (const k of stepOrder) {
    if (!stepRules[k]) stepRules[k] = { canSkip: false, minWaitDays: 0, maxDaysToReport: null };
  }

  const stepAliases = sanitizeStepAliases(cfg.stepAliases || {}, stepOrder) || {};

  return {
    id: snap.id,
    ...cfg,
    stepOrder,
    stepCount,
    stepRules,
    stepAliases,
  };
}

// Require all required (non-skippable) steps complete across all ACTIVE screenings
async function ensureAllRequiredStepsComplete(pid, projectCfg, limitScan = 5000) {
  const col = projectRef(pid).collection("screenings");
  const snap = await col.limit(limitScan).get();
  const missing = [];
  for (const doc of snap.docs) {
    const d = doc.data() || {};
    if (isWithdrawnScreening(d)) continue;

    for (const stepKey of projectCfg.stepOrder) {
      const rule = projectCfg.stepRules?.[stepKey] || {};
      if (rule.canSkip) continue; // not required

      const ts = getStepTsFromScreening(d, stepKey);
      const ms = tsToMs(ts);
      if (!ms) {
        missing.push({ screeningId: d.screeningId || doc.id, stepKey });
        if (missing.length >= 25) break;
      }
    }
    if (missing.length >= 25) break;
  }

  if (missing.length) {
    const err = new Error(
      `Cannot modify steps until all required steps are filled. Example missing: ` +
      missing.map((m) => `${m.screeningId} (step ${m.stepKey})`).join(", ")
    );
    err.statusCode = 409;
    err.code = "steps_incomplete";
    err.missing = missing;
    throw err;
  }
}

// Auto-withdraw evaluation: find next required step missing and deadline exceeded
function computeAutoWithdrawNowIfOverdue(screeningData, projectCfg, nowMs) {
  if (!screeningData || isWithdrawnScreening(screeningData)) return null;

  // Find last completed step date by walking order and taking latest found
  // (dates are validated monotonic by save-step rules, so "last found" is last completed)
  let lastCompletedMs = null;

  // Walk through steps and record ms where present
  for (const stepKey of projectCfg.stepOrder) {
    const ms = tsToMs(getStepTsFromScreening(screeningData, stepKey));
    if (ms != null) lastCompletedMs = ms;
  }

  if (lastCompletedMs == null) return null; // nothing started -> no auto-withdraw

  // Find the next REQUIRED step that is missing (skippable steps are ignored)
  for (const stepKey of projectCfg.stepOrder) {
    const rule = projectCfg.stepRules?.[stepKey] || {};
    const has = tsToMs(getStepTsFromScreening(screeningData, stepKey)) != null;
    if (has) continue;

    if (rule.canSkip) {
      // can be filled later via propagation; don't withdraw for missing this
      continue;
    }

    const maxDays = rule.maxDaysToReport;
    if (maxDays == null) return null; // no deadline for this required step

    const dueMs = lastCompletedMs + maxDays * 24 * 60 * 60 * 1000;
    if (nowMs > dueMs) {
      return {
        shouldWithdraw: true,
        dueMs,
        overdueByDays: Math.floor((nowMs - dueMs) / (24 * 60 * 60 * 1000)),
        missingRequiredStepKey: stepKey,
      };
    }
    return null;
  }

  return null;
}

// -----------------------------
// Batched delete helpers (Firestore batch limit is 500)
// -----------------------------
async function deleteCollectionDocs(collectionRef, batchSize = 400) {
  while (true) {
    const snap = await collectionRef.limit(batchSize).get();
    if (snap.empty) break;

    const batch = db.batch();
    snap.docs.forEach((doc) => batch.delete(doc.ref));
    await batch.commit();
  }
}

async function deleteProjectScreenings(projectId, batchSize = 400) {
  const col = projectRef(projectId).collection("screenings");
  await deleteCollectionDocs(col, batchSize);
}

// -----------------------------
// PROJECTS
// Collection: redcap_data (projects)
// Screenings under: redcap_data/{projectId}/screenings/{screeningId}
// -----------------------------

// LIST projects
// GET /projects?limit=200
app.get("/projects", requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parsePositiveInt(req.query.limit) || 200, 1000);
    const qs = await db
      .collection("redcap_data")
      .orderBy("projectId", "asc")
      .limit(limit)
      .get();
    const rows = qs.docs.map((d) => ({ id: d.id, ...d.data() }));
    return res.json({ ok: true, count: rows.length, data: rows });
  } catch (err) {
    console.error("LIST projects failed:", {
      message: err.message,
      code: err.code,
      stack: err.stack,
    });
    return res.status(500).json({
      ok: false,
      error: "projects_list_failed",
      message: err.message,
    });
  }
});

// CREATE project
// POST /projects
// body: { projectId, name?, stepCount?, stepAliases?, stepRules? }
app.post("/projects", requireAuth, async (req, res) => {
  try {
    const { projectId, name, stepCount, stepAliases, stepRules } = req.body || {};
    const pid = normalizeProjectId(projectId);
    if (!pid) {
      return res.status(400).json({
        ok: false,
        message:
          "projectId is required and must match /^[a-zA-Z0-9_-]+$/ (max 64 chars)",
      });
    }

    const stepsN = clampInt(stepCount, 1, DEFAULT_MAX_STEPS) || 10;
    const stepOrder = makeDefaultStepOrder(stepsN);
    const aliases = sanitizeStepAliases(stepAliases, stepOrder) || {};
    const rules = sanitizeStepRules(stepRules || {}, stepOrder) || {};
    for (const k of stepOrder) {
      if (!rules[k])
        rules[k] = { canSkip: false, minWaitDays: 0, maxDaysToReport: null };
    }

    const projectDocRef = projectRef(pid);
    const now = admin.firestore.FieldValue.serverTimestamp();

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(projectDocRef);
      if (snap.exists) {
        const err = new Error("Project already exists");
        err.statusCode = 409;
        throw err;
      }
      tx.create(projectDocRef, {
        projectId: pid,
        name: (name && String(name).trim()) || pid,

        stepCount: stepOrder.length,
        stepOrder,
        stepAliases: aliases,
        stepRules: rules,

        createdAt: now,
        updatedAt: now,
        createdBy: req.user.uid,
      });
    });

    return res
      .status(201)
      .json({ ok: true, projectId: pid, message: "Project created" });
  } catch (err) {
    const status = err.statusCode || 400;
    return res.status(status).json({
      ok: false,
      error: "project_create_failed",
      message: err.message,
    });
  }
});

// GET project config
// GET /projects/:projectId
app.get("/projects/:projectId", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    // ensure step config exists even for older projects
    const pRef = projectRef(pid);
    await db.runTransaction(async (tx) => {
      await ensureProjectExistsTx(tx, pRef, pid, req.user);
    });

    const cfg = await getProjectConfigOrThrow(pid);
    return res.json({ ok: true, data: cfg });
  } catch (err) {
    const status = err.statusCode || 500;
    return res
      .status(status)
      .json({ ok: false, error: "project_get_failed", message: err.message });
  }
});

// UPDATE/UPSERT project config (name, aliases, rules, order)
// PUT /projects/:projectId
// body: { name?, stepAliases?, stepRules?, stepOrder? }
app.put("/projects/:projectId", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const { name, stepAliases, stepRules, stepOrder } = req.body || {};
    const now = admin.firestore.FieldValue.serverTimestamp();
    const projectDocRef = projectRef(pid);

    await db.runTransaction(async (tx) => {
      await ensureProjectExistsTx(tx, projectDocRef, pid, req.user);

      const snap = await tx.get(projectDocRef);
      const current = snap.data() || {};
      const currentOrder =
        sanitizeStepOrder(current.stepOrder) ||
        makeDefaultStepOrder(current.stepCount || 10);

      // if stepOrder is being changed, validate and enforce "all required steps complete"
      let nextOrder = currentOrder;
      if (stepOrder != null) {
        const sanitized = sanitizeStepOrder(stepOrder);
        if (!sanitized) {
          const err = new Error(
            "stepOrder must be an array of unique numeric step keys like ['1','2','3']"
          );
          err.statusCode = 400;
          throw err;
        }

        // Ensure it's a permutation of existing keys (use /steps/add or /steps/delete for changes)
        const a = new Set(currentOrder);
        const b = new Set(sanitized);
        if (a.size !== b.size) {
          const err = new Error(
            "stepOrder must contain the same set of step keys. Use /steps/add or /steps/delete to change count."
          );
          err.statusCode = 400;
          throw err;
        }
        for (const k of a) {
          if (!b.has(k)) {
            const err = new Error(
              "stepOrder must contain the same set of step keys. Use /steps/add or /steps/delete to change count."
            );
            err.statusCode = 400;
            throw err;
          }
        }

        // enforce completeness before reorder
        const cfg = await getProjectConfigOrThrow(pid);
        await ensureAllRequiredStepsComplete(pid, cfg);

        nextOrder = sanitized;
      }

      const patch = { updatedAt: now };

      if (name != null) patch.name = String(name).trim() || pid;

      if (stepAliases != null) {
        const aliases = sanitizeStepAliases(stepAliases, nextOrder);
        if (aliases == null) {
          const err = new Error(
            'stepAliases must be an object like {"1":"Consent"}'
          );
          err.statusCode = 400;
          throw err;
        }
        patch.stepAliases = aliases;
      }

      if (stepRules != null) {
        const rules = sanitizeStepRules(stepRules, nextOrder);
        if (rules == null) {
          const err = new Error(
            'stepRules must be an object like {"1":{"canSkip":false,"minWaitDays":0,"maxDaysToReport":30}}'
          );
          err.statusCode = 400;
          throw err;
        }
        // fill missing rules with defaults
        for (const k of nextOrder) {
          if (!rules[k])
            rules[k] = {
              canSkip: false,
              minWaitDays: 0,
              maxDaysToReport: null,
            };
        }
        patch.stepRules = rules;
      }

      if (stepOrder != null) {
        patch.stepOrder = nextOrder;
        patch.stepCount = nextOrder.length;
      }

      tx.set(projectDocRef, patch, { merge: true });
    });

    return res.json({ ok: true, projectId: pid, message: "Project updated" });
  } catch (err) {
    const status = err.statusCode || 500;
    return res.status(status).json({
      ok: false,
      error: "project_update_failed",
      message: err.message,
      code: err.code,
      missing: err.missing,
    });
  }
});

// ---- Steps management endpoints (NEW) ----

// ADD a step (insert position optional)
// POST /projects/:projectId/steps/add
// body: { insertIndex? }  // 0..len ; default append
app.post("/projects/:projectId/steps/add", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const insertIndexRaw = req.body?.insertIndex;
    const projectDocRef = projectRef(pid);
    const now = admin.firestore.FieldValue.serverTimestamp();

    // enforce completeness before add (as you requested)
    const cfg = await getProjectConfigOrThrow(pid);
    await ensureAllRequiredStepsComplete(pid, cfg);

    await db.runTransaction(async (tx) => {
      await ensureProjectExistsTx(tx, projectDocRef, pid, req.user);
      const snap = await tx.get(projectDocRef);
      const current = snap.data() || {};
      const order =
        sanitizeStepOrder(current.stepOrder) ||
        makeDefaultStepOrder(current.stepCount || 10);

      const maxKey = Math.max(...order.map((k) => Number(k)));
      const newKey = String(maxKey + 1);
      if (order.length + 1 > DEFAULT_MAX_STEPS) {
        const err = new Error(`Cannot exceed ${DEFAULT_MAX_STEPS} steps`);
        err.statusCode = 400;
        throw err;
      }

      const insertIndex =
        insertIndexRaw == null
          ? order.length
          : clampInt(insertIndexRaw, 0, order.length) ?? order.length;

      const nextOrder = [...order];
      nextOrder.splice(insertIndex, 0, newKey);

      const nextRules = { ...(current.stepRules || {}) };
      nextRules[newKey] = { canSkip: false, minWaitDays: 0, maxDaysToReport: null };

      const nextAliases = { ...(current.stepAliases || {}) };
      // no alias by default

      tx.set(
        projectDocRef,
        {
          updatedAt: now,
          stepOrder: nextOrder,
          stepCount: nextOrder.length,
          stepRules: nextRules,
          stepAliases: nextAliases,
        },
        { merge: true }
      );
    });

    return res.json({ ok: true, projectId: pid, message: "Step added" });
  } catch (err) {
    const status = err.statusCode || 500;
    return res.status(status).json({
      ok: false,
      error: "step_add_failed",
      message: err.message,
      code: err.code,
      missing: err.missing,
    });
  }
});

// DELETE a step (no data deletion, config only)
// POST /projects/:projectId/steps/delete
// body: { stepKey }
app.post("/projects/:projectId/steps/delete", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const stepKey = String(req.body?.stepKey || "").trim();
    if (!stepKey || !/^\d+$/.test(stepKey)) {
      return res.status(400).json({ ok: false, message: "stepKey is required (numeric string)" });
    }

    const projectDocRef = projectRef(pid);
    const now = admin.firestore.FieldValue.serverTimestamp();

    await db.runTransaction(async (tx) => {
      await ensureProjectExistsTx(tx, projectDocRef, pid, req.user);
      const snap = await tx.get(projectDocRef);
      const current = snap.data() || {};
      const order =
        sanitizeStepOrder(current.stepOrder) ||
        makeDefaultStepOrder(current.stepCount || 10);

      if (!order.includes(stepKey)) {
        const err = new Error(`stepKey ${stepKey} not found in project stepOrder`);
        err.statusCode = 404;
        throw err;
      }
      if (order.length <= 1) {
        const err = new Error("Cannot delete the last remaining step");
        err.statusCode = 400;
        throw err;
      }

      const nextOrder = order.filter((k) => k !== stepKey);

      const nextAliases = { ...(current.stepAliases || {}) };
      delete nextAliases[stepKey];

      const nextRules = { ...(current.stepRules || {}) };
      delete nextRules[stepKey];

      tx.set(
        projectDocRef,
        {
          updatedAt: now,
          stepOrder: nextOrder,
          stepCount: nextOrder.length,
          stepAliases: nextAliases,
          stepRules: nextRules,
        },
        { merge: true }
      );
    });

    return res.json({ ok: true, projectId: pid, message: "Step deleted (config only)" });
  } catch (err) {
    const status = err.statusCode || 500;
    return res.status(status).json({
      ok: false,
      error: "step_delete_failed",
      message: err.message,
    });
  }
});

// REORDER steps (drag/drop)
// POST /projects/:projectId/steps/reorder
// body: { stepOrder: ["2","1","3"] }
app.post("/projects/:projectId/steps/reorder", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const nextOrder = sanitizeStepOrder(req.body?.stepOrder);
    if (!nextOrder) {
      return res.status(400).json({
        ok: false,
        message: "stepOrder must be an array of unique numeric step keys like ['1','2','3']",
      });
    }

    // enforce completeness before reorder (as you requested)
    const cfg = await getProjectConfigOrThrow(pid);
    await ensureAllRequiredStepsComplete(pid, cfg);

    const projectDocRef = projectRef(pid);
    const now = admin.firestore.FieldValue.serverTimestamp();

    await db.runTransaction(async (tx) => {
      await ensureProjectExistsTx(tx, projectDocRef, pid, req.user);
      const snap = await tx.get(projectDocRef);
      const current = snap.data() || {};
      const currentOrder =
        sanitizeStepOrder(current.stepOrder) ||
        makeDefaultStepOrder(current.stepCount || 10);

      const a = new Set(currentOrder);
      const b = new Set(nextOrder);
      if (a.size !== b.size) {
        const err = new Error(
          "stepOrder must contain the same set of step keys. Use /steps/add or /steps/delete to change count."
        );
        err.statusCode = 400;
        throw err;
      }
      for (const k of a) if (!b.has(k)) {
        const err = new Error(
          "stepOrder must contain the same set of step keys. Use /steps/add or /steps/delete to change count."
        );
        err.statusCode = 400;
        throw err;
      }

      tx.set(
        projectDocRef,
        {
          updatedAt: now,
          stepOrder: nextOrder,
          stepCount: nextOrder.length,
        },
        { merge: true }
      );
    });

    return res.json({ ok: true, projectId: pid, message: "Steps reordered" });
  } catch (err) {
    const status = err.statusCode || 500;
    return res.status(status).json({
      ok: false,
      error: "step_reorder_failed",
      message: err.message,
      code: err.code,
      missing: err.missing,
    });
  }
});

// SUGGEST next screeningId for a project (numeric)
// GET /projects/:projectId/suggest-next-screening-id
app.get(
  "/projects/:projectId/suggest-next-screening-id",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const qs = await projectRef(pid)
        .collection("screenings")
        .where("screeningIdNum", ">", 0)
        .orderBy("screeningIdNum", "desc")
        .limit(1)
        .get();

      let suggested = "1";
      if (!qs.empty) {
        const top = qs.docs[0].data();
        const maxNum = parsePositiveInt(top.screeningIdNum);
        if (maxNum) suggested = String(maxNum + 1);
      }

      return res.json({ ok: true, projectId: pid, suggestedScreeningId: suggested });
    } catch (err) {
      return res
        .status(500)
        .json({ ok: false, error: "suggest_failed", message: err.message });
    }
  }
);

// -----------------------------
// SCREENINGS (per project)
// -----------------------------

// LIST screenings
// GET /projects/:projectId/redcap_data?limit=1000
// - also enforces auto-withdraw if overdue
app.get("/projects/:projectId/redcap_data", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const limit = Math.min(parsePositiveInt(req.query.limit) || 200, 5000);

    // ensure config exists
    const cfg = await getProjectConfigOrThrow(pid);

    const qs = await projectRef(pid).collection("screenings").limit(limit).get();
    const rows = qs.docs.map((d) => ({ id: d.id, ...d.data() }));

    // auto-withdraw overdue screenings (best-effort; batch write)
    const nowMs = Date.now();
    const toWithdraw = [];
    for (const r of rows) {
      const info = computeAutoWithdrawNowIfOverdue(r, cfg, nowMs);
      if (info?.shouldWithdraw) {
        toWithdraw.push({ screeningId: r.screeningId || r.id, info });
      }
    }

    // perform withdrawals in batches (if any)
    if (toWithdraw.length) {
      const batchSize = 400;
      for (let i = 0; i < toWithdraw.length; i += batchSize) {
        const slice = toWithdraw.slice(i, i + batchSize);
        const batch = db.batch();
        for (const item of slice) {
          const ref = screeningRef(pid, item.screeningId);
          batch.set(
            ref,
            {
              updatedAt: admin.firestore.FieldValue.serverTimestamp(),
              withdrewAt: admin.firestore.Timestamp.fromDate(new Date(nowMs)),
              withdrewUpdatedAt: admin.firestore.FieldValue.serverTimestamp(),
              autoWithdraw: {
                atMs: nowMs,
                dueMs: item.info.dueMs,
                missingRequiredStepKey: item.info.missingRequiredStepKey,
                overdueByDays: item.info.overdueByDays,
              },
            },
            { merge: true }
          );
        }
        await batch.commit();
      }

      // reflect in returned rows as well (so UI updates immediately)
      for (const r of rows) {
        if (r.withdrewAt) continue;
        const info = computeAutoWithdrawNowIfOverdue(r, cfg, nowMs);
        if (info?.shouldWithdraw) {
          r.withdrewAt = admin.firestore.Timestamp.fromDate(new Date(nowMs));
          r.autoWithdraw = {
            atMs: nowMs,
            dueMs: info.dueMs,
            missingRequiredStepKey: info.missingRequiredStepKey,
            overdueByDays: info.overdueByDays,
          };
        }
      }
    }

    // Sort: numeric screeningIdNum first, then alphanumeric screeningId
    rows.sort((a, b) => {
      const an = Number(a.screeningIdNum || 0);
      const bn = Number(b.screeningIdNum || 0);

      if (an > 0 && bn === 0) return -1;
      if (an === 0 && bn > 0) return 1;

      if (an > 0 && bn > 0 && an !== bn) return an - bn;

      return String(a.screeningId || a.id || "").localeCompare(
        String(b.screeningId || b.id || "")
      );
    });

    return res.json({ ok: true, projectId: pid, count: rows.length, data: rows });
  } catch (err) {
    console.error("LIST screenings failed:", {
      message: err.message,
      code: err.code,
      stack: err.stack,
    });

    return res.status(500).json({
      ok: false,
      error: "list_failed",
      message: err?.message || "Unknown error",
    });
  }
});

// GET one screening
// GET /projects/:projectId/redcap_data/:screeningId
app.get(
  "/projects/:projectId/redcap_data/:screeningId",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const sid = normalizeScreeningId(req.params.screeningId);
      if (!sid)
        return res.status(400).json({ ok: false, message: "Invalid screeningId" });

      const snap = await screeningRef(pid, sid).get();
      if (!snap.exists)
        return res.status(404).json({ ok: false, message: "Not found" });

      return res.json({
        ok: true,
        projectId: pid,
        data: { id: snap.id, ...snap.data() },
      });
    } catch (err) {
      return res
        .status(500)
        .json({ ok: false, error: "get_failed", message: err.message });
    }
  }
);

// CREATE screening (manual screeningId)
// POST /projects/:projectId/redcap_data
// body: { screeningId, studyId?, stepKey?, date? }
app.post("/projects/:projectId/redcap_data", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const { screeningId, studyId, stepKey, date } = req.body || {};
    const sid = normalizeScreeningId(screeningId);
    if (!sid) {
      return res.status(400).json({
        ok: false,
        message: "screeningId is required (string/number, max 64 chars)",
      });
    }

    // optional initial step set
    const cfg = await getProjectConfigOrThrow(pid);
    const sk = stepKey != null ? String(stepKey).trim() : null;
    if (stepKey != null && !cfg.stepOrder.includes(sk)) {
      return res.status(400).json({
        ok: false,
        message: `stepKey must be one of project stepOrder keys: ${cfg.stepOrder.join(",")}`,
      });
    }

    const ts = date != null ? parseDateToTimestamp(date) : null;
    if (date != null && !ts) {
      return res
        .status(400)
        .json({ ok: false, message: "date must be a valid date string or epoch ms" });
    }

    const projectDocRef = projectRef(pid);
    const docRef = screeningRef(pid, sid);
    const now = admin.firestore.FieldValue.serverTimestamp();
    const screeningIdNum = screeningIdToNumIfNumeric(sid);

    await db.runTransaction(async (tx) => {
      await ensureProjectExistsTx(tx, projectDocRef, pid, req.user);

      const existing = await tx.get(docRef);
      if (existing.exists) {
        const err = new Error("screeningId already exists in this project");
        err.statusCode = 409;
        throw err;
      }

      const baseDoc = {
        screeningId: sid,
        screeningIdNum: screeningIdNum || 0,
        createdAt: now,
        updatedAt: now,
        steps: {},
        withdrewAt: null,
      };

      if (studyId != null) {
        const st = String(studyId).trim();
        if (st) baseDoc.studyId = st;
      }

      if (sk && ts) {
        baseDoc.steps[String(sk)] = { date: ts, updatedAt: now };
      }

      tx.create(docRef, baseDoc);
    });

    return res.status(201).json({
      ok: true,
      projectId: pid,
      screeningId: sid,
      message: "Created screening record",
    });
  } catch (err) {
    const status = err.statusCode || 400;
    return res.status(status).json({
      ok: false,
      error: "create_failed",
      message: err.message,
    });
  }
});

// UPDATE screening meta (studyId optional, can be set anytime)
// PATCH /projects/:projectId/redcap_data/:screeningId/meta
// body: { studyId? }
app.patch(
  "/projects/:projectId/redcap_data/:screeningId/meta",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const sid = normalizeScreeningId(req.params.screeningId);
      if (!sid)
        return res.status(400).json({ ok: false, message: "Invalid screeningId" });

      const { studyId } = req.body || {};
      if (studyId == null) {
        return res.status(400).json({ ok: false, message: "Nothing to update" });
      }

      const docRef = screeningRef(pid, sid);
      const now = admin.firestore.FieldValue.serverTimestamp();

      await db.runTransaction(async (tx) => {
        const snap = await tx.get(docRef);

        if (!snap.exists) {
          const screeningIdNum = screeningIdToNumIfNumeric(sid);
          tx.set(
            docRef,
            {
              screeningId: sid,
              screeningIdNum: screeningIdNum || 0,
              createdAt: now,
              updatedAt: now,
              steps: {},
              withdrewAt: null,
            },
            { merge: true }
          );
        }

        const patch = { updatedAt: now };

        const st = String(studyId).trim();
        if (st) patch.studyId = st;
        else patch.studyId = admin.firestore.FieldValue.delete();

        tx.set(docRef, patch, { merge: true });
      });

      return res.json({
        ok: true,
        projectId: pid,
        screeningId: sid,
        message: "Meta updated",
      });
    } catch (err) {
      return res.status(500).json({
        ok: false,
        error: "meta_update_failed",
        message: err.message,
      });
    }
  }
);

// UPSERT STEP DATE (create doc if missing)
// POST /projects/:projectId/redcap_data/:screeningId/step
// body: { stepKey, date }
app.post(
  "/projects/:projectId/redcap_data/:screeningId/step",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const sid = normalizeScreeningId(req.params.screeningId);
      if (!sid)
        return res.status(400).json({ ok: false, message: "Invalid screeningId" });

      const { stepKey, date } = req.body || {};
      const sk = String(stepKey || "").trim();
      if (!sk || !/^\d+$/.test(sk)) {
        return res.status(400).json({ ok: false, message: "stepKey is required (numeric string)" });
      }

      const ts = parseDateToTimestamp(date);
      if (!ts)
        return res.status(400).json({
          ok: false,
          message: "date must be a valid date string or epoch ms",
        });

      const now = admin.firestore.FieldValue.serverTimestamp();
      const docRef = screeningRef(pid, sid);
      const projectDocRef = projectRef(pid);

      let warning = null;

      await db.runTransaction(async (tx) => {
        // read project config
        await ensureProjectExistsTx(tx, projectDocRef, pid, req.user);
        const pSnap = await tx.get(projectDocRef);
        const pData = pSnap.data() || {};
        const order =
          sanitizeStepOrder(pData.stepOrder) ||
          makeDefaultStepOrder(pData.stepCount || 10);

        if (!order.includes(sk)) {
          const err = new Error(`stepKey ${sk} is not in project stepOrder`);
          err.statusCode = 400;
          throw err;
        }

        const rules = sanitizeStepRules(pData.stepRules || {}, order) || {};
        for (const k of order) {
          if (!rules[k]) rules[k] = { canSkip: false, minWaitDays: 0, maxDaysToReport: null };
        }

        const snap = await tx.get(docRef);
        const data = snap.exists ? snap.data() || {} : {};

        // BLOCK if withdrawn
        if (data.withdrewAt) {
          const err = new Error("User withdrawn; cannot set any step dates.");
          err.statusCode = 409;
          throw err;
        }

        // create minimal doc if missing
        if (!snap.exists) {
          const screeningIdNum = screeningIdToNumIfNumeric(sid);
          tx.set(
            docRef,
            {
              screeningId: sid,
              screeningIdNum: screeningIdNum || 0,
              createdAt: now,
              updatedAt: now,
              steps: {},
              withdrewAt: null,
            },
            { merge: true }
          );
        }

        const idx = order.indexOf(sk);
        const prevKey = idx > 0 ? order[idx - 1] : null;
        const nextKey = idx < order.length - 1 ? order[idx + 1] : null;

        const newMs = tsToMs(ts);
        // --- NEW: anchorStart auto-update when editing FIRST step (stepOrder[0]) ---
        const firstStepKey = order[0];
        if (firstStepKey && sk === String(firstStepKey)) {
          const newAnchor = mondayWeekStartStrFromMs(newMs);

          const curAnchor = (pData?.analytics && typeof pData.analytics === "object")
            ? pData.analytics.anchorStart
            : null;

          // Update anchor if missing OR newAnchor is earlier (YYYY-MM-DD compare works)
          if (!curAnchor || (typeof curAnchor === "string" && newAnchor < curAnchor)) {
            tx.set(
              projectDocRef,
              {
                updatedAt: now,
                "analytics.anchorStart": newAnchor,
              },
              { merge: true }
            );
          }
        }
        if (newMs == null) {
          const err = new Error("Invalid date");
          err.statusCode = 400;
          throw err;
        }

        // Enforce: cannot be before previous step date (if prev exists)
        if (prevKey) {
          const prevMs = tsToMs(getStepTsFromScreening(data, prevKey));
          if (prevMs != null) {
            if (newMs < prevMs) {
              const err = new Error(
                `Step ${sk} date cannot be before Step ${prevKey} (${new Date(prevMs)
                  .toISOString()
                  .slice(0, 10)}).`
              );
              err.statusCode = 400;
              throw err;
            }

            // Soft warning: minWaitDays
            const minWaitDays = rules?.[sk]?.minWaitDays || 0;
            if (minWaitDays > 0) {
              const minAllowedMs = prevMs + minWaitDays * 24 * 60 * 60 * 1000;
              if (newMs < minAllowedMs) {
                warning = `You set a ${minWaitDays}-day wait time for Step ${sk}. You are reporting before that window.`;
              }
            }
          }
        }

        // Enforce: cannot be after next step date (if next exists and already filled)
        if (nextKey) {
          const nextMs = tsToMs(getStepTsFromScreening(data, nextKey));
          if (nextMs != null) {
            if (newMs > nextMs) {
              const err = new Error(
                `Step ${sk} date cannot be after Step ${nextKey} (${new Date(nextMs)
                  .toISOString()
                  .slice(0, 10)}).`
              );
              err.statusCode = 400;
              throw err;
            }
          }
        }

        // Save the step itself
        tx.set(
          docRef,
          {
            updatedAt: now,
            steps: {
              [sk]: { date: ts, updatedAt: now },
            },
          },
          { merge: true }
        );

        // Skip propagation (NEW):
        // If previous steps are marked canSkip and currently missing, fill them with THIS date.
        // We propagate backward through consecutive skippable steps immediately before this one.
        // Example: step 2 (canSkip) missing, user sets step 3 => step2 gets step3 date.
        for (let j = idx - 1; j >= 0; j--) {
          const k = order[j];
          const rule = rules?.[k] || {};
          if (!rule.canSkip) break; // stop at first non-skippable

          const existingMs = tsToMs(getStepTsFromScreening(data, k));
          if (existingMs != null) continue; // don't overwrite existing
          // Fill skipped step
          tx.set(
            docRef,
            {
              updatedAt: now,
              steps: {
                [k]: { date: ts, updatedAt: now, autoFilledFrom: sk },
              },
            },
            { merge: true }
          );
        }
      });

      return res.json({
        ok: true,
        projectId: pid,
        screeningId: sid,
        stepKey: sk,
        message: "Step date saved",
        ...(warning ? { warning } : {}),
      });
    } catch (err) {
      const status = err.statusCode || 400;
      return res.status(status).json({
        ok: false,
        error: "step_update_failed",
        message: err.message,
      });
    }
  }
);

// WITHDRAW (locks step updates)
// POST /projects/:projectId/redcap_data/:screeningId/withdraw
// body: { date }
app.post(
  "/projects/:projectId/redcap_data/:screeningId/withdraw",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const sid = normalizeScreeningId(req.params.screeningId);
      if (!sid)
        return res.status(400).json({ ok: false, message: "Invalid screeningId" });

      const { date } = req.body || {};
      const withdrewTs = parseDateToTimestamp(date);
      if (!withdrewTs)
        return res.status(400).json({
          ok: false,
          message: "date must be a valid date string or epoch ms",
        });

      const docRef = screeningRef(pid, sid);
      const now = admin.firestore.FieldValue.serverTimestamp();

      await db.runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        const data = snap.exists ? snap.data() || {} : {};

        if (data.withdrewAt) {
          const err = new Error(
            "User already withdrawn; withdrewAt is already set."
          );
          err.statusCode = 409;
          throw err;
        }

        if (!snap.exists) {
          const screeningIdNum = screeningIdToNumIfNumeric(sid);
          tx.set(
            docRef,
            {
              screeningId: sid,
              screeningIdNum: screeningIdNum || 0,
              createdAt: now,
              updatedAt: now,
              steps: {},
              withdrewAt: null,
            },
            { merge: true }
          );
        }

        tx.set(
          docRef,
          {
            updatedAt: now,
            withdrewAt: withdrewTs,
            withdrewUpdatedAt: now,
          },
          { merge: true }
        );
      });

      return res.json({
        ok: true,
        projectId: pid,
        screeningId: sid,
        message: "Withdraw date saved. Further step updates are blocked.",
      });
    } catch (err) {
      const status = err.statusCode || 400;
      return res.status(status).json({
        ok: false,
        error: "withdraw_failed",
        message: err.message,
      });
    }
  }
);

// REVERT WITHDRAW
// POST /projects/:projectId/redcap_data/:screeningId/revert-withdraw
app.post(
  "/projects/:projectId/redcap_data/:screeningId/revert-withdraw",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const sid = normalizeScreeningId(req.params.screeningId);
      if (!sid)
        return res.status(400).json({ ok: false, message: "Invalid screeningId" });

      const docRef = screeningRef(pid, sid);
      const now = admin.firestore.FieldValue.serverTimestamp();

      await db.runTransaction(async (tx) => {
        const snap = await tx.get(docRef);
        if (!snap.exists) {
          const err = new Error("Not found");
          err.statusCode = 404;
          throw err;
        }

        tx.set(
          docRef,
          {
            updatedAt: now,
            withdrewAt: null,
            withdrewUpdatedAt: now,
            autoWithdraw: admin.firestore.FieldValue.delete(),
          },
          { merge: true }
        );
      });

      return res.json({
        ok: true,
        projectId: pid,
        screeningId: sid,
        message: "Withdraw reverted",
      });
    } catch (err) {
      const status = err.statusCode || 400;
      return res.status(status).json({
        ok: false,
        error: "revert_withdraw_failed",
        message: err.message,
      });
    }
  }
);

// -----------------------------
// DELETE endpoints
// -----------------------------

// DELETE one screening
// DELETE /projects/:projectId/redcap_data/:screeningId
app.delete(
  "/projects/:projectId/redcap_data/:screeningId",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const sid = normalizeScreeningId(req.params.screeningId);
      if (!sid)
        return res.status(400).json({ ok: false, message: "Invalid screeningId" });

      const docRef = screeningRef(pid, sid);
      const snap = await docRef.get();
      if (!snap.exists) {
        return res.status(404).json({
          ok: false,
          projectId: pid,
          screeningId: sid,
          message: "Not found",
        });
      }

      await docRef.delete();

      return res.json({
        ok: true,
        projectId: pid,
        screeningId: sid,
        message: "Screening deleted",
      });
    } catch (err) {
      console.error("DELETE screening failed:", {
        message: err.message,
        code: err.code,
        stack: err.stack,
      });
      return res.status(500).json({
        ok: false,
        error: "delete_screening_failed",
        message: err.message,
      });
    }
  }
);

// DELETE all screenings in a project (keeps the project doc)
// DELETE /projects/:projectId/redcap_data?confirm=YES
app.delete(
  "/projects/:projectId/redcap_data",
  requireAuth,
  async (req, res) => {
    try {
      const pid = normalizeProjectId(req.params.projectId);
      if (!pid)
        return res.status(400).json({ ok: false, message: "Invalid projectId" });

      const confirm = String(req.query.confirm || "");
      if (confirm !== "YES") {
        return res.status(400).json({
          ok: false,
          message:
            'This will delete ALL screenings in the project. Re-run with ?confirm=YES',
        });
      }

      await deleteProjectScreenings(pid);

      return res.json({
        ok: true,
        projectId: pid,
        message: "All screenings deleted",
      });
    } catch (err) {
      console.error("DELETE all screenings failed:", {
        message: err.message,
        code: err.code,
        stack: err.stack,
      });
      return res.status(500).json({
        ok: false,
        error: "delete_all_screenings_failed",
        message: err.message,
      });
    }
  }
);

// DELETE a project AND all its screenings
// DELETE /projects/:projectId?confirm=YES
app.delete("/projects/:projectId", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid)
      return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const confirm = String(req.query.confirm || "");
    if (confirm !== "YES") {
      return res.status(400).json({
        ok: false,
        message:
          'This will delete the PROJECT and ALL its screenings. Re-run with ?confirm=YES',
      });
    }

    const pRef = projectRef(pid);
    const pSnap = await pRef.get();
    if (!pSnap.exists) {
      return res
        .status(404)
        .json({ ok: false, projectId: pid, message: "Project not found" });
    }

    await deleteProjectScreenings(pid);
    await pRef.delete();

    return res.json({ ok: true, projectId: pid, message: "Project deleted" });
  } catch (err) {
    console.error("DELETE project failed:", {
      message: err.message,
      code: err.code,
      stack: err.stack,
    });
    return res.status(500).json({
      ok: false,
      error: "delete_project_failed",
      message: err.message,
    });
  }
});

// (Danger) DELETE ALL projects AND ALL screenings
// DELETE /projects?confirm=DELETE_ALL
app.delete("/projects", requireAuth, async (req, res) => {
  try {
    const confirm = String(req.query.confirm || "");
    if (confirm !== "DELETE_ALL") {
      return res.status(400).json({
        ok: false,
        message:
          'This will delete ALL projects and ALL screenings. Re-run with ?confirm=DELETE_ALL',
      });
    }

    let deletedProjects = 0;

    while (true) {
      const qs = await db.collection("redcap_data").limit(100).get();
      if (qs.empty) break;

      for (const doc of qs.docs) {
        const pid = doc.id;
        await deleteProjectScreenings(pid);
        await doc.ref.delete();
        deletedProjects += 1;
      }
    }

    return res.json({
      ok: true,
      message: "All projects deleted",
      deletedProjects,
    });
  } catch (err) {
    console.error("DELETE all projects failed:", {
      message: err.message,
      code: err.code,
      stack: err.stack,
    });
    return res.status(500).json({
      ok: false,
      error: "delete_all_projects_failed",
      message: err.message,
    });
  }
});
// -----------------------------
// ANALYTICS endpoints (NEW) - Plotly-ready
// -----------------------------

// GET /projects/:projectId/analytics/all?limit=5000&asOf=2026-02-17
app.get("/projects/:projectId/analytics/all", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid) return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const limit = Math.min(parsePositiveInt(req.query.limit) || 5000, 20000);

    // asOf can be ISO date or ISO datetime
    const asOfTs = req.query.asOf ? parseDateToTimestamp(req.query.asOf) : null;
    const asOfMs = asOfTs ? tsToMs(asOfTs) : Date.now();

    const projectCfg = await getProjectConfigOrThrow(pid);

    // Load screenings
    const snap = await projectRef(pid).collection("screenings").limit(limit).get();
    const screenings = snap.docs.map((d) => ({ id: d.id, ...d.data() }));

    const stepOrder = projectCfg.stepOrder || [];
    if (!stepOrder.length) {
      return res.json({ ok: true, projectId: pid, anchorStart: null, steps: [], countControl: {}, percent: {}, summary: [], funnel: [] });
    }

    // Anchor start
    const anchorStart = await getOrComputeAnchorStart(pid, projectCfg, screenings);
    const analyticsCfg = getAnalyticsConfig(projectCfg);

    // 1) Weekly counts per step
    const weeklyCounts = buildWeeklyCountSeries(stepOrder, anchorStart, screenings);

    // 2) Count control chart stats (Poisson 3σ) per step
    const countControlByStep = {};
    for (const stepKey of stepOrder) {
      const rows = weeklyCounts.byStep[String(stepKey)] || [];
      countControlByStep[String(stepKey)] = addPoissonControlStatsPerStep(rows, analyticsCfg, anchorStart);
    }

    // 3) Percent possible series (steps >=2)
    const pctPossible = buildPercentPossibleSeries(stepOrder, anchorStart, screenings, projectCfg, asOfMs);

    // 4) Percent control chart bounds per step (trim + 3σ)
    const pctControlByStep = {};
    for (const stepKey of stepOrder.slice(1)) {
      const rows = pctPossible.byStep[String(stepKey)] || [];
      pctControlByStep[String(stepKey)] = addPercentControlStats(rows, 3);
    }

    // 5) Summary + funnel
    const { summary, funnel } = computeDashboardSummary(stepOrder, countControlByStep, pctControlByStep, projectCfg);

    return res.json({
      ok: true,
      projectId: pid,
      anchorStart,
      steps: stepOrder.map(String),

      meta: {
        limitUsed: screenings.length,
        globalMinWeekStart: weeklyCounts.globalMinWeekStart,
        globalMaxWeekStart: weeklyCounts.globalMaxWeekStart,
        weeksRemaining: getAnalyticsConfig(projectCfg).weeksRemaining,
        excelRosterMode: !!getAnalyticsConfig(projectCfg).excelRosterMode,
      },

      // for Plotly
      countControl: { byStep: countControlByStep },
      percentPossible: { byStep: pctPossible.byStep },
      percentControl: { byStep: pctControlByStep },

      summary,
      funnel,
    });
  } catch (err) {
    console.error("analytics/all failed:", err);
    return res.status(500).json({ ok: false, error: "analytics_failed", message: err.message });
  }
});

// Optional lighter endpoints if you want smaller payloads:

// GET /projects/:projectId/analytics/count-control?limit=5000
app.get("/projects/:projectId/analytics/count-control", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid) return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const limit = Math.min(parsePositiveInt(req.query.limit) || 5000, 20000);
    const projectCfg = await getProjectConfigOrThrow(pid);

    const snap = await projectRef(pid).collection("screenings").limit(limit).get();
    const screenings = snap.docs.map((d) => ({ id: d.id, ...d.data() }));

    const anchorStart = await getOrComputeAnchorStart(pid, projectCfg, screenings);
    const analyticsCfg = getAnalyticsConfig(projectCfg);

    const weeklyCounts = buildWeeklyCountSeries(projectCfg.stepOrder, anchorStart, screenings);

    const byStep = {};
    for (const stepKey of projectCfg.stepOrder) {
      const rows = weeklyCounts.byStep[String(stepKey)] || [];
      byStep[String(stepKey)] = addPoissonControlStatsPerStep(rows, analyticsCfg, anchorStart);
    }

    return res.json({
      ok: true,
      projectId: pid,
      anchorStart,
      steps: projectCfg.stepOrder.map(String),
      meta: {
        globalMinWeekStart: weeklyCounts.globalMinWeekStart,
        globalMaxWeekStart: weeklyCounts.globalMaxWeekStart,
      },
      byStep,
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "count_control_failed", message: err.message });
  }
});

// GET /projects/:projectId/analytics/percent?limit=5000&asOf=2026-02-17
app.get("/projects/:projectId/analytics/percent", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid) return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const limit = Math.min(parsePositiveInt(req.query.limit) || 5000, 20000);
    const asOfTs = req.query.asOf ? parseDateToTimestamp(req.query.asOf) : null;
    const asOfMs = asOfTs ? tsToMs(asOfTs) : Date.now();

    const projectCfg = await getProjectConfigOrThrow(pid);

    const snap = await projectRef(pid).collection("screenings").limit(limit).get();
    const screenings = snap.docs.map((d) => ({ id: d.id, ...d.data() }));

    const anchorStart = await getOrComputeAnchorStart(pid, projectCfg, screenings);

    const pctPossible = buildPercentPossibleSeries(projectCfg.stepOrder, anchorStart, screenings, projectCfg, asOfMs);

    const pctControl = {};
    for (const stepKey of projectCfg.stepOrder.slice(1)) {
      const rows = pctPossible.byStep[String(stepKey)] || [];
      pctControl[String(stepKey)] = addPercentControlStats(rows, 3);
    }

    return res.json({
      ok: true,
      projectId: pid,
      anchorStart,
      steps: projectCfg.stepOrder.map(String),
      percentPossible: pctPossible.byStep,
      percentControl: pctControl,
    });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "percent_failed", message: err.message });
  }
});

// GET /projects/:projectId/analytics/summary?limit=5000
app.get("/projects/:projectId/analytics/summary", requireAuth, async (req, res) => {
  try {
    const pid = normalizeProjectId(req.params.projectId);
    if (!pid) return res.status(400).json({ ok: false, message: "Invalid projectId" });

    const limit = Math.min(parsePositiveInt(req.query.limit) || 5000, 20000);

    const projectCfg = await getProjectConfigOrThrow(pid);

    const snap = await projectRef(pid).collection("screenings").limit(limit).get();
    const screenings = snap.docs.map((d) => ({ id: d.id, ...d.data() }));

    const anchorStart = await getOrComputeAnchorStart(pid, projectCfg, screenings);
    const analyticsCfg = getAnalyticsConfig(projectCfg);

    const weeklyCounts = buildWeeklyCountSeries(projectCfg.stepOrder, anchorStart, screenings);

    const countControlByStep = {};
    for (const stepKey of projectCfg.stepOrder) {
      const rows = weeklyCounts.byStep[String(stepKey)] || [];
      countControlByStep[String(stepKey)] = addPoissonControlStatsPerStep(rows, analyticsCfg, anchorStart);
    }

    const pctPossible = buildPercentPossibleSeries(projectCfg.stepOrder, anchorStart, screenings, projectCfg, Date.now());
    const pctControlByStep = {};
    for (const stepKey of projectCfg.stepOrder.slice(1)) {
      pctControlByStep[String(stepKey)] = addPercentControlStats(pctPossible.byStep[String(stepKey)] || [], 3);
    }

    const { summary, funnel } = computeDashboardSummary(projectCfg.stepOrder, countControlByStep, pctControlByStep, projectCfg);

    return res.json({ ok: true, projectId: pid, anchorStart, summary, funnel });
  } catch (err) {
    return res.status(500).json({ ok: false, error: "summary_failed", message: err.message });
  }
});
// -----------------------------
// Health check
// -----------------------------
app.get("/", (req, res) => {
  res.json({ ok: true, name: "redcap api", version: "projects-v2-steps" });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () =>
  console.log(`API running on http://localhost:${PORT}`)
);