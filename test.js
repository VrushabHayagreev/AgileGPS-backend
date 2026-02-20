/**
 * seed_project1_admin.js
 *
 * Prereqs:
 * 1) npm i firebase-admin
 * 2) export GOOGLE_APPLICATION_CREDENTIALS="/absolute/path/to/serviceAccount.json"
 *    OR set FIREBASE_SERVICE_ACCOUNT_JSON env var to the JSON string
 *
 * Run:
 *   node seed_project1_admin.js
 */

const admin = require("firebase-admin");

// Optional: hit your backend analytics after seeding
const BASE_URL = "http://localhost:3001";
const PROJECT_ID = "1";
const TARGET_STEPS = 6;
const COUNT = 50;

// ---------- Firebase Admin init ----------
function initAdmin() {
  if (admin.apps.length) return;

  // Use local servicekey.json (same as your server.js)
  const serviceAccount = require("./servicekey.json");
  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });
}

function pad(n, len = 3) {
  return String(n).padStart(len, "0");
}

function addDaysUTC(dateObj, days) {
  const d = new Date(dateObj.getTime());
  d.setUTCDate(d.getUTCDate() + days);
  return d;
}

function randInt(min, max) {
  return Math.floor(Math.random() * (max - min + 1)) + min;
}

function toTs(dateObj) {
  return admin.firestore.Timestamp.fromDate(dateObj);
}

// ---------- Firestore paths (assumed by your API shape) ----------
function projectRef(db, projectId) {
  // server.js uses: db.collection("redcap_data").doc(projectId)
  return db.collection("redcap_data").doc(String(projectId));
}

function screeningRef(db, projectId, screeningId) {
  // server.js uses: redcap_data/{projectId}/screenings/{screeningId}
  return projectRef(db, projectId).collection("screenings").doc(String(screeningId));
}

// ---------- Project config seeding ----------
async function ensureProjectHas6Steps(db) {
  const ref = projectRef(db, PROJECT_ID);
  const snap = await ref.get();
  const existing = snap.exists ? snap.data() : {};

  const existingOrder = Array.isArray(existing?.stepOrder) ? existing.stepOrder.map(String) : [];
  const order = existingOrder.length ? [...existingOrder] : [];

  // Ensure at least 6 keys in stepOrder
  for (let i = order.length; i < TARGET_STEPS; i++) {
    order.push(String(i + 1));
  }

  // Generic aliases + rules for 6 steps (you can rename later)
  const defaultAliases = {
    "1": "Screened",
    "2": "Consent",
    "3": "Eligible",
    "4": "Baseline",
    "5": "Randomized",
    "6": "Complete",
  };

  const mergedAliases = { ...(existing?.stepAliases || {}), ...defaultAliases };

  const mergedRules = { ...(existing?.stepRules || {}) };
  for (let i = 1; i <= TARGET_STEPS; i++) {
    const k = String(i);
    if (!mergedRules[k]) mergedRules[k] = {};
    if (typeof mergedRules[k].canSkip !== "boolean") mergedRules[k].canSkip = false;
  }

  await ref.set(
    {
      projectId: PROJECT_ID,
      name: String(existing?.name || PROJECT_ID),
      stepCount: TARGET_STEPS,
      stepOrder: order.slice(0, TARGET_STEPS),
      stepAliases: mergedAliases,
      stepRules: mergedRules,
      updatedAt: admin.firestore.FieldValue.serverTimestamp(),
      createdAt: snap.exists ? (existing?.createdAt || admin.firestore.FieldValue.serverTimestamp()) : admin.firestore.FieldValue.serverTimestamp(),
    },
    { merge: true }
  );

  return order.slice(0, TARGET_STEPS);
}

// ---------- Screening row generator ----------
function makeScreeningRow(screeningId, stepKeys, baseStartDateUTC) {
  // Spread step 1 across ~26 weeks so your weekly analytics charts look real
  const weekOffset = randInt(0, 26);
  const dayJitter = randInt(0, 6);

  const step1Date = addDaysUTC(baseStartDateUTC, weekOffset * 7 + dayJitter);

  const steps = {};
  let prev = step1Date;

  for (let idx = 0; idx < stepKeys.length; idx++) {
    const k = String(stepKeys[idx]);

    if (idx === 0) {
      steps[k] = { date: toTs(step1Date) };
      continue;
    }

    // keep monotonic increasing dates
    const gap = 5 + randInt(0, 2); // 5–7 day gap
    prev = addDaysUTC(prev, gap);
    steps[k] = { date: toTs(prev) };
  }

  return {
    screeningId,
    screeningIdNum: /^\d+$/.test(String(screeningId)) ? Number(screeningId) : 0,
    withdrewAt: null,
    steps,
    createdAt: admin.firestore.FieldValue.serverTimestamp(),
    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
    // If you use any other fields in your backend, add them here (studyId, siteId, arm, etc.)
  };
}

// ---------- Optional analytics ping ----------
async function pingAnalytics() {
  try {
    const res = await fetch(
      `${BASE_URL}/projects/${encodeURIComponent(PROJECT_ID)}/analytics/all?limit=5000`
    );
    const text = await res.text();
    let json = null;
    try {
      json = text ? JSON.parse(text) : null;
    } catch {
      json = { raw: text };
    }

    if (!res.ok) {
      console.log(
        `analytics/all returned ${res.status}. If your API requires auth, just open your Plots page and it will compute on request.`
      );
      return;
    }

    console.log("analytics/all ok:", json?.ok);
    console.log("anchorStart:", json?.anchorStart || json?.anchorStartISO);
    console.log("steps:", json?.steps);
    console.log("summary rows:", Array.isArray(json?.summary) ? json.summary.length : 0);
    console.log("funnel rows:", Array.isArray(json?.funnel) ? json.funnel.length : 0);
  } catch (e) {
    console.log("analytics ping failed (safe to ignore):", e?.message || e);
  }
}

// ---------- Main ----------
async function run() {
  initAdmin();
  const db = admin.firestore();

  console.log("Ensuring project 1 has 6 steps...");
  const stepKeys = await ensureProjectHas6Steps(db);
  console.log("Using step keys:", stepKeys);

  // Base date far enough back to span weeks
  const baseStartDateUTC = new Date(Date.UTC(2025, 5, 3)); // 2025-06-03 UTC

  console.log(`Writing ${COUNT} screening docs under redcap_data/${PROJECT_ID}/screenings ...`);

  const batchSize = 400; // safe batch size (Firestore limit is 500 writes)
  let batch = db.batch();
  let ops = 0;

  for (let i = 1; i <= COUNT; i++) {
    const screeningId = `TST-${PROJECT_ID}-${pad(i, 3)}`; // e.g. TST-1-001

    const row = makeScreeningRow(screeningId, stepKeys, baseStartDateUTC);
    const docRef = screeningRef(db, PROJECT_ID, screeningId);

    batch.set(docRef, row, { merge: true });
    ops++;

    if (ops >= batchSize || i === COUNT) {
      await batch.commit();
      console.log(`Committed batch (${i}/${COUNT})`);
      batch = db.batch();
      ops = 0;
    }
  }

  console.log("Seed complete.");

  // Optional: ping analytics to “trigger” verification
  console.log("Pinging analytics/all...");
  await pingAnalytics();

  console.log("Done.");
}

run().catch((e) => {
  console.error("Seeder failed:", e?.message || e);
  process.exit(1);
});