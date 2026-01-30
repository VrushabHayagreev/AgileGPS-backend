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

        // Verify token is valid and issued by your Firebase project
        const decoded = await admin.auth().verifyIdToken(idToken);

        return res.json({
            ok: true,
            uid: decoded.uid,
            email: decoded.email || null,
        });
    } catch (err) {
        return res.status(401).json({ ok: false, error: "invalid_token", message: err.message });
    }
});

// -----------------------------
// Protected route middleware
// -----------------------------
async function requireAuth(req, res, next) {
    try {
        const authHeader = req.headers.authorization || "";
        const match = authHeader.match(/^Bearer (.+)$/);
        if (!match) return res.status(401).json({ ok: false, error: "missing_bearer_token" });

        const decoded = await admin.auth().verifyIdToken(match[1]);
        req.user = decoded;
        next();
    } catch (e) {
        return res.status(401).json({ ok: false, error: "unauthorized", message: e.message });
    }
}

app.get("/me", requireAuth, (req, res) => {
    res.json({ ok: true, uid: req.user.uid, email: req.user.email || null });
});

// -----------------------------
// Helpers for redcap_data
// -----------------------------
function parsePositiveInt(value) {
    const n = Number(value);
    if (!Number.isInteger(n) || n <= 0) return null;
    return n;
}

function parseStepNumber(stepNumber) {
    const n = parsePositiveInt(stepNumber);
    if (!n || n < 1 || n > 10) return null;
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
    return null;
}

// -----------------------------
// REDCAP DATA
// Collection: redcap_data
// Counter doc: meta/redcap_counter { nextId: number }
// Steps stored at: steps.{1..10} = { date: Timestamp, updatedAt: Timestamp }
//
// Flow you asked:
// - If not exists: create it
// - If exists: ask for step number then insert/update date
// - screeningId is numeric 1,2,3...
// - lock on next id using transaction
// -----------------------------

// CREATE NEW RECORD with next screeningId (atomic increment)
// POST /redcap_data
// Optional body: { stepNumber, date }
app.post("/redcap_data", requireAuth, async (req, res) => {
    try {
        const { stepNumber, date } = req.body || {};
        const counterRef = db.collection("meta").doc("redcap_counter");

        const result = await db.runTransaction(async (tx) => {
            const counterSnap = await tx.get(counterRef);

            let nextId = 1;
            if (counterSnap.exists) {
                const data = counterSnap.data() || {};
                nextId = parsePositiveInt(data.nextId) || 1;
            }

            const screeningId = nextId;
            const docRef = db.collection("redcap_data").doc(String(screeningId));

            // lock/increment
            tx.set(counterRef, { nextId: screeningId + 1 }, { merge: true });

            const now = admin.firestore.FieldValue.serverTimestamp();

            const baseDoc = {
                screeningId,
                createdAt: now,
                updatedAt: now,
                steps: {},
            };

            // Optional initial step on create
            if (stepNumber != null && date != null) {
                const s = parseStepNumber(stepNumber);
                const ts = parseDateToTimestamp(date);
                if (!s) throw new Error("stepNumber must be an integer between 1 and 10");
                if (!ts) throw new Error("date must be a valid date string or epoch ms");

                baseDoc.steps[String(s)] = {
                    date: ts,
                    updatedAt: admin.firestore.FieldValue.serverTimestamp(),
                };
            }

            tx.create(docRef, baseDoc);

            return { screeningId };
        });

        return res.status(201).json({
            ok: true,
            screeningId: result.screeningId,
            message: "Created redcap_data record",
        });
    } catch (err) {
        return res.status(400).json({ ok: false, error: "create_failed", message: err.message });
    }
});

// UPSERT STEP DATE (create doc if missing)
// POST /redcap_data/:screeningId/step
// body: { stepNumber, date }
app.post("/redcap_data/:screeningId/step", requireAuth, async (req, res) => {
    try {
        const screeningId = parsePositiveInt(req.params.screeningId);
        if (!screeningId) {
            return res.status(400).json({ ok: false, message: "screeningId must be a positive integer" });
        }

        const { stepNumber, date } = req.body || {};
        const s = parseStepNumber(stepNumber);
        if (!s) {
            return res.status(400).json({ ok: false, message: "stepNumber must be an integer between 1 and 10" });
        }

        const ts = parseDateToTimestamp(date);
        if (!ts) {
            return res.status(400).json({ ok: false, message: "date must be a valid date string or epoch ms" });
        }

        const docRef = db.collection("redcap_data").doc(String(screeningId));
        const now = admin.firestore.FieldValue.serverTimestamp();

        await db.runTransaction(async (tx) => {
            const snap = await tx.get(docRef);
            const data = snap.exists ? (snap.data() || {}) : {};

            // BLOCK if withdrawn
            if (data.withdrewAt) {
                const err = new Error("User withdrawn; cannot set any step dates.");
                err.statusCode = 409;
                throw err;
            }

            // If missing, create
            if (!snap.exists) {
                tx.set(
                    docRef,
                    {
                        screeningId,
                        createdAt: now,
                        updatedAt: now,
                        steps: {},
                    },
                    { merge: true }
                );
            }

            // Upsert step (store as nested map under steps: { "1": { ... } })
            tx.set(
                docRef,
                {
                    updatedAt: now,
                    steps: {
                        [String(s)]: {
                            date: ts,
                            updatedAt: now,
                        },
                    },
                },
                { merge: true }
            );
        });
        return res.json({
            ok: true,
            screeningId,
            stepNumber: s,
            message: "Step date saved",
        });
    } catch (err) {
        const status = err.statusCode || 400;
        return res.status(status).json({ ok: false, error: "step_update_failed", message: err.message });
    }
});

// GET one record
// GET /redcap_data/:screeningId
app.get("/redcap_data/:screeningId", requireAuth, async (req, res) => {
    try {
        const screeningId = parsePositiveInt(req.params.screeningId);
        if (!screeningId) {
            return res.status(400).json({ ok: false, message: "screeningId must be a positive integer" });
        }

        const snap = await db.collection("redcap_data").doc(String(screeningId)).get();
        if (!snap.exists) {
            return res.status(404).json({ ok: false, message: "Not found" });
        }

        return res.json({ ok: true, data: { id: snap.id, ...snap.data() } });
    } catch (err) {
        return res.status(500).json({ ok: false, error: "get_failed", message: err.message });
    }
});

// GET all records
// GET /redcap_data?limit=200
app.get("/redcap_data", requireAuth, async (req, res) => {
    try {
        const limit = Math.min(parsePositiveInt(req.query.limit) || 200, 1000);

        const qs = await db
            .collection("redcap_data")
            .orderBy("screeningId", "asc")
            .limit(limit)
            .get();

        const rows = qs.docs.map((d) => ({ id: d.id, ...d.data() }));

        return res.json({ ok: true, count: rows.length, data: rows });
    } catch (err) {
        return res.status(500).json({ ok: false, error: "list_failed", message: err.message });
    }
});
app.post("/redcap_data/:screeningId/withdraw", requireAuth, async (req, res) => {
    try {
        const screeningId = parsePositiveInt(req.params.screeningId);
        if (!screeningId) {
            return res.status(400).json({ ok: false, message: "screeningId must be a positive integer" });
        }

        const { date } = req.body || {};
        const withdrewTs = parseDateToTimestamp(date);
        if (!withdrewTs) {
            return res.status(400).json({ ok: false, message: "date must be a valid date string or epoch ms" });
        }

        const docRef = db.collection("redcap_data").doc(String(screeningId));
        const now = admin.firestore.FieldValue.serverTimestamp();

        await db.runTransaction(async (tx) => {
            const snap = await tx.get(docRef);
            const data = snap.exists ? (snap.data() || {}) : {};

            // If already withdrawn, block
            if (data.withdrewAt) {
                const err = new Error("User already withdrawn; withdrewAt is already set.");
                err.statusCode = 409;
                throw err;
            }

            // Create if missing
            if (!snap.exists) {
                tx.set(
                    docRef,
                    {
                        screeningId,
                        createdAt: now,
                        updatedAt: now,
                        steps: {},
                    },
                    { merge: true }
                );
            }

            // Set withdrewAt (one time)
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
            screeningId,
            message: "Withdraw date saved. Further step updates are blocked.",
        });
    } catch (err) {
        const status = err.statusCode || 400;
        return res.status(status).json({ ok: false, error: "withdraw_failed", message: err.message });
    }
});
// REVERT WITHDRAW (set withdrewAt back to null)
// POST /redcap_data/:screeningId/revert-withdraw
app.post("/redcap_data/:screeningId/revert-withdraw", requireAuth, async (req, res) => {
  try {
    const screeningId = parsePositiveInt(req.params.screeningId);
    if (!screeningId) {
      return res.status(400).json({ ok: false, message: "screeningId must be a positive integer" });
    }

    const docRef = db.collection("redcap_data").doc(String(screeningId));
    const now = admin.firestore.FieldValue.serverTimestamp();

    await db.runTransaction(async (tx) => {
      const snap = await tx.get(docRef);
      if (!snap.exists) {
        const err = new Error("Not found");
        err.statusCode = 404;
        throw err;
      }

      // Set withdrewAt back to null (user requested null, not delete)
      tx.set(
        docRef,
        {
          updatedAt: now,
          withdrewAt: null,
          withdrewUpdatedAt: now,
        },
        { merge: true }
      );
    });

    return res.json({ ok: true, screeningId, message: "Withdraw reverted" });
  } catch (err) {
    const status = err.statusCode || 400;
    return res.status(status).json({ ok: false, error: "revert_withdraw_failed", message: err.message });
  }
});
// -----------------------------
// Health check
// -----------------------------
app.get("/", (req, res) => {
    res.json({ ok: true, name: "redcap api" });
});

const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`API running on http://localhost:${PORT}`));