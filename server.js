const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Inicializar Firebase Admin con variables de entorno
admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    privateKey: process.env.FIREBASE_PRIVATE_KEY.replace(/\\n/g, "\n")
  })
});

const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET || "super_secret";

// ---------- AUTH ----------

// Registro
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;

    if (!username || !email || !password) {
      return res.status(400).json({ message: "Faltan campos" });
    }

    const exists = await db.collection("users").where("email", "==", email).get();
    if (!exists.empty) {
      return res.status(400).json({ message: "Email ya registrado" });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      username,
      email,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    const ref = await db.collection("users").add(newUser);

    const token = jwt.sign({ uid: ref.id, email }, JWT_SECRET, { expiresIn: "7d" });

    res.json({ uid: ref.id, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Login
app.post("/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Faltan campos" });
    }

    const snap = await db.collection("users")
      .where("email", "==", email)
      .get();

    if (snap.empty) {
      return res.status(400).json({ message: "Usuario no encontrado" });
    }

    const doc = snap.docs[0];
    const data = doc.data();

    const match = await bcrypt.compare(password, data.passwordHash);
    if (!match) {
      return res.status(401).json({ message: "Credenciales inválidas" });
    }

    const token = jwt.sign({ uid: doc.id, email }, JWT_SECRET, { expiresIn: "7d" });

    res.json({ uid: doc.id, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// ---------- EVENTS ----------

// Listar eventos
app.get("/events", async (req, res) => {
  try {
    const snap = await db.collection("events").get();
    const events = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(events);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Detalle evento
app.get("/events/:id", async (req, res) => {
  try {
    const doc = await db.collection("events").doc(req.params.id).get();
    if (!doc.exists) {
      return res.status(404).json({ message: "Evento no encontrado" });
    }
    res.json({ id: doc.id, ...doc.data() });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Crear comentario
app.post("/events/:id/comments", async (req, res) => {
  try {
    const { uid, comment, rating } = req.body;
    if (!uid || !comment) {
      return res.status(400).json({ message: "Faltan datos" });
    }

    await db.collection("events")
      .doc(req.params.id)
      .collection("comments")
      .add({
        uid,
        comment,
        rating: rating || null,
        createdAt: new Date().toISOString()
      });

    res.json({ message: "Comentario agregado" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Listar comentarios
app.get("/events/:id/comments", async (req, res) => {
  try {
    const snap = await db
      .collection("events")
      .doc(req.params.id)
      .collection("comments")
      .get();

    const comments = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    res.json(comments);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// ---------- ATTENDANCE ----------

// Confirmar asistencia
app.post("/attend/:eventId/confirm", async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) {
      return res.status(400).json({ message: "uid requerido" });
    }

    await db.collection("events")
      .doc(req.params.eventId)
      .collection("attendees")
      .doc(uid)
      .set({
        uid,
        confirmed: true,
        updatedAt: new Date().toISOString()
      });

    res.json({ message: "Asistencia confirmada" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Cancelar asistencia
app.post("/attend/:eventId/cancel", async (req, res) => {
  try {
    const { uid } = req.body;
    if (!uid) {
      return res.status(400).json({ message: "uid requerido" });
    }

    await db.collection("events")
      .doc(req.params.eventId)
      .collection("attendees")
      .doc(uid)
      .delete();

    res.json({ message: "Asistencia cancelada" });
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Listar asistentes
app.get("/attend/:eventId/attendees", async (req, res) => {
  try {
    const snap = await db
      .collection("events")
      .doc(req.params.eventId)
      .collection("attendees")
      .get();

    const attendees = snap.docs.map(d => ({ id: d.id, ...d.data() }));

    res.json(attendees);
  } catch (e) {
    res.status(500).json({ error: e.message });
  }
});

// Root
app.get("/", (req, res) => {
  res.json({ message: "API DSM con Firebase funcionando" });
});

const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log("API DSM escuchando en puerto " + port);
});
