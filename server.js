// server.js - API DSM completa (Eventos, Comentarios, Asistencia, Usuarios, Roles, Seguridad)
const express = require("express");
const cors = require("cors");
const admin = require("firebase-admin");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();
app.use(cors());
app.use(express.json());

// Inicializar Firebase Admin con variables de entorno
if (!process.env.FIREBASE_PROJECT_ID || !process.env.FIREBASE_CLIENT_EMAIL || !process.env.FIREBASE_PRIVATE_KEY) {
  console.warn("WARNING: Firebase env vars no configuradas. Asegúrate de setear FIREBASE_PROJECT_ID, FIREBASE_CLIENT_EMAIL, FIREBASE_PRIVATE_KEY");
}

admin.initializeApp({
  credential: admin.credential.cert({
    projectId: process.env.FIREBASE_PROJECT_ID,
    clientEmail: process.env.FIREBASE_CLIENT_EMAIL,
    // la privateKey debe venir con \n por cada nueva línea; aquí lo transformamos
    privateKey: (process.env.FIREBASE_PRIVATE_KEY || "").replace(/\\n/g, "\n")
  })
});

const db = admin.firestore();
const JWT_SECRET = process.env.JWT_SECRET || "super_secret_key";
const BASE_URL_PUBLIC = process.env.BASE_URL_PUBLIC || "https://api-proyecto-2-dsm.onrender.com"; // para compartir enlaces

// -----------------------------
// UTIL / MIDDLEWARES
// -----------------------------

function generateToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "7d" });
}

// Middleware de autenticación
function authenticateToken(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) return res.status(401).json({ message: "Token requerido" });
  const token = auth.split(" ")[1];
  try {
    const data = jwt.verify(token, JWT_SECRET);
    req.user = data; // contiene uid y email según generamos
    next();
  } catch (e) {
    return res.status(401).json({ message: "Token inválido" });
  }
}

// Middleware - requiere rol admin
async function requireAdmin(req, res, next) {
  try {
    const uid = req.user?.uid;
    if (!uid) return res.status(403).json({ message: "Acceso denegado" });
    const userDoc = await db.collection("users").doc(uid).get();
    const role = userDoc.exists ? userDoc.data().role : null;
    if (role === "admin") return next();
    return res.status(403).json({ message: "Requiere permiso de administrador" });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message });
  }
}

// Middleware - requiere ser creador del recurso o admin
async function requireOwnerOrAdmin(req, res, next) {
  try {
    const uid = req.user?.uid;
    if (!uid) return res.status(403).json({ message: "Acceso denegado" });

    // owner check: for events route expect req.params.id
    const resourceId = req.params.id || req.params.eventId;
    if (!resourceId) return res.status(400).json({ message: "ID de recurso requerido" });

    // check event owner
    const eventDoc = await db.collection("events").doc(resourceId).get();
    if (!eventDoc.exists) return res.status(404).json({ message: "Evento no encontrado" });

    const eventData = eventDoc.data();
    if (!eventData) return res.status(404).json({ message: "Evento no encontrado" });

    if (eventData.creatorUid === uid) return next();

    // else check admin
    const userDoc = await db.collection("users").doc(uid).get();
    const role = userDoc.exists ? userDoc.data().role : null;
    if (role === "admin") return next();

    return res.status(403).json({ message: "Solo el creador o admin puede realizar esta acción" });

  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: e.message });
  }
}

// -----------------------------
// AUTH - Registro / Login
// -----------------------------

// Registro
app.post("/auth/register", async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password) return res.status(400).json({ message: "Faltan campos" });

    const q = await db.collection("users").where("email", "==", email).get();
    if (!q.empty) return res.status(400).json({ message: "Email ya registrado" });

    const passwordHash = await bcrypt.hash(password, 10);
    const newUser = {
      username,
      email,
      passwordHash,
      role: "user",
      createdAt: new Date().toISOString()
    };

    const ref = await db.collection("users").add(newUser);

    const token = generateToken({ uid: ref.id, email });

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
    if (!email || !password) return res.status(400).json({ message: "Faltan campos" });

    const snap = await db.collection("users").where("email", "==", email).get();
    if (snap.empty) return res.status(400).json({ message: "Usuario no encontrado" });

    const doc = snap.docs[0];
    const data = doc.data();
    const match = await bcrypt.compare(password, data.passwordHash || "");
    if (!match) return res.status(401).json({ message: "Credenciales inválidas" });

    const token = generateToken({ uid: doc.id, email });
    res.json({ uid: doc.id, token });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -----------------------------
// USERS - Perfil
// -----------------------------

// Obtener usuario (solo info pública, no passwordHash)
app.get("/users/:uid", async (req, res) => {
  try {
    const doc = await db.collection("users").doc(req.params.uid).get();
    if (!doc.exists) return res.status(404).json({ message: "Usuario no encontrado" });
    const d = doc.data();
    // devolver solo campos públicos
    const out = {
      uid: doc.id,
      username: d.username,
      email: d.email,
      role: d.role || "user",
      createdAt: d.createdAt
    };
    res.json(out);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Actualizar perfil (solo el usuario o admin)
app.put("/users/:uid", authenticateToken, async (req, res) => {
  try {
    const targetUid = req.params.uid;
    const callerUid = req.user.uid;
    // sólo owner o admin
    const callerDoc = await db.collection("users").doc(callerUid).get();
    const callerRole = callerDoc.exists ? callerDoc.data().role : null;
    if (callerUid !== targetUid && callerRole !== "admin") {
      return res.status(403).json({ message: "Acceso denegado" });
    }

    const { username, email } = req.body;
    const update = {};
    if (username) update.username = username;
    if (email) update.email = email;

    await db.collection("users").doc(targetUid).update(update);
    const doc = await db.collection("users").doc(targetUid).get();
    const d = doc.data();
    res.json({ uid: doc.id, username: d.username, email: d.email, role: d.role });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Cambiar contraseña
app.put("/users/:uid/password", authenticateToken, async (req, res) => {
  try {
    const targetUid = req.params.uid;
    const callerUid = req.user.uid;
    if (callerUid !== targetUid) return res.status(403).json({ message: "Sólo el usuario puede cambiar su contraseña" });

    const { oldPassword, newPassword } = req.body;
    if (!oldPassword || !newPassword) return res.status(400).json({ message: "Faltan datos" });

    const doc = await db.collection("users").doc(targetUid).get();
    if (!doc.exists) return res.status(404).json({ message: "Usuario no encontrado" });

    const data = doc.data();
    const match = await bcrypt.compare(oldPassword, data.passwordHash || "");
    if (!match) return res.status(401).json({ message: "Contraseña actual incorrecta" });

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.collection("users").doc(targetUid).update({ passwordHash: newHash });

    res.json({ message: "Contraseña actualizada" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -----------------------------
// EVENTS - CRUD y extras
// -----------------------------

// Listar todos (sin paginar)
app.get("/events", async (req, res) => {
  try {
    const snap = await db.collection("events").orderBy("createdAt", "desc").get();
    const events = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(events);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Próximos eventos (date >= hoy) - orden ascendente por date
app.get("/events/upcoming", async (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0]; // compararemos YYYY-MM-DD simple
    const snap = await db.collection("events")
      .where("date", ">=", today)
      .orderBy("date", "asc")
      .get();
    const events = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(events);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Eventos pasados (history) date < hoy, orden descendente
app.get("/events/past", async (req, res) => {
  try {
    const today = new Date().toISOString().split("T")[0];
    const snap = await db.collection("events")
      .where("date", "<", today)
      .orderBy("date", "desc")
      .get();
    const events = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(events);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Buscar eventos por texto (título o descripción)
app.get("/events/search", async (req, res) => {
  try {
    const q = (req.query.q || "").toString().toLowerCase();
    if (!q) return res.status(400).json({ message: "query q requerido" });

    // Firestore no tiene LIKE nativo; hacemos una simple estrategia: buscar en todos y filtrar
    const snap = await db.collection("events").get();
    const events = snap.docs
      .map(d => ({ id: d.id, ...d.data() }))
      .filter(ev => {
        const title = (ev.title || "").toString().toLowerCase();
        const desc = (ev.description || "").toString().toLowerCase();
        return title.includes(q) || desc.includes(q);
      });

    res.json(events);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Mis eventos (creados por uid)
app.get("/events/creator/:uid", async (req, res) => {
  try {
    const snap = await db.collection("events").where("creatorUid", "==", req.params.uid).orderBy("createdAt", "desc").get();
    const events = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(events);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Obtener evento
app.get("/events/:id", async (req, res) => {
  try {
    const doc = await db.collection("events").doc(req.params.id).get();
    if (!doc.exists) return res.status(404).json({ message: "Evento no encontrado" });
    res.json({ id: doc.id, ...doc.data() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Crear evento - ahora obtiene creatorName desde users doc
app.post("/events", authenticateToken, async (req, res) => {
  try {
    const { title, date, location, description, creatorUid } = req.body;
    if (!title || !date || !location || !description || !creatorUid) return res.status(400).json({ message: "Faltan campos" });

    // traer username
    const userDoc = await db.collection("users").doc(creatorUid).get();
    if (!userDoc.exists) return res.status(404).json({ message: "Usuario creador no encontrado" });
    const creatorName = userDoc.data().username || "Desconocido";

    const newEvent = {
      title,
      date,
      location,
      description,
      creatorUid,
      creatorName,
      createdAt: new Date().toISOString()
    };

    const ref = await db.collection("events").add(newEvent);
    res.json({ id: ref.id, ...newEvent });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Editar evento (solo creador o admin)
app.put("/events/:id", authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const { title, date, location, description } = req.body;
    // validaciones mínimas
    const doc = await db.collection("events").doc(id).get();
    if (!doc.exists) return res.status(404).json({ message: "Evento no encontrado" });

    const event = doc.data();
    const callerUid = req.user.uid;
    // check owner or admin
    const callerDoc = await db.collection("users").doc(callerUid).get();
    const callerRole = callerDoc.exists ? callerDoc.data().role : null;
    if (event.creatorUid !== callerUid && callerRole !== "admin") {
      return res.status(403).json({ message: "Solo el creador o admin puede editar" });
    }

    const update = {};
    if (title) update.title = title;
    if (date) update.date = date;
    if (location) update.location = location;
    if (description) update.description = description;

    await db.collection("events").doc(id).update(update);
    const updated = await db.collection("events").doc(id).get();
    res.json({ id: updated.id, ...updated.data() });

  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Eliminar evento (solo creador o admin)
app.delete("/events/:id", authenticateToken, async (req, res) => {
  try {
    const id = req.params.id;
    const doc = await db.collection("events").doc(id).get();
    if (!doc.exists) return res.status(404).json({ message: "Evento no encontrado" });

    const event = doc.data();
    const callerUid = req.user.uid;
    const callerDoc = await db.collection("users").doc(callerUid).get();
    const callerRole = callerDoc.exists ? callerDoc.data().role : null;
    if (event.creatorUid !== callerUid && callerRole !== "admin") {
      return res.status(403).json({ message: "Solo el creador o admin puede eliminar" });
    }

    // eliminar subcolecciones: comments y attendees (opcional: en batch)
    const commentsSnap = await db.collection("events").doc(id).collection("comments").get();
    const batch = db.batch();
    commentsSnap.forEach(c => batch.delete(c.ref));
    const attendeesSnap = await db.collection("events").doc(id).collection("attendees").get();
    attendeesSnap.forEach(a => batch.delete(a.ref));
    // eliminar documento
    batch.delete(db.collection("events").doc(id));
    await batch.commit();

    res.json({ message: "Evento eliminado" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Compartir evento - devuelve URL pública para compartir (Android hace Intent share)
app.get("/events/:id/share", async (req, res) => {
  try {
    const id = req.params.id;
    // podrías generar slug; por ahora devolvemos URL directa
    const url = `${BASE_URL_PUBLIC}/events/${id}`;
    res.json({ url });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -----------------------------
// COMMENTS - CRUD + rating
// -----------------------------

// Crear comentario (autenticado)
app.post("/events/:id/comments", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const { comment, rating } = req.body;
    const uid = req.user.uid;
    if (!comment) return res.status(400).json({ message: "Falta comment" });

    const userDoc = await db.collection("users").doc(uid).get();
    const username = userDoc.exists ? userDoc.data().username : "Desconocido";

    const newComment = {
      uid,
      username,
      comment,
      rating: rating || null,
      createdAt: new Date().toISOString()
    };

    const ref = await db.collection("events").doc(eventId).collection("comments").add(newComment);
    res.json({ id: ref.id, ...newComment });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Listar comentarios
app.get("/events/:id/comments", async (req, res) => {
  try {
    const eventId = req.params.id;
    const snap = await db.collection("events").doc(eventId).collection("comments").orderBy("createdAt", "desc").get();
    const comments = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(comments);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Editar comentario (autor o admin)
app.put("/events/:id/comments/:cid", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const cid = req.params.cid;
    const uid = req.user.uid;
    const docRef = db.collection("events").doc(eventId).collection("comments").doc(cid);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: "Comentario no encontrado" });

    const data = doc.data();
    if (data.uid !== uid) {
      // verificar admin
      const callerDoc = await db.collection("users").doc(uid).get();
      const callerRole = callerDoc.exists ? callerDoc.data().role : null;
      if (callerRole !== "admin") return res.status(403).json({ message: "Solo autor o admin puede editar" });
    }

    const { comment, rating } = req.body;
    const update = {};
    if (comment) update.comment = comment;
    if (rating !== undefined) update.rating = rating;
    await docRef.update({ ...update, editedAt: new Date().toISOString() });
    const updated = await docRef.get();
    res.json({ id: updated.id, ...updated.data() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Eliminar comentario (autor o admin)
app.delete("/events/:id/comments/:cid", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.id;
    const cid = req.params.cid;
    const uid = req.user.uid;
    const docRef = db.collection("events").doc(eventId).collection("comments").doc(cid);
    const doc = await docRef.get();
    if (!doc.exists) return res.status(404).json({ message: "Comentario no encontrado" });

    const data = doc.data();
    if (data.uid !== uid) {
      const callerDoc = await db.collection("users").doc(uid).get();
      const callerRole = callerDoc.exists ? callerDoc.data().role : null;
      if (callerRole !== "admin") return res.status(403).json({ message: "Solo autor o admin puede eliminar" });
    }

    await docRef.delete();
    res.json({ message: "Comentario eliminado" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Promedio de rating
app.get("/events/:id/rating", async (req, res) => {
  try {
    const eventId = req.params.id;
    const snap = await db.collection("events").doc(eventId).collection("comments").get();
    const ratings = snap.docs.map(d => d.data().rating).filter(Boolean);
    if (ratings.length === 0) return res.json({ average: 0, count: 0 });
    const sum = ratings.reduce((s, r) => s + Number(r), 0);
    const avg = sum / ratings.length;
    res.json({ average: avg, count: ratings.length });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -----------------------------
// ATTENDANCE (Asistencia)
// -----------------------------

// Confirmar asistencia (guarda uid y username)
app.post("/attend/:eventId/confirm", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const uid = req.user.uid;

    const userDoc = await db.collection("users").doc(uid).get();
    const username = userDoc.exists ? userDoc.data().username : "Desconocido";

    // Evitar doble confirmación: usamos doc con id = uid
    await db.collection("events").doc(eventId).collection("attendees").doc(uid).set({
      uid,
      username,
      confirmed: true,
      updatedAt: new Date().toISOString()
    });

    res.json({ message: "Asistencia confirmada" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Cancelar asistencia
app.post("/attend/:eventId/cancel", authenticateToken, async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const uid = req.user.uid;
    await db.collection("events").doc(eventId).collection("attendees").doc(uid).delete();
    res.json({ message: "Asistencia cancelada" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Listar asistentes con username
app.get("/attend/:eventId/attendees", async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const snap = await db.collection("events").doc(eventId).collection("attendees").get();
    const attendees = snap.docs.map(d => ({ id: d.id, ...d.data() }));
    res.json(attendees);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Chequear estado de asistencia de un usuario
app.get("/attend/:eventId/status/:uid", async (req, res) => {
  try {
    const eventId = req.params.eventId;
    const uid = req.params.uid;
    const doc = await db.collection("events").doc(eventId).collection("attendees").doc(uid).get();
    if (!doc.exists) return res.json({ confirmed: false });
    res.json({ confirmed: !!doc.data().confirmed, ...doc.data() });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Contador de asistentes
app.get("/events/:id/attendees/count", async (req, res) => {
  try {
    const eventId = req.params.id;
    const snap = await db.collection("events").doc(eventId).collection("attendees").get();
    res.json({ count: snap.size });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -----------------------------
// ADMIN UTILITIES
// -----------------------------

// Listar todos los usuarios (admin)
app.get("/admin/users", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const snap = await db.collection("users").get();
    const users = snap.docs.map(d => ({ uid: d.id, ...d.data() }));
    res.json(users);
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// Hacer admin a un usuario (admin)
app.post("/admin/users/:uid/make-admin", authenticateToken, requireAdmin, async (req, res) => {
  try {
    const uid = req.params.uid;
    await db.collection("users").doc(uid).update({ role: "admin" });
    res.json({ message: "Usuario promovido a admin" });
  } catch (e) {
    console.error(e);
    res.status(500).json({ error: e.message });
  }
});

// -----------------------------
// ROOT
// -----------------------------

app.get("/", (req, res) => {
  res.json({ message: "API DSM completa corriendo" });
});

// -----------------------------
// RUN
// -----------------------------
const port = process.env.PORT || 3000;
app.listen(port, () => {
  console.log(`API DSM escuchando en puerto ${port}`);
});
