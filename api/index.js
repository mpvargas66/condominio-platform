import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import Database from 'better-sqlite3';

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const db = new Database(process.env.NODE_ENV === 'production' ? '/tmp/comunite.db' : './comunite.db');

app.use(cors());
app.use(express.json({ limit: '10mb' }));

db.pragma('foreign_keys = ON');

// Crear tablas
function initDb() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS usuarios (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      contrasena TEXT NOT NULL,
      nombre TEXT NOT NULL,
      perfil TEXT DEFAULT 'miembro',
      activo BOOLEAN DEFAULT 1,
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS auditoria (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      usuario_id INTEGER,
      accion TEXT,
      fecha DATETIME DEFAULT CURRENT_TIMESTAMP,
      detalles TEXT,
      FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
    );
  `);

  try {
    const passwordHash = bcrypt.hashSync('admin123', 10);
    db.prepare(`
      INSERT OR IGNORE INTO usuarios (email, contrasena, nombre, perfil)
      VALUES ('admin@comunite.cl', ?, 'Administrador', 'admin')
    `).run(passwordHash);
  } catch (e) {}
}

initDb();

// Middleware auth
const verificarToken = (req, res, next) => {
  const token = req.headers['authorization']?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No autenticado' });
  try {
    const decoded = jwt.verify(token, JWT_SECRET);
    req.usuarioId = decoded.id;
    req.usuarioPerfil = decoded.perfil;
    next();
  } catch (err) {
    return res.status(403).json({ error: 'Token inválido' });
  }
};

// Login
app.post('/api/auth/login', (req, res) => {
  try {
    const { email, contrasena } = req.body;
    const usuario = db.prepare(`SELECT * FROM usuarios WHERE email = ? AND activo = 1`).get(email);

    if (!usuario || !bcrypt.compareSync(contrasena, usuario.contrasena)) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign({ id: usuario.id, email, perfil: usuario.perfil }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, usuario: { id: usuario.id, email, nombre: usuario.nombre, perfil: usuario.perfil } });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Registro
app.post('/api/auth/registro', (req, res) => {
  try {
    const { nombre, email, contrasena } = req.body;
    if (!email || !contrasena || !nombre) {
      return res.status(400).json({ error: 'Campos requeridos faltantes' });
    }

    const passwordHash = bcrypt.hashSync(contrasena, 10);
    const stmt = db.prepare(`
      INSERT INTO usuarios (email, contrasena, nombre, perfil)
      VALUES (?, ?, ?, ?)
    `);
    const result = stmt.run(email, passwordHash, nombre, 'miembro');

    const token = jwt.sign({ id: result.lastInsertRowid, email, perfil: 'miembro' }, JWT_SECRET, { expiresIn: '7d' });
    res.json({ success: true, token, usuario: { id: result.lastInsertRowid, email, nombre, perfil: 'miembro' } });
  } catch (error) {
    if (error.message.includes('UNIQUE')) {
      return res.status(400).json({ error: 'Email ya registrado' });
    }
    res.status(500).json({ error: error.message });
  }
});

// Usuarios
app.get('/api/usuarios', verificarToken, (req, res) => {
  try {
    const usuarios = db.prepare(`SELECT id, email, nombre, perfil, activo FROM usuarios`).all();
    res.json(usuarios);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Comunité' });
});

export default app;
