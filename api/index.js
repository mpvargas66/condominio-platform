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

    CREATE TABLE IF NOT EXISTS actas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      titulo TEXT NOT NULL,
      tipo TEXT DEFAULT 'comite',
      contenido TEXT,
      estado TEXT DEFAULT 'borrador',
      usuario_id INTEGER,
      fecha_reunion DATE,
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
    );

    CREATE TABLE IF NOT EXISTS firmas_actas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      acta_id INTEGER NOT NULL,
      usuario_id INTEGER NOT NULL,
      fecha_firma DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(acta_id) REFERENCES actas(id),
      FOREIGN KEY(usuario_id) REFERENCES usuarios(id),
      UNIQUE(acta_id, usuario_id)
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

// Función auxiliar de auditoría
const registrarAuditoria = (usuarioId, accion, detalles) => {
  try {
    db.prepare(`INSERT INTO auditoria (usuario_id, accion, detalles) VALUES (?, ?, ?)`).run(usuarioId, accion, detalles);
  } catch (e) {}
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

// ========== ACTAS ==========
app.get('/api/actas', verificarToken, (req, res) => {
  try {
    const actas = db.prepare(`
      SELECT a.*, u.nombre as usuario_nombre FROM actas a
      LEFT JOIN usuarios u ON a.usuario_id = u.id
      ORDER BY a.fecha_creacion DESC
    `).all();
    res.json(actas);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id', verificarToken, (req, res) => {
  try {
    const acta = db.prepare(`
      SELECT a.*, u.nombre as usuario_nombre FROM actas a
      LEFT JOIN usuarios u ON a.usuario_id = u.id
      WHERE a.id = ?
    `).get(req.params.id);

    if (!acta) return res.status(404).json({ error: 'Acta no encontrada' });

    const firmas = db.prepare(`
      SELECT f.*, u.nombre FROM firmas_actas f
      LEFT JOIN usuarios u ON f.usuario_id = u.id
      WHERE f.acta_id = ?
    `).all(req.params.id);

    acta.firmas = firmas;
    res.json(acta);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/actas', verificarToken, (req, res) => {
  try {
    const { titulo, tipo, contenido, fecha_reunion } = req.body;
    if (!titulo) return res.status(400).json({ error: 'Título requerido' });

    const stmt = db.prepare(`
      INSERT INTO actas (titulo, tipo, contenido, fecha_reunion, usuario_id, estado)
      VALUES (?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(titulo, tipo || 'comite', contenido || '', fecha_reunion || new Date().toISOString().split('T')[0], req.usuarioId, 'borrador');

    registrarAuditoria(req.usuarioId, 'crear_acta', `Acta: ${titulo}`);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/actas/:id', verificarToken, (req, res) => {
  try {
    const { titulo, tipo, contenido, estado } = req.body;
    const stmt = db.prepare(`
      UPDATE actas
      SET titulo = ?, tipo = ?, contenido = ?, estado = ?, fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id = ?
    `);
    stmt.run(titulo, tipo, contenido, estado, req.params.id);
    registrarAuditoria(req.usuarioId, 'editar_acta', `Acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/actas/:id', verificarToken, (req, res) => {
  try {
    const stmt = db.prepare(`DELETE FROM actas WHERE id = ?`);
    stmt.run(req.params.id);
    registrarAuditoria(req.usuarioId, 'eliminar_acta', `Acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/actas/:id/firmar', verificarToken, (req, res) => {
  try {
    const stmt = db.prepare(`INSERT INTO firmas_actas (acta_id, usuario_id) VALUES (?, ?)`);
    stmt.run(req.params.id, req.usuarioId);
    registrarAuditoria(req.usuarioId, 'firmar_acta', `Firmó acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas-templates', verificarToken, (req, res) => {
  const templates = {
    comite: {
      nombre: 'Reunión de Comité',
      template: `# ACTA DE REUNIÓN DE COMITÉ\n\n**Fecha:** ${new Date().toLocaleDateString('es-CL')}\n**Lugar:** [LUGAR]\n**Presentes:** [NOMBRES]\n\n## Orden del Día\n\n[ASUNTOS]\n\n## Decisiones\n\n[ACUERDOS TOMADOS]\n\n## Próxima Reunión\n\n[FECHA]`
    },
    asamblea_ordinaria: {
      nombre: 'Asamblea Ordinaria',
      template: `# ACTA DE ASAMBLEA ORDINARIA\n\n**Fecha:** ${new Date().toLocaleDateString('es-CL')}\n**Lugar:** [LUGAR]\n**Quórum:** [CANTIDAD]\n\n## Orden del Día\n\n[ASUNTOS]\n\n## Votaciones\n\n[RESULTADOS]\n\n## Acuerdos Finales\n\n[LISTADO]`
    },
    asamblea_extraordinaria: {
      nombre: 'Asamblea Extraordinaria',
      template: `# ACTA DE ASAMBLEA EXTRAORDINARIA\n\n**Motivo de Convocatoria:** [MOTIVO]\n**Fecha:** ${new Date().toLocaleDateString('es-CL')}\n**Lugar:** [LUGAR]\n\n## Participantes\n\n[NOMBRES]\n\n## Asuntos Tratados\n\n[DETALLES]\n\n## Acuerdos Adoptados\n\n[LISTADO]`
    }
  };
  res.json(templates);
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Comunité' });
});

export default app;
