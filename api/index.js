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
      fecha_reunion DATE,
      hora_inicio TEXT,
      hora_cierre TEXT,
      lugar TEXT,
      estado TEXT DEFAULT 'borrador',
      usuario_id INTEGER NOT NULL,
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
    );

    CREATE TABLE IF NOT EXISTS asistentes_actas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      acta_id INTEGER NOT NULL,
      usuario_id INTEGER,
      nombre TEXT,
      rut TEXT,
      rol TEXT,
      presente BOOLEAN DEFAULT 1,
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(acta_id) REFERENCES actas(id),
      FOREIGN KEY(usuario_id) REFERENCES usuarios(id)
    );

    CREATE TABLE IF NOT EXISTS votaciones_actas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      acta_id INTEGER NOT NULL,
      numero INTEGER,
      titulo TEXT NOT NULL,
      descripcion TEXT,
      votos_favor INTEGER DEFAULT 0,
      votos_contra INTEGER DEFAULT 0,
      abstenciones INTEGER DEFAULT 0,
      resultado TEXT,
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(acta_id) REFERENCES actas(id)
    );

    CREATE TABLE IF NOT EXISTS temas_actas (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      acta_id INTEGER NOT NULL,
      numero INTEGER,
      titulo TEXT NOT NULL,
      descripcion TEXT,
      conclusiones TEXT,
      observaciones TEXT,
      pendientes TEXT,
      acuerdos TEXT,
      responsable TEXT,
      fecha_limite DATE,
      estado TEXT DEFAULT 'pendiente',
      fecha_creacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      fecha_actualizacion DATETIME DEFAULT CURRENT_TIMESTAMP,
      FOREIGN KEY(acta_id) REFERENCES actas(id)
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

// ========== ASISTENTES DE ACTAS ==========
app.post('/api/actas/:id/asistentes', verificarToken, (req, res) => {
  try {
    const { nombre, rut, rol, presente } = req.body;
    const stmt = db.prepare(`
      INSERT INTO asistentes_actas (acta_id, nombre, rut, rol, presente)
      VALUES (?, ?, ?, ?, ?)
    `);
    const result = stmt.run(req.params.id, nombre, rut, rol, presente !== false ? 1 : 0);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id/asistentes', verificarToken, (req, res) => {
  try {
    const asistentes = db.prepare(`
      SELECT * FROM asistentes_actas WHERE acta_id = ? ORDER BY presente DESC, nombre ASC
    `).all(req.params.id);
    res.json(asistentes);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/asistentes/:id', verificarToken, (req, res) => {
  try {
    db.prepare(`DELETE FROM asistentes_actas WHERE id = ?`).run(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== VOTACIONES ==========
app.post('/api/actas/:id/votaciones', verificarToken, (req, res) => {
  try {
    const { numero, titulo, descripcion, votos_favor, votos_contra, abstenciones } = req.body;
    const resultado = votos_favor > votos_contra ? 'APROBADO' : votos_favor < votos_contra ? 'RECHAZADO' : 'EMPATE';

    const stmt = db.prepare(`
      INSERT INTO votaciones_actas (acta_id, numero, titulo, descripcion, votos_favor, votos_contra, abstenciones, resultado)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const result = stmt.run(req.params.id, numero, titulo, descripcion, votos_favor, votos_contra, abstenciones, resultado);
    res.json({ success: true, id: result.lastInsertRowid, resultado });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id/votaciones', verificarToken, (req, res) => {
  try {
    const votaciones = db.prepare(`
      SELECT * FROM votaciones_actas WHERE acta_id = ? ORDER BY numero ASC
    `).all(req.params.id);
    res.json(votaciones);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/votaciones/:id', verificarToken, (req, res) => {
  try {
    db.prepare(`DELETE FROM votaciones_actas WHERE id = ?`).run(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== TEMAS ==========
app.post('/api/actas/:id/temas', verificarToken, (req, res) => {
  try {
    const { numero, titulo } = req.body;
    const stmt = db.prepare(`
      INSERT INTO temas_actas (acta_id, numero, titulo, estado)
      VALUES (?, ?, ?, 'pendiente')
    `);
    const result = stmt.run(req.params.id, numero, titulo);
    res.json({ success: true, id: result.lastInsertRowid });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id/temas', verificarToken, (req, res) => {
  try {
    const temas = db.prepare(`
      SELECT * FROM temas_actas WHERE acta_id = ? ORDER BY numero ASC
    `).all(req.params.id);
    res.json(temas);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/temas/:id', verificarToken, (req, res) => {
  try {
    const tema = db.prepare(`SELECT * FROM temas_actas WHERE id = ?`).get(req.params.id);
    if (!tema) return res.status(404).json({ error: 'Tema no encontrado' });
    res.json(tema);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/temas/:id', verificarToken, (req, res) => {
  try {
    const { descripcion, conclusiones, observaciones, pendientes, acuerdos, responsable, fecha_limite, estado } = req.body;
    const stmt = db.prepare(`
      UPDATE temas_actas
      SET descripcion = ?, conclusiones = ?, observaciones = ?, pendientes = ?, acuerdos = ?, responsable = ?, fecha_limite = ?, estado = ?, fecha_actualizacion = CURRENT_TIMESTAMP
      WHERE id = ?
    `);
    stmt.run(descripcion, conclusiones, observaciones, pendientes, acuerdos, responsable, fecha_limite, estado, req.params.id);
    registrarAuditoria(req.usuarioId, 'actualizar_tema', `Tema actualizado`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/temas/:id', verificarToken, (req, res) => {
  try {
    db.prepare(`DELETE FROM temas_actas WHERE id = ?`).run(req.params.id);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== DESCARGAR PDF ==========
app.get('/api/actas/:id/pdf', verificarToken, (req, res) => {
  try {
    const acta = db.prepare(`SELECT * FROM actas WHERE id = ?`).get(req.params.id);
    if (!acta) return res.status(404).json({ error: 'Acta no encontrada' });

    const PDFDocument = require('pdfkit');
    const doc = new PDFDocument({ size: 'A4', margin: 50 });
    const filename = `acta-${acta.id}.pdf`;

    res.setHeader('Content-Type', 'application/pdf');
    res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);

    doc.pipe(res);

    if (acta.tipo.includes('asamblea')) {
      generarPDFAsamblea(doc, acta, req.params.id);
    } else {
      generarPDFComite(doc, acta, req.params.id);
    }

    doc.end();
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

function generarPDFAsamblea(doc, acta, actaId) {
  doc.fontSize(14).font('Helvetica-Bold').text('ACTA DE ASAMBLEA DE COPROPIETARIOS', { align: 'center' });

  const tipo = acta.tipo === 'asamblea_ordinaria' ? 'ORDINARIA' : 'EXTRAORDINARIA';
  doc.fontSize(12).font('Helvetica-Bold').text(`(${tipo})`, { align: 'center' });
  doc.moveDown(0.5);

  doc.fontSize(10).font('Helvetica');
  doc.text(`Fecha: ${new Date(acta.fecha_reunion).toLocaleDateString('es-CL')}`);
  doc.text(`Hora: ${acta.hora_inicio || '[Sin especificar]'} - ${acta.hora_cierre || '[Sin especificar]'}`);
  doc.text(`Lugar: ${acta.lugar || '[Sin especificar]'}`);
  doc.text(`Título: ${acta.titulo}`);
  doc.moveDown(0.5);

  const asistentes = db.prepare(`SELECT * FROM asistentes_actas WHERE acta_id = ? ORDER BY presente DESC, nombre ASC`).all(actaId);
  const presentes = asistentes.filter(a => a.presente).length;
  const total = asistentes.length;
  const porcentaje = total > 0 ? Math.round((presentes / total) * 100) : 0;

  doc.fontSize(11).font('Helvetica-Bold').text('I. PARTICIPANTES', 50);
  doc.fontSize(9).font('Helvetica');
  doc.text(`Total: ${total} | Presentes: ${presentes} | Porcentaje: ${porcentaje}%`);
  doc.moveDown(0.3);

  doc.fontSize(8).font('Helvetica-Bold');
  doc.text('Nombre', 50, doc.y);
  doc.text('RUT', 250, doc.y);
  doc.text('Rol', 350, doc.y);
  doc.text('Presente', 450, doc.y);
  doc.moveDown(0.2);
  doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();

  doc.fontSize(8).font('Helvetica');
  asistentes.forEach(a => {
    doc.text(a.nombre.substring(0, 30), 50, doc.y);
    doc.text(a.rut, 250, doc.y - doc.currentLineHeight());
    doc.text(a.rol, 350, doc.y - doc.currentLineHeight());
    doc.text(a.presente ? 'Sí' : 'No', 450, doc.y - doc.currentLineHeight());
    doc.moveDown(0.25);
  });

  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
  doc.moveDown(0.3);

  doc.fontSize(10).font('Helvetica-Bold').text('II. QUÓRUM', 50);
  doc.fontSize(9).font('Helvetica');
  const minimoRequerido = acta.tipo === 'asamblea_extraordinaria' ? 50 : 33;
  const quorumValido = acta.tipo === 'asamblea_extraordinaria'
    ? presentes >= Math.ceil(total * 0.5) + 1
    : porcentaje >= 33;
  doc.text(`Mínimo requerido: ${minimoRequerido}% | Quórum: ${quorumValido ? '✅ VÁLIDO' : '❌ INVÁLIDO'}`);
  doc.moveDown(0.5);

  const votaciones = db.prepare(`SELECT * FROM votaciones_actas WHERE acta_id = ? ORDER BY numero ASC`).all(actaId);
  if (votaciones.length > 0) {
    doc.fontSize(10).font('Helvetica-Bold').text('III. VOTACIONES', 50);
    doc.fontSize(9).font('Helvetica');

    votaciones.forEach(v => {
      doc.text(`${v.numero}. ${v.titulo}`, 50);
      doc.text(`  A favor: ${v.votos_favor} | Contra: ${v.votos_contra} | Abstenciones: ${v.abstenciones}`, 50);
      doc.text(`  Resultado: ${v.resultado}`, 50);
      doc.moveDown(0.2);
    });
    doc.moveDown(0.5);
  }

  doc.fontSize(10).font('Helvetica-Bold').text('IV. FIRMAS', 50);
  doc.moveDown(1);

  const firmaY = doc.y;
  doc.fontSize(8).font('Helvetica').text('_____________________', 50, firmaY);
  doc.text('Presidente', 50, firmaY + 15);

  doc.text('_____________________', 200, firmaY);
  doc.text('Secretario', 200, firmaY + 15);

  doc.text('_____________________', 350, firmaY);
  doc.text('Tesorero', 350, firmaY + 15);

  doc.moveDown(2);
  doc.fontSize(8).text('Se levanta acta siendo las ' + (acta.hora_cierre || '[Hora]') + ' horas.', { align: 'center' });
}

function generarPDFComite(doc, acta, actaId) {
  doc.fontSize(14).font('Helvetica-Bold').text('ACTA DE REUNIÓN DE COMITÉ', { align: 'center' });
  doc.moveDown(0.5);

  doc.fontSize(10).font('Helvetica');
  doc.text(`Fecha: ${new Date(acta.fecha_reunion).toLocaleDateString('es-CL')}`);
  doc.text(`Hora: ${acta.hora_inicio || '[Sin especificar]'} - ${acta.hora_cierre || '[Sin especificar]'}`);
  doc.text(`Lugar: ${acta.lugar || '[Sin especificar]'}`);
  doc.text(`Título: ${acta.titulo}`);
  doc.moveDown(0.5);

  const asistentes = db.prepare(`SELECT * FROM asistentes_actas WHERE acta_id = ? ORDER BY presente DESC, nombre ASC`).all(actaId);

  doc.fontSize(11).font('Helvetica-Bold').text('I. ASISTENTES', 50);
  doc.fontSize(9).font('Helvetica');

  doc.fontSize(8).font('Helvetica-Bold');
  doc.text('Nombre', 50, doc.y);
  doc.text('RUT', 250, doc.y);
  doc.text('Rol', 350, doc.y);
  doc.text('Presente', 450, doc.y);
  doc.moveDown(0.2);
  doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();

  doc.fontSize(8).font('Helvetica');
  asistentes.forEach(a => {
    doc.text(a.nombre.substring(0, 30), 50, doc.y);
    doc.text(a.rut, 250, doc.y - doc.currentLineHeight());
    doc.text(a.rol, 350, doc.y - doc.currentLineHeight());
    doc.text(a.presente ? 'Sí' : 'No', 450, doc.y - doc.currentLineHeight());
    doc.moveDown(0.25);
  });

  doc.moveDown(0.5);
  doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
  doc.moveDown(0.5);

  doc.fontSize(11).font('Helvetica-Bold').text('II. ORDEN DEL DÍA', 50);
  doc.fontSize(9).font('Helvetica');

  const temas = db.prepare(`SELECT * FROM temas_actas WHERE acta_id = ? ORDER BY numero ASC`).all(actaId);

  if (temas.length === 0) {
    doc.text('[Sin temas registrados]');
  } else {
    temas.forEach(t => {
      doc.fontSize(9).font('Helvetica-Bold').text(`Tema ${t.numero}: ${t.titulo}`, 50);
      doc.fontSize(8).font('Helvetica');
      if (t.descripcion) doc.text(`Descripción: ${t.descripcion.substring(0, 80)}...`, 50);
      if (t.conclusiones) doc.text(`Conclusiones: ${t.conclusiones.substring(0, 80)}...`, 50);
      if (t.acuerdos) doc.text(`Acuerdos: ${t.acuerdos.substring(0, 80)}...`, 50);
      if (t.responsable) doc.text(`Responsable: ${t.responsable}`, 50);
      if (t.fecha_limite) doc.text(`Fecha límite: ${t.fecha_limite}`, 50);
      doc.moveDown(0.3);
    });
  }

  doc.moveDown(0.5);

  doc.fontSize(10).font('Helvetica-Bold').text('III. FIRMAS', 50);
  doc.moveDown(1);

  const firmaY = doc.y;
  doc.fontSize(8).font('Helvetica').text('_____________________', 50, firmaY);
  doc.text('Presidente', 50, firmaY + 15);

  doc.text('_____________________', 200, firmaY);
  doc.text('Secretario', 200, firmaY + 15);

  doc.moveDown(2);
  doc.fontSize(8).text('Se levanta acta siendo las ' + (acta.hora_cierre || '[Hora]') + ' horas.', { align: 'center' });
}

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Comunité' });
});

export default app;
