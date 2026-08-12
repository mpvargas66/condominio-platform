import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import supabase from '../supabase-client.js';

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';

app.use(cors());
app.use(express.json({ limit: '10mb' }));

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

// Registrar en auditoría
async function registrarAuditoria(usuarioId, accion, detalles) {
  try {
    await supabase.from('auditoria').insert({
      usuario_id: usuarioId,
      accion,
      detalles
    });
  } catch (error) {
    console.error('Error auditoría:', error);
  }
}

// ========== AUTH ==========

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, contrasena } = req.body;

    const { data: usuario, error } = await supabase
      .from('usuarios')
      .select('*')
      .eq('email', email)
      .eq('activo', true)
      .single();

    if (error || !usuario || !bcrypt.compareSync(contrasena, usuario.contrasena)) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    const token = jwt.sign(
      { id: usuario.id, email, perfil: usuario.perfil },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      usuario: {
        id: usuario.id,
        email,
        nombre: usuario.nombre,
        perfil: usuario.perfil
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/auth/registro', async (req, res) => {
  try {
    const { nombre, email, contrasena } = req.body;
    if (!email || !contrasena || !nombre) {
      return res.status(400).json({ error: 'Campos requeridos faltantes' });
    }

    const passwordHash = bcrypt.hashSync(contrasena, 10);

    const { data, error } = await supabase
      .from('usuarios')
      .insert({
        email,
        contrasena: passwordHash,
        nombre,
        perfil: 'miembro'
      })
      .select()
      .single();

    if (error) {
      if (error.message.includes('duplicate')) {
        return res.status(400).json({ error: 'Email ya registrado' });
      }
      throw error;
    }

    const token = jwt.sign(
      { id: data.id, email, perfil: 'miembro' },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    res.json({
      success: true,
      token,
      usuario: {
        id: data.id,
        email,
        nombre,
        perfil: 'miembro'
      }
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== USUARIOS ==========

app.get('/api/usuarios', verificarToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('usuarios')
      .select('id, email, nombre, perfil, activo');

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/usuarios/:id', verificarToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('usuarios')
      .update({ activo: false })
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ACTAS ==========

app.get('/api/actas', verificarToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('actas')
      .select('*, usuarios(nombre)')
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    const actas = data.map(a => ({
      ...a,
      usuario_nombre: a.usuarios?.nombre || 'Desconocido'
    }));

    res.json(actas);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id', verificarToken, async (req, res) => {
  try {
    const { data: acta, error } = await supabase
      .from('actas')
      .select('*, usuarios(nombre)')
      .eq('id', req.params.id)
      .single();

    if (error || !acta) return res.status(404).json({ error: 'Acta no encontrada' });

    const { data: firmas } = await supabase
      .from('firmas_actas')
      .select('*, usuarios(nombre)')
      .eq('acta_id', req.params.id);

    res.json({ ...acta, firmas });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/actas', verificarToken, async (req, res) => {
  try {
    const { titulo, tipo, contenido, fecha_reunion, hora_inicio, hora_cierre, lugar } = req.body;

    if (!titulo) return res.status(400).json({ error: 'Título requerido' });

    const { data, error } = await supabase
      .from('actas')
      .insert({
        titulo,
        tipo: tipo || 'comite',
        contenido: contenido || '',
        fecha_reunion: fecha_reunion || new Date().toISOString().split('T')[0],
        hora_inicio,
        hora_cierre,
        lugar,
        usuario_id: req.usuarioId,
        estado: 'borrador'
      })
      .select()
      .single();

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'crear_acta', `Acta: ${titulo}`);
    res.json({ success: true, id: data.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/actas/:id', verificarToken, async (req, res) => {
  try {
    const { titulo, tipo, contenido, estado } = req.body;

    const { error } = await supabase
      .from('actas')
      .update({
        titulo,
        tipo,
        contenido,
        estado,
        fecha_actualizacion: new Date().toISOString()
      })
      .eq('id', req.params.id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'editar_acta', `Acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/actas/:id', verificarToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('actas')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_acta', `Acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ASISTENTES ==========

app.post('/api/actas/:id/asistentes', verificarToken, async (req, res) => {
  try {
    const { nombre, rut, rol, presente } = req.body;

    const { data, error } = await supabase
      .from('asistentes_actas')
      .insert({
        acta_id: req.params.id,
        nombre,
        rut,
        rol,
        presente: presente !== false
      })
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id/asistentes', verificarToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('asistentes_actas')
      .select('*')
      .eq('acta_id', req.params.id)
      .order('presente', { ascending: false })
      .order('nombre');

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/asistentes/:id', verificarToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('asistentes_actas')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== TEMAS ==========

app.post('/api/actas/:id/temas', verificarToken, async (req, res) => {
  try {
    const { numero, titulo } = req.body;

    const { data, error } = await supabase
      .from('temas_actas')
      .insert({
        acta_id: req.params.id,
        numero,
        titulo,
        estado: 'pendiente'
      })
      .select()
      .single();

    if (error) throw error;
    res.json({ success: true, id: data.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/actas/:id/temas', verificarToken, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('temas_actas')
      .select('*')
      .eq('acta_id', req.params.id)
      .order('numero');

    if (error) throw error;
    res.json(data);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/temas/:id', verificarToken, async (req, res) => {
  try {
    const { descripcion, conclusiones, observaciones, pendientes, acuerdos, responsable, fecha_limite, estado } = req.body;

    const { error } = await supabase
      .from('temas_actas')
      .update({
        descripcion,
        conclusiones,
        observaciones,
        pendientes,
        acuerdos,
        responsable,
        fecha_limite,
        estado,
        fecha_actualizacion: new Date().toISOString()
      })
      .eq('id', req.params.id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'actualizar_tema', 'Tema actualizado');
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/temas/:id', verificarToken, async (req, res) => {
  try {
    const { error } = await supabase
      .from('temas_actas')
      .delete()
      .eq('id', req.params.id);

    if (error) throw error;
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== VOTACIONES INDEPENDIENTES ==========

app.post('/api/votaciones', verificarToken, async (req, res) => {
  try {
    const { titulo, descripcion, tipo, opciones } = req.body;
    if (!titulo || !opciones || opciones.length < 2) {
      return res.status(400).json({ error: 'Título y mínimo 2 opciones requeridas' });
    }

    const { data: votacion, error } = await supabase
      .from('votaciones')
      .insert({
        titulo,
        descripcion: descripcion || '',
        tipo: tipo || 'abierta',
        usuario_creador_id: req.usuarioId,
        estado: 'abierta'
      })
      .select()
      .single();

    if (error) throw error;

    for (let i = 0; i < opciones.length; i++) {
      await supabase.from('opciones_votacion').insert({
        votacion_id: votacion.id,
        numero: i + 1,
        titulo: opciones[i]
      });
    }

    registrarAuditoria(req.usuarioId, 'crear_votacion', `Votación: ${titulo}`);
    res.json({ success: true, id: votacion.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/votaciones', verificarToken, async (req, res) => {
  try {
    const { data: votaciones, error } = await supabase
      .from('votaciones')
      .select('*, usuarios(nombre)')
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    const resultado = await Promise.all(votaciones.map(async (v) => {
      const { data: opciones } = await supabase
        .from('opciones_votacion')
        .select('*')
        .eq('votacion_id', v.id)
        .order('numero');

      const { data: miVoto } = await supabase
        .from('votos_usuarios')
        .select('opcion_id')
        .eq('votacion_id', v.id)
        .eq('usuario_id', req.usuarioId)
        .single();

      const opcionesConVotos = await Promise.all(opciones?.map(async (o) => {
        const { count } = await supabase
          .from('votos_usuarios')
          .select('*', { count: 'exact', head: true })
          .eq('opcion_id', o.id);
        return { ...o, cantidad_votos: count || 0 };
      }) || []);

      return {
        ...v,
        usuario_creador_nombre: v.usuarios?.nombre || 'Desconocido',
        opciones: opcionesConVotos,
        miVoto: miVoto?.opcion_id || null,
        total_votos: opcionesConVotos.reduce((sum, o) => sum + o.cantidad_votos, 0)
      };
    }));

    res.json(resultado);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/votaciones/:id', verificarToken, async (req, res) => {
  try {
    const { data: votacion, error } = await supabase
      .from('votaciones')
      .select('*')
      .eq('id', req.params.id)
      .single();

    if (error || !votacion) return res.status(404).json({ error: 'Votación no encontrada' });

    const { data: opciones } = await supabase
      .from('opciones_votacion')
      .select('*')
      .eq('votacion_id', req.params.id)
      .order('numero');

    const { data: miVoto } = await supabase
      .from('votos_usuarios')
      .select('opcion_id')
      .eq('votacion_id', req.params.id)
      .eq('usuario_id', req.usuarioId)
      .single();

    const opcionesConVotos = await Promise.all(opciones?.map(async (o) => {
      const { count } = await supabase
        .from('votos_usuarios')
        .select('*', { count: 'exact', head: true })
        .eq('opcion_id', o.id);
      return { ...o, cantidad_votos: count || 0 };
    }) || []);

    res.json({
      ...votacion,
      opciones: opcionesConVotos,
      miVoto: miVoto?.opcion_id || null
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/votaciones/:id/votar', verificarToken, async (req, res) => {
  try {
    const { opcion_id } = req.body;
    if (!opcion_id) return res.status(400).json({ error: 'Opción requerida' });

    const { data: votacion } = await supabase
      .from('votaciones')
      .select('estado')
      .eq('id', req.params.id)
      .single();

    if (votacion?.estado === 'cerrada') {
      return res.status(400).json({ error: 'Votación cerrada' });
    }

    const { data: votoExistente } = await supabase
      .from('votos_usuarios')
      .select('id')
      .eq('votacion_id', req.params.id)
      .eq('usuario_id', req.usuarioId)
      .single();

    if (votoExistente) {
      return res.status(400).json({ error: 'Ya has votado en esta votación' });
    }

    const { error } = await supabase
      .from('votos_usuarios')
      .insert({
        votacion_id: req.params.id,
        opcion_id,
        usuario_id: req.usuarioId
      });

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'votar', `Votó en votación ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/votaciones/:id/cerrar', verificarToken, async (req, res) => {
  try {
    const { data: votacion } = await supabase
      .from('votaciones')
      .select('usuario_creador_id')
      .eq('id', req.params.id)
      .single();

    if (req.usuarioPerfil !== 'admin' && votacion?.usuario_creador_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    const { error } = await supabase
      .from('votaciones')
      .update({
        estado: 'cerrada',
        fecha_cierre: new Date().toISOString()
      })
      .eq('id', req.params.id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'cerrar_votacion', `Cerró votación ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/votaciones/:id', verificarToken, async (req, res) => {
  try {
    const { data: votacion } = await supabase
      .from('votaciones')
      .select('usuario_creador_id')
      .eq('id', req.params.id)
      .single();

    if (req.usuarioPerfil !== 'admin' && votacion?.usuario_creador_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    await supabase.from('votos_usuarios').delete().eq('votacion_id', req.params.id);
    await supabase.from('opciones_votacion').delete().eq('votacion_id', req.params.id);
    const { error } = await supabase.from('votaciones').delete().eq('id', req.params.id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_votacion', `Eliminó votación ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== AUDITORIA ==========

app.get('/api/auditoria', verificarToken, async (req, res) => {
  try {
    if (req.usuarioPerfil !== 'admin') {
      return res.status(403).json({ error: 'Solo admin' });
    }

    const { data, error } = await supabase
      .from('auditoria')
      .select('*, usuarios(nombre)')
      .order('fecha', { ascending: false })
      .limit(100);

    if (error) throw error;

    const logs = data.map(log => ({
      ...log,
      nombre: log.usuarios?.nombre || 'Sistema'
    }));

    res.json(logs);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== HEALTH ==========

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Comunité' });
});

export default app;
