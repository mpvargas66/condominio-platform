import express from 'express';
import cors from 'cors';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcryptjs';
import multer from 'multer';
import crypto from 'crypto';
import { Resend } from 'resend';
import supabase from '../supabase-client.js';

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-in-production';
const resend = new Resend(process.env.RESEND_API_KEY);

app.use(cors());
app.use(express.json({ limit: '10mb' }));

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }
});

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

// Middleware multi-tenant
const verificarComite = async (req, res, next) => {
  try {
    const comiteId = req.body.comite_id || req.query.comite_id || req.params.comite_id;

    if (!comiteId) {
      return res.status(400).json({ error: 'comite_id requerido' });
    }

    const { data: acceso } = await supabase
      .from('usuarios_comites')
      .select('id')
      .eq('usuario_id', req.usuarioId)
      .eq('comite_id', comiteId)
      .single();

    if (!acceso) {
      return res.status(403).json({ error: 'No tienes acceso a este comité' });
    }

    req.comiteId = parseInt(comiteId);
    next();
  } catch (error) {
    res.status(500).json({ error: error.message });
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

    // NUEVO: Obtener comités del usuario
    const { data: comites } = await supabase
      .from('comites')
      .select('id, nombre, usuarios_comites(rol)')
      .eq('usuarios_comites.usuario_id', usuario.id);

    const comitesFormatted = comites?.map(c => ({
      id: c.id,
      nombre: c.nombre,
      rol: c.usuarios_comites?.[0]?.rol || 'miembro'
    })) || [];

    const token = jwt.sign(
      { id: usuario.id, email, perfil: usuario.perfil },
      JWT_SECRET,
      { expiresIn: '7d' }
    );

    // ACTUALIZADO: Agregar comites a la respuesta
    res.json({
      success: true,
      token,
      usuario: {
        id: usuario.id,
        email,
        nombre: usuario.nombre,
        perfil: usuario.perfil,
        comites: comitesFormatted
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

// ========== INVITACIÓN DE USUARIOS ==========

// 1. POST /api/usuarios/:id/enviar-invitacion
app.post('/api/usuarios/:id/enviar-invitacion', verificarToken, async (req, res) => {
  try {
    if (req.usuarioPerfil !== 'admin') {
      return res.status(403).json({ error: 'Solo admins pueden enviar invitaciones' });
    }

    const { data: usuario, error: userError } = await supabase
      .from('usuarios')
      .select('id, email, nombre')
      .eq('id', req.params.id)
      .single();

    if (userError || !usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }

    // Generar token único
    const token = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + 7 * 24 * 60 * 60 * 1000); // 7 días

    // Guardar token en password_resets
    const { error: tokenError } = await supabase
      .from('password_resets')
      .insert({
        usuario_id: usuario.id,
        token,
        expires_at: expiresAt.toISOString(),
        usado: false
      });

    if (tokenError) throw tokenError;

    // Enviar email con Resend
    const setPasswordUrl = `${process.env.APP_URL || 'https://comunite.vercel.app'}/set-password?token=${token}`;

    await resend.emails.send({
      from: 'Comunité <noreply@comunite.app>',
      to: usuario.email,
      subject: '¡Bienvenido a Comunité! Completa tu registro',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto;">
          <h2>¡Hola ${usuario.nombre}!</h2>
          <p>Has sido invitado a Comunité, la plataforma digital para gobernanza de condominios.</p>

          <div style="background-color: #f3f4f6; padding: 20px; border-radius: 8px; margin: 20px 0;">
            <h3>Tus credenciales de acceso:</h3>
            <p><strong>Email:</strong> ${usuario.email}</p>
            <p><strong>Contraseña temporal:</strong> Se generó una contraseña temporal. Debes cambiarla al primer acceso.</p>
          </div>

          <p style="margin: 20px 0;">
            <a href="${setPasswordUrl}"
               style="display: inline-block; padding: 12px 30px; background-color: #6B21A8; color: white; text-decoration: none; border-radius: 6px; font-weight: bold;">
              Establecer mi contraseña
            </a>
          </p>

          <p>Este enlace expira en 7 días. Si no estableces tu contraseña en ese tiempo, solicita una nueva invitación.</p>

          <hr style="border: none; border-top: 1px solid #e5e7eb; margin: 30px 0;">

          <p style="color: #6b7280; font-size: 12px;">
            Si no solicitaste esta invitación, puedes ignorar este email.<br>
            Comunité - Gobernanza Digital para Condominios
          </p>
        </div>
      `
    });

    registrarAuditoria(req.usuarioId, 'enviar_invitacion', `Invitación enviada a ${usuario.email}`);
    res.json({ success: true, email_enviado: true });
  } catch (error) {
    console.error('Error enviando invitación:', error);
    res.status(500).json({ error: error.message });
  }
});

// 2. POST /api/auth/establecer-contrasena
app.post('/api/auth/establecer-contrasena', async (req, res) => {
  try {
    const { token, contrasena_nueva } = req.body;

    if (!token || !contrasena_nueva) {
      return res.status(400).json({ error: 'Token y contraseña requeridos' });
    }

    if (contrasena_nueva.length < 6) {
      return res.status(400).json({ error: 'Contraseña debe tener al menos 6 caracteres' });
    }

    // Validar token
    const { data: resetToken, error: tokenError } = await supabase
      .from('password_resets')
      .select('usuario_id, expires_at, usado')
      .eq('token', token)
      .single();

    if (tokenError || !resetToken) {
      return res.status(401).json({ error: 'Token inválido' });
    }

    if (resetToken.usado) {
      return res.status(401).json({ error: 'Token ya fue utilizado' });
    }

    if (new Date(resetToken.expires_at) < new Date()) {
      return res.status(401).json({ error: 'Token expirado' });
    }

    // Hashear nueva contraseña
    const hashedPassword = await bcrypt.hash(contrasena_nueva, 10);

    // Actualizar contraseña del usuario
    const { error: updateError } = await supabase
      .from('usuarios')
      .update({ contrasena: hashedPassword })
      .eq('id', resetToken.usuario_id);

    if (updateError) throw updateError;

    // Marcar token como usado
    const { error: markError } = await supabase
      .from('password_resets')
      .update({ usado: true })
      .eq('token', token);

    if (markError) throw markError;

    res.json({ success: true, mensaje: 'Contraseña establecida correctamente' });
  } catch (error) {
    console.error('Error estableciendo contraseña:', error);
    res.status(500).json({ error: error.message });
  }
});

// ========== ACTAS ==========

// ACTUALIZADO: Agregar verificarComite
app.get('/api/actas', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('actas')
      .select('*, usuarios(nombre)')
      .eq('comite_id', req.comiteId)  // NUEVO: filtro comite_id
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

// ACTUALIZADO: Agregar verificarComite
app.get('/api/actas/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: acta, error } = await supabase
      .from('actas')
      .select('*, usuarios(nombre)')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)  // NUEVO: filtro comite_id
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

// ACTUALIZADO: Agregar verificarComite y comite_id al insert
app.post('/api/actas', verificarToken, verificarComite, async (req, res) => {
  try {
    const { titulo, tipo, contenido, fecha_reunion, hora_inicio, hora_cierre, lugar } = req.body;

    if (!titulo) return res.status(400).json({ error: 'Título requerido' });

    const { data, error } = await supabase
      .from('actas')
      .insert({
        comite_id: req.comiteId,  // NUEVO: agregar comite_id
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

// ACTUALIZADO: Agregar verificarComite y filtro comite_id
app.put('/api/actas/:id', verificarToken, verificarComite, async (req, res) => {
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
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);  // NUEVO: filtro comite_id

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'editar_acta', `Acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ACTUALIZADO: Agregar verificarComite y filtro comite_id
app.delete('/api/actas/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { error } = await supabase
      .from('actas')
      .delete()
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);  // NUEVO: filtro comite_id

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_acta', `Acta ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== ASISTENTES ==========

// ACTUALIZADO: Agregar verificarComite
app.post('/api/actas/:id/asistentes', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite
app.get('/api/actas/:id/asistentes', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite
app.delete('/api/asistentes/:id', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite
app.post('/api/actas/:id/temas', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite
app.get('/api/actas/:id/temas', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite
app.put('/api/temas/:id', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite
app.delete('/api/temas/:id', verificarToken, verificarComite, async (req, res) => {
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

// ACTUALIZADO: Agregar verificarComite y comite_id al insert
app.post('/api/votaciones', verificarToken, verificarComite, async (req, res) => {
  try {
    const { titulo, descripcion, tipo, opciones } = req.body;
    if (!titulo || !opciones || opciones.length < 2) {
      return res.status(400).json({ error: 'Título y mínimo 2 opciones requeridas' });
    }

    const { data: votacion, error } = await supabase
      .from('votaciones')
      .insert({
        comite_id: req.comiteId,  // NUEVO: agregar comite_id
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

// ACTUALIZADO: Agregar verificarComite y filtro comite_id
app.get('/api/votaciones', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: votaciones, error } = await supabase
      .from('votaciones')
      .select('*, usuarios(nombre)')
      .eq('comite_id', req.comiteId)  // NUEVO: filtro comite_id
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

// ACTUALIZADO: Agregar verificarComite
app.get('/api/votaciones/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: votacion, error } = await supabase
      .from('votaciones')
      .select('*')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)  // NUEVO: filtro comite_id
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

// ACTUALIZADO: Agregar verificarComite
app.post('/api/votaciones/:id/votar', verificarToken, verificarComite, async (req, res) => {
  try {
    const { opcion_id } = req.body;
    if (!opcion_id) return res.status(400).json({ error: 'Opción requerida' });

    const { data: votacion } = await supabase
      .from('votaciones')
      .select('estado')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)  // NUEVO: filtro comite_id
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

// ACTUALIZADO: Agregar verificarComite
app.put('/api/votaciones/:id/cerrar', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: votacion } = await supabase
      .from('votaciones')
      .select('usuario_creador_id')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)  // NUEVO: filtro comite_id
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
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);  // NUEVO: filtro comite_id

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'cerrar_votacion', `Cerró votación ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ACTUALIZADO: Agregar verificarComite
app.delete('/api/votaciones/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: votacion } = await supabase
      .from('votaciones')
      .select('usuario_creador_id')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);  // NUEVO: filtro comite_id

    if (req.usuarioPerfil !== 'admin' && votacion?.usuario_creador_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    await supabase.from('votos_usuarios').delete().eq('votacion_id', req.params.id);
    await supabase.from('opciones_votacion').delete().eq('votacion_id', req.params.id);
    const { error } = await supabase.from('votaciones').delete().eq('id', req.params.id).eq('comite_id', req.comiteId);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_votacion', `Eliminó votación ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== DOCUMENTOS ==========

app.post('/api/documentos/upload', verificarToken, verificarComite, upload.single('archivo'), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'Archivo requerido' });
    }

    const { nombre, categoria, descripcion } = req.body;
    const archivo = req.file;

    if (!nombre || !categoria) {
      return res.status(400).json({ error: 'Nombre y categoría requeridos' });
    }

    const timestamp = Date.now();
    // Sanitizar nombre del archivo: solo alfanuméricos, guiones y puntos
    const extension = archivo.originalname.substring(archivo.originalname.lastIndexOf('.') + 1) || 'bin';
    const nombreSanitizado = archivo.originalname
      .substring(0, archivo.originalname.lastIndexOf('.'))
      .replace(/[^a-z0-9]/gi, '-')
      .toLowerCase();
    const archivoNombre = `${req.comiteId}/${timestamp}-${nombreSanitizado}.${extension}`;

    const { data: storageData, error: storageError } = await supabase.storage
      .from('documentos')
      .upload(archivoNombre, archivo.buffer, {
        contentType: archivo.mimetype
      });

    if (storageError) throw storageError;

    const { data: { publicUrl } } = supabase.storage
      .from('documentos')
      .getPublicUrl(archivoNombre);

    const { data: documento, error: dbError } = await supabase
      .from('documentos')
      .insert({
        nombre,
        categoria,
        descripcion: descripcion || '',
        archivo_url: publicUrl,
        archivo_nombre: archivo.originalname,
        tamaño: archivo.size,
        usuario_id: req.usuarioId,
        comite_id: req.comiteId
      })
      .select()
      .single();

    if (dbError) throw dbError;

    registrarAuditoria(req.usuarioId, 'subir_documento', `Documento: ${nombre}`);
    res.json({ success: true, id: documento.id, archivo_url: publicUrl });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/documentos', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data, error } = await supabase
      .from('documentos')
      .select('*, usuarios(nombre)')
      .eq('comite_id', req.comiteId)
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    const documentos = data.map(d => ({
      ...d,
      usuario_nombre: d.usuarios?.nombre || 'Desconocido'
    }));

    res.json(documentos);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/documentos/:id/descargar', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: documento, error } = await supabase
      .from('documentos')
      .select('*')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    if (error || !documento) {
      return res.status(404).json({ error: 'Documento no encontrado' });
    }

    res.json({ success: true, archivo_url: documento.archivo_url });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/documentos/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: documento } = await supabase
      .from('documentos')
      .select('usuario_id, archivo_nombre')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    if (req.usuarioPerfil !== 'admin' && documento?.usuario_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    if (documento?.archivo_nombre) {
      const archivoPath = `${req.comiteId}/${documento.archivo_nombre}`;
      await supabase.storage.from('documentos').remove([archivoPath]);
    }

    const { error: dbError } = await supabase
      .from('documentos')
      .delete()
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);

    if (dbError) throw dbError;

    registrarAuditoria(req.usuarioId, 'eliminar_documento', `Documento ${req.params.id}`);
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

// ========== PROYECTOS ==========

// 1. POST /api/proyectos - Crear proyecto
app.post('/api/proyectos', verificarToken, verificarComite, async (req, res) => {
  try {
    const { nombre, descripcion } = req.body;
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });

    const { data: proyecto, error: projError } = await supabase
      .from('proyectos')
      .insert({
        nombre,
        descripcion: descripcion || '',
        comite_id: req.comiteId,
        usuario_creador_id: req.usuarioId,
        estado: 'planificacion'
      })
      .select()
      .single();

    if (projError) throw projError;

    registrarAuditoria(req.usuarioId, 'crear_proyecto', `Proyecto: ${nombre}`);
    res.json({ success: true, id: proyecto.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. GET /api/proyectos - Listar proyectos del comité
app.get('/api/proyectos', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: proyectos, error } = await supabase
      .from('proyectos')
      .select('*, usuarios(nombre), proyecto_detalles(*)')
      .eq('comite_id', req.comiteId)
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    const result = proyectos.map(p => ({
      id: p.id,
      nombre: p.nombre,
      descripcion: p.descripcion,
      estado: p.estado,
      presupuesto_estimado: p.proyecto_detalles?.[0]?.presupuesto_estimado || 0,
      presupuesto_real: p.proyecto_detalles?.[0]?.presupuesto_real || 0,
      impacto: p.proyecto_detalles?.[0]?.impacto,
      inversion: p.proyecto_detalles?.[0]?.inversion,
      responsable_nombre: p.usuarios?.nombre,
      progreso: p.proyecto_detalles?.[0]?.progreso || 0
    }));

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. GET /api/proyectos/:id - Obtener proyecto completo
app.get('/api/proyectos/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: proyecto, error: projError } = await supabase
      .from('proyectos')
      .select('*, usuarios(nombre), proyecto_detalles(*)')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    if (projError) throw projError;

    const { data: gastos } = await supabase
      .from('proyecto_gastos')
      .select('*, usuarios(nombre)')
      .eq('proyecto_id', req.params.id);

    const { data: comentarios } = await supabase
      .from('proyecto_comentarios')
      .select('*, usuarios(nombre)')
      .eq('proyecto_id', req.params.id)
      .order('fecha_creacion', { ascending: false });

    const { data: historial } = await supabase
      .from('proyecto_historial')
      .select('*, usuarios(nombre)')
      .eq('proyecto_id', req.params.id)
      .order('fecha', { ascending: false });

    res.json({
      ...proyecto,
      gastos: gastos || [],
      comentarios: comentarios || [],
      historial: historial || []
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. PUT /api/proyectos/:id - Actualizar proyecto
app.put('/api/proyectos/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { estado, descripcion, presupuesto_estimado, presupuesto_real, impacto, inversion, responsable_id, progreso, beneficiarios_estimados } = req.body;

    // Obtener proyecto actual para comparar
    const { data: proyectoActual } = await supabase
      .from('proyectos')
      .select('*, proyecto_detalles(*)')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    // Actualizar proyecto base
    if (estado !== undefined || descripcion !== undefined) {
      const { error: updateError } = await supabase
        .from('proyectos')
        .update({
          ...(estado && { estado }),
          ...(descripcion && { descripcion })
        })
        .eq('id', req.params.id)
        .eq('comite_id', req.comiteId);

      if (updateError) throw updateError;
    }

    // Actualizar detalles
    if (presupuesto_estimado !== undefined || presupuesto_real !== undefined || impacto !== undefined || inversion !== undefined || progreso !== undefined || beneficiarios_estimados !== undefined) {
      const { error: detallError } = await supabase
        .from('proyecto_detalles')
        .update({
          ...(presupuesto_estimado !== undefined && { presupuesto_estimado }),
          ...(presupuesto_real !== undefined && { presupuesto_real }),
          ...(impacto && { impacto }),
          ...(inversion && { inversion }),
          ...(responsable_id && { responsable_id }),
          ...(progreso !== undefined && { progreso }),
          ...(beneficiarios_estimados !== undefined && { beneficiarios_estimados })
        })
        .eq('proyecto_id', req.params.id);

      if (detallError) throw detallError;
    }

    // Registrar cambios en historial
    const cambios = [];
    if (estado && estado !== proyectoActual.estado) cambios.push({ campo: 'estado', anterior: proyectoActual.estado, nuevo: estado });
    if (descripcion && descripcion !== proyectoActual.descripcion) cambios.push({ campo: 'descripcion', anterior: proyectoActual.descripcion, nuevo: descripcion });
    if (presupuesto_estimado !== undefined && presupuesto_estimado !== proyectoActual.proyecto_detalles?.[0]?.presupuesto_estimado) cambios.push({ campo: 'presupuesto_estimado', anterior: proyectoActual.proyecto_detalles?.[0]?.presupuesto_estimado, nuevo: presupuesto_estimado });
    if (presupuesto_real !== undefined && presupuesto_real !== proyectoActual.proyecto_detalles?.[0]?.presupuesto_real) cambios.push({ campo: 'presupuesto_real', anterior: proyectoActual.proyecto_detalles?.[0]?.presupuesto_real, nuevo: presupuesto_real });
    if (progreso !== undefined && progreso !== proyectoActual.proyecto_detalles?.[0]?.progreso) cambios.push({ campo: 'progreso', anterior: proyectoActual.proyecto_detalles?.[0]?.progreso, nuevo: progreso });

    for (const cambio of cambios) {
      await supabase.from('proyecto_historial').insert({
        proyecto_id: req.params.id,
        usuario_id: req.usuarioId,
        campo_cambio: cambio.campo,
        valor_anterior: String(cambio.anterior),
        valor_nuevo: String(cambio.nuevo)
      });
    }

    registrarAuditoria(req.usuarioId, 'actualizar_proyecto', `Proyecto ${req.params.id}: ${cambios.length} cambios`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. DELETE /api/proyectos/:id - Eliminar proyecto
app.delete('/api/proyectos/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: proyecto } = await supabase
      .from('proyectos')
      .select('usuario_creador_id')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    if (req.usuarioPerfil !== 'admin' && proyecto?.usuario_creador_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    await supabase.from('proyecto_gastos').delete().eq('proyecto_id', req.params.id);
    await supabase.from('proyecto_comentarios').delete().eq('proyecto_id', req.params.id);
    await supabase.from('proyecto_historial').delete().eq('proyecto_id', req.params.id);
    await supabase.from('proyecto_detalles').delete().eq('proyecto_id', req.params.id);

    const { error } = await supabase
      .from('proyectos')
      .delete()
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_proyecto', `Proyecto ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. POST /api/proyectos/:id/gastos - Crear gasto
app.post('/api/proyectos/:id/gastos', verificarToken, verificarComite, async (req, res) => {
  try {
    const { concepto, monto, fecha_gasto, respaldo_nombre, respaldo_url } = req.body;

    if (!concepto || !monto) {
      return res.status(400).json({ error: 'Concepto y monto requeridos' });
    }

    const { data: gasto, error: gastoError } = await supabase
      .from('proyecto_gastos')
      .insert({
        proyecto_id: req.params.id,
        usuario_id: req.usuarioId,
        concepto,
        monto,
        fecha_gasto: fecha_gasto || new Date().toISOString(),
        respaldo_nombre,
        respaldo_url
      })
      .select()
      .single();

    if (gastoError) throw gastoError;

    // Actualizar presupuesto_real
    const { data: detalles } = await supabase
      .from('proyecto_detalles')
      .select('presupuesto_real')
      .eq('proyecto_id', req.params.id)
      .single();

    const nuevoPresupuesto = (detalles?.presupuesto_real || 0) + monto;
    await supabase
      .from('proyecto_detalles')
      .update({ presupuesto_real: nuevoPresupuesto })
      .eq('proyecto_id', req.params.id);

    registrarAuditoria(req.usuarioId, 'agregar_gasto', `Gasto: ${concepto} - ${monto}`);
    res.json({ success: true, id: gasto.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. GET /api/proyectos/:id/gastos - Listar gastos
app.get('/api/proyectos/:id/gastos', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: gastos, error } = await supabase
      .from('proyecto_gastos')
      .select('*, usuarios(nombre)')
      .eq('proyecto_id', req.params.id)
      .order('fecha_gasto', { ascending: false });

    if (error) throw error;

    res.json(gastos.map(g => ({
      id: g.id,
      concepto: g.concepto,
      monto: g.monto,
      fecha_gasto: g.fecha_gasto,
      usuario_nombre: g.usuarios?.nombre,
      respaldo_url: g.respaldo_url
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 8. DELETE /api/proyectos/:id/gastos/:gasto_id - Eliminar gasto
app.delete('/api/proyectos/:id/gastos/:gasto_id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: gasto } = await supabase
      .from('proyecto_gastos')
      .select('monto, usuario_id')
      .eq('id', req.params.gasto_id)
      .single();

    if (req.usuarioPerfil !== 'admin' && gasto?.usuario_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    // Restar del presupuesto_real
    const { data: detalles } = await supabase
      .from('proyecto_detalles')
      .select('presupuesto_real')
      .eq('proyecto_id', req.params.id)
      .single();

    const nuevoPresupuesto = Math.max(0, (detalles?.presupuesto_real || 0) - gasto.monto);
    await supabase
      .from('proyecto_detalles')
      .update({ presupuesto_real: nuevoPresupuesto })
      .eq('proyecto_id', req.params.id);

    const { error } = await supabase
      .from('proyecto_gastos')
      .delete()
      .eq('id', req.params.gasto_id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_gasto', `Gasto ${req.params.gasto_id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 9. POST /api/proyectos/:id/comentarios - Crear comentario
app.post('/api/proyectos/:id/comentarios', verificarToken, verificarComite, async (req, res) => {
  try {
    const { contenido } = req.body;

    if (!contenido) {
      return res.status(400).json({ error: 'Contenido requerido' });
    }

    const { data: comentario, error: comentError } = await supabase
      .from('proyecto_comentarios')
      .insert({
        proyecto_id: req.params.id,
        usuario_id: req.usuarioId,
        contenido
      })
      .select()
      .single();

    if (comentError) throw comentError;

    registrarAuditoria(req.usuarioId, 'comentar_proyecto', `Proyecto ${req.params.id}`);
    res.json({ success: true, id: comentario.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 10. GET /api/proyectos/:id/comentarios - Listar comentarios
app.get('/api/proyectos/:id/comentarios', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: comentarios, error } = await supabase
      .from('proyecto_comentarios')
      .select('*, usuarios(nombre)')
      .eq('proyecto_id', req.params.id)
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    res.json(comentarios.map(c => ({
      id: c.id,
      usuario_nombre: c.usuarios?.nombre,
      contenido: c.contenido,
      fecha_creacion: c.fecha_creacion
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 11. DELETE /api/proyectos/:id/comentarios/:comentario_id - Eliminar comentario
app.delete('/api/proyectos/:id/comentarios/:comentario_id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: comentario } = await supabase
      .from('proyecto_comentarios')
      .select('usuario_id')
      .eq('id', req.params.comentario_id)
      .single();

    if (req.usuarioPerfil !== 'admin' && comentario?.usuario_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    const { error } = await supabase
      .from('proyecto_comentarios')
      .delete()
      .eq('id', req.params.comentario_id);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_comentario', `Comentario ${req.params.comentario_id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 12. GET /api/proyectos/:id/historial - Listar historial
app.get('/api/proyectos/:id/historial', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: historial, error } = await supabase
      .from('proyecto_historial')
      .select('*, usuarios(nombre)')
      .eq('proyecto_id', req.params.id)
      .order('fecha', { ascending: false });

    if (error) throw error;

    res.json(historial.map(h => ({
      id: h.id,
      usuario_nombre: h.usuarios?.nombre,
      campo_cambio: h.campo_cambio,
      valor_anterior: h.valor_anterior,
      valor_nuevo: h.valor_nuevo,
      fecha: h.fecha
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== CHECKLISTS ==========

// HELPER: Calcular progreso del checklist
async function recalcularProgresoChecklist(checklistId) {
  const { data: items } = await supabase
    .from('checklist_items')
    .select('completado')
    .eq('checklist_id', checklistId);

  if (!items || items.length === 0) {
    await supabase.from('checklists').update({ progreso: 0 }).eq('id', checklistId);
    return 0;
  }

  const completados = items.filter(i => i.completado).length;
  const progreso = Math.round((completados / items.length) * 100);

  await supabase.from('checklists').update({ progreso }).eq('id', checklistId);
  return progreso;
}

// 1. POST /api/checklists - Crear checklist
app.post('/api/checklists', verificarToken, verificarComite, async (req, res) => {
  try {
    const { nombre, descripcion, fecha_vencimiento } = req.body;
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });

    const { data: checklist, error } = await supabase
      .from('checklists')
      .insert({
        nombre,
        descripcion: descripcion || '',
        fecha_vencimiento,
        comite_id: req.comiteId,
        usuario_creador_id: req.usuarioId,
        estado: 'pendiente',
        progreso: 0
      })
      .select()
      .single();

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'crear_checklist', `Checklist: ${nombre}`);
    res.json({ success: true, id: checklist.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 2. GET /api/checklists - Listar checklists del comité
app.get('/api/checklists', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: checklists, error } = await supabase
      .from('checklists')
      .select('*')
      .eq('comite_id', req.comiteId)
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    const result = await Promise.all(checklists.map(async (c) => {
      const { data: items } = await supabase
        .from('checklist_items')
        .select('completado')
        .eq('checklist_id', c.id);

      return {
        id: c.id,
        nombre: c.nombre,
        estado: c.estado,
        progreso: c.progreso,
        fecha_vencimiento: c.fecha_vencimiento,
        responsables_count: items ? items.length : 0,
        completados_count: items ? items.filter(i => i.completado).length : 0
      };
    }));

    res.json(result);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 3. GET /api/checklists/:id - Obtener checklist con items
app.get('/api/checklists/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: checklist, error: checklistError } = await supabase
      .from('checklists')
      .select('*')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    if (checklistError) throw checklistError;

    const { data: items } = await supabase
      .from('checklist_items')
      .select('*, usuarios(nombre)')
      .eq('checklist_id', req.params.id)
      .order('orden', { ascending: true });

    res.json({
      ...checklist,
      items: items ? items.map(i => ({
        ...i,
        responsable_nombre: i.usuarios?.nombre
      })) : []
    });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 4. PUT /api/checklists/:id - Actualizar checklist
app.put('/api/checklists/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { estado, fecha_vencimiento, nombre, descripcion } = req.body;

    const { error } = await supabase
      .from('checklists')
      .update({
        ...(estado && { estado }),
        ...(fecha_vencimiento && { fecha_vencimiento }),
        ...(nombre && { nombre }),
        ...(descripcion && { descripcion })
      })
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'actualizar_checklist', `Checklist ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 5. DELETE /api/checklists/:id - Eliminar checklist
app.delete('/api/checklists/:id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: checklist } = await supabase
      .from('checklists')
      .select('creador_id')
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId)
      .single();

    if (req.usuarioPerfil !== 'admin' && checklist?.creador_id !== req.usuarioId) {
      return res.status(403).json({ error: 'No tienes permiso' });
    }

    await supabase.from('checklist_items').delete().eq('checklist_id', req.params.id);
    const { error } = await supabase
      .from('checklists')
      .delete()
      .eq('id', req.params.id)
      .eq('comite_id', req.comiteId);

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'eliminar_checklist', `Checklist ${req.params.id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 6. POST /api/checklists/:id/items - Agregar item
app.post('/api/checklists/:id/items', verificarToken, verificarComite, async (req, res) => {
  try {
    const { titulo, descripcion, responsable_id, orden } = req.body;
    if (!titulo) return res.status(400).json({ error: 'Título requerido' });

    const { data: item, error } = await supabase
      .from('checklist_items')
      .insert({
        checklist_id: req.params.id,
        titulo,
        descripcion: descripcion || '',
        responsable_id,
        orden: orden || 0,
        completado: false
      })
      .select()
      .single();

    if (error) throw error;

    await recalcularProgresoChecklist(req.params.id);

    registrarAuditoria(req.usuarioId, 'agregar_item_checklist', `Item: ${titulo}`);
    res.json({ success: true, id: item.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 7. GET /api/checklists/:id/items - Listar items
app.get('/api/checklists/:id/items', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: items, error } = await supabase
      .from('checklist_items')
      .select('*, usuarios(nombre)')
      .eq('checklist_id', req.params.id)
      .order('orden', { ascending: true });

    if (error) throw error;

    res.json(items.map(i => ({
      id: i.id,
      titulo: i.titulo,
      descripcion: i.descripcion,
      responsable_nombre: i.usuarios?.nombre,
      completado: i.completado,
      fecha_completado: i.fecha_completado,
      orden: i.orden
    })));
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 8. PUT /api/checklists/:id/items/:item_id - Actualizar item
app.put('/api/checklists/:id/items/:item_id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { completado, responsable_id, descripcion } = req.body;

    const updateData = {
      ...(completado !== undefined && { completado }),
      ...(responsable_id && { responsable_id }),
      ...(descripcion && { descripcion })
    };

    if (completado === true) {
      updateData.fecha_completado = new Date().toISOString();
    } else if (completado === false) {
      updateData.fecha_completado = null;
    }

    const { error } = await supabase
      .from('checklist_items')
      .update(updateData)
      .eq('id', req.params.item_id);

    if (error) throw error;

    await recalcularProgresoChecklist(req.params.id);

    registrarAuditoria(req.usuarioId, 'actualizar_item_checklist', `Item ${req.params.item_id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 9. DELETE /api/checklists/:id/items/:item_id - Eliminar item
app.delete('/api/checklists/:id/items/:item_id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { error } = await supabase
      .from('checklist_items')
      .delete()
      .eq('id', req.params.item_id);

    if (error) throw error;

    await recalcularProgresoChecklist(req.params.id);

    registrarAuditoria(req.usuarioId, 'eliminar_item_checklist', `Item ${req.params.item_id}`);
    res.json({ success: true });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 10. POST /api/checklist-templates - Crear template
app.post('/api/checklist-templates', verificarToken, verificarComite, async (req, res) => {
  try {
    const { nombre, descripcion, recurrencia } = req.body;
    if (!nombre) return res.status(400).json({ error: 'Nombre requerido' });

    const { data: template, error } = await supabase
      .from('checklist_templates')
      .insert({
        nombre,
        descripcion: descripcion || '',
        recurrencia: recurrencia || 'manual',
        comite_id: req.comiteId,
        creador_id: req.usuarioId
      })
      .select()
      .single();

    if (error) throw error;

    registrarAuditoria(req.usuarioId, 'crear_template_checklist', `Template: ${nombre}`);
    res.json({ success: true, id: template.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 11. GET /api/checklist-templates - Listar templates
app.get('/api/checklist-templates', verificarToken, verificarComite, async (req, res) => {
  try {
    const { data: templates, error } = await supabase
      .from('checklist_templates')
      .select('*')
      .eq('comite_id', req.comiteId)
      .order('fecha_creacion', { ascending: false });

    if (error) throw error;

    res.json(templates);
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// 12. POST /api/checklists/from-template/:template_id - Crear desde template
app.post('/api/checklists/from-template/:template_id', verificarToken, verificarComite, async (req, res) => {
  try {
    const { nombre, fecha_vencimiento } = req.body;

    // Obtener template
    const { data: template, error: templateError } = await supabase
      .from('checklist_templates')
      .select('*')
      .eq('id', req.params.template_id)
      .eq('comite_id', req.comiteId)
      .single();

    if (templateError) throw templateError;

    // Crear checklist
    const { data: checklist, error: checklistError } = await supabase
      .from('checklists')
      .insert({
        nombre: nombre || template.nombre,
        descripcion: template.descripcion,
        fecha_vencimiento,
        comite_id: req.comiteId,
        usuario_creador_id: req.usuarioId,
        estado: 'pendiente',
        progreso: 0,
        template_id: req.params.template_id
      })
      .select()
      .single();

    if (checklistError) throw checklistError;

    // Copiar items del template
    const { data: templateItems } = await supabase
      .from('checklist_template_items')
      .select('*')
      .eq('template_id', req.params.template_id);

    if (templateItems && templateItems.length > 0) {
      const itemsToInsert = templateItems.map(ti => ({
        checklist_id: checklist.id,
        titulo: ti.titulo,
        descripcion: ti.descripcion,
        orden: ti.orden,
        completado: false
      }));

      await supabase.from('checklist_items').insert(itemsToInsert);
    }

    registrarAuditoria(req.usuarioId, 'crear_checklist_desde_template', `Template: ${template.nombre}`);
    res.json({ success: true, id: checklist.id });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// ========== HEALTH ==========

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', app: 'Comunité' });
});

export default app;
