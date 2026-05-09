import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client'; 
import bcrypt from 'bcryptjs'; 
import jwt from 'jsonwebtoken';
import { OAuth2Client } from 'google-auth-library';
import { Resend } from 'resend';
import 'dotenv/config';

import checkoutRoutes from './routes/checkout.routes.js';

// ==========================================
// 1. INICIALIZACIÓN Y CONFIGURACIÓN
// ==========================================
const app = express();
const prisma = new PrismaClient(); 
const PORT = process.env.PORT || 4000;

const resend = new Resend(process.env.RESEND_API_KEY);
const clienteGoogle = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// Configuración dinámica de CORS (Escudo de seguridad)
const origenesPermitidos = process.env.FRONTEND_URL 
  ? process.env.FRONTEND_URL.split(',') 
  : ['http://localhost:5173'];

app.use(cors({
  origin: origenesPermitidos,
  credentials: true
}));

app.use(express.json());
// 💡 CORRECCIÓN: Se eliminó la ruta duplicada del checkout que estaba aquí

// ==========================================
// 2. MIDDLEWARES DE SEGURIDAD
// ==========================================
const verificarToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Acceso denegado. No tienes un token válido.' });
  
  try {
    const tokenLimpio = token.replace('Bearer ', '');
    const verificado = jwt.verify(tokenLimpio, process.env.JWT_SECRET);
    req.comercio = verificado;
    next();
  } catch (error) {
    res.status(401).json({ error: 'El token ha expirado o es inválido.' });
  }
};

const verificarApiKey = async (req, res, next) => {
  const apiKey = req.header('x-api-key'); 
  if (!apiKey) return res.status(401).json({ error: 'Acceso denegado. Falta la API Key.' });

  try {
    const comercio = await prisma.comercio.findUnique({ where: { api_key: apiKey } });
    if (!comercio) return res.status(401).json({ error: 'API Key inválida o revocada.' });
    
    req.comercioId = comercio.id; 
    next();
  } catch (error) {
    res.status(500).json({ error: 'Error validando credenciales de seguridad.' });
  }
};

// ==========================================
// 3. RUTAS DE AUTENTICACIÓN (LOGIN/REGISTRO)
// ==========================================

app.post('/api/registro', async (req, res) => {
 const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
  
  if (!passwordRegex.test(req.body.password)) {
    return res.status(400).json({ error: 'Contraseña muy débil o con caracteres no permitidos.' });
  }

  try {
    const { comercio, email, password } = req.body;
    
    const comercioExistente = await prisma.comercio.findUnique({ where: { email } });
    if (comercioExistente) return res.status(400).json({ error: 'Este correo ya está registrado.' });

    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);
    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();

    await prisma.comercio.create({
      data: {
        nombre: comercio,
        email: email,
        password: passwordEncriptada,
        codigoVerificacion: codigoOTP,
        api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
      }
    });

    try {
      await resend.emails.send({
        from: 'Lumina Pay <soporte@luminapay.xyz>', 
        to: email,
        subject: '🛡️ Verifica tu cuenta en Lumina Pay',
        html: `<p>Tu código de verificación es: <strong>${codigoOTP}</strong></p>`
      });
    } catch (e) { console.error("Error enviando correo silencioso"); }

    res.status(201).json({ mensaje: 'Comercio creado. Revisa tu correo.' });
  } catch (error) {
    res.status(500).json({ error: 'Error interno al registrar el comercio.' });
  }
}); 


app.post('/api/verificar', async (req, res) => {
  try {
    const { email, codigo } = req.body;
    const comercio = await prisma.comercio.findUnique({ where: { email } });
    
    if (!comercio) return res.status(404).json({ error: 'Comercio no encontrado.' });
    if (comercio.verificado) return res.status(400).json({ error: 'Cuenta ya verificada.' });
    if (comercio.codigoVerificacion !== codigo) return res.status(400).json({ error: 'Código incorrecto.' });

    await prisma.comercio.update({
      where: { email },
      data: { verificado: true, codigoVerificacion: null }
    });

    res.status(200).json({ mensaje: '¡Cuenta verificada con éxito!' });
  } catch (error) {
    res.status(500).json({ error: 'Error al verificar la cuenta.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const comercio = await prisma.comercio.findUnique({ where: { email } });

    if (!comercio || !(await bcrypt.compare(password, comercio.password))) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    if (!comercio.verificado) {
      return res.status(403).json({ error: 'Cuenta no verificada.', requiereVerificacion: true });
    }

    
    const token = jwt.sign({ id: comercio.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({
      mensaje: 'Login exitoso', token, 
      comercio: { id: comercio.id, nombre: comercio.nombre, email: comercio.email }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error en el servidor al iniciar sesión.' });
  }
});

app.post('/api/login/google', async (req, res) => {
  try {
    const { token } = req.body;
    const ticket = await clienteGoogle.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });
    
    const payload = ticket.getPayload();
    let comercio = await prisma.comercio.findUnique({ where: { email: payload.email } });

    if (!comercio) {
      const salt = await bcrypt.genSalt(10);
      const passwordAleatoria = await bcrypt.hash(Math.random().toString(36).slice(-12), salt);
      comercio = await prisma.comercio.create({
        data: {
          nombre: payload.name, email: payload.email, password: passwordAleatoria,
          verificado: true, api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
        }
      });
    }

    const tokenLumina = jwt.sign({ id: comercio.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({
      mensaje: 'Login con Google exitoso', token: tokenLumina,
      comercio: { id: comercio.id, nombre: comercio.nombre, email: comercio.email }
    });
  } catch (error) {
    res.status(401).json({ error: 'Token de Google inválido.' });
  }
});

app.post('/api/login/github', async (req, res) => {
  try {
    const { code } = req.body;
    const tokenRes = await fetch('https://github.com/login/oauth/access_token', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Accept': 'application/json' },
      body: JSON.stringify({
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code
      })
    });
    const { access_token } = await tokenRes.json();
    if (!access_token) return res.status(400).json({ error: 'Código de GitHub inválido.' });

    const userRes = await fetch('https://api.github.com/user', { headers: { 'Authorization': `Bearer ${access_token}` } });
    const userData = await userRes.json();

    const emailsRes = await fetch('https://api.github.com/user/emails', { headers: { 'Authorization': `Bearer ${access_token}` } });
    const emails = await emailsRes.json();
    const primaryEmail = emails.find(e => e.primary && e.verified)?.email || emails[0]?.email;

    if (!primaryEmail) return res.status(400).json({ error: 'No pudimos obtener tu correo de GitHub.' });

    let comercio = await prisma.comercio.findUnique({ where: { email: primaryEmail } });
    if (!comercio) {
      const salt = await bcrypt.genSalt(10);
      const passwordAleatoria = await bcrypt.hash(Math.random().toString(36).slice(-12), salt);
      comercio = await prisma.comercio.create({
        data: {
          nombre: userData.name || userData.login, email: primaryEmail, password: passwordAleatoria,
          verificado: true, api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
        }
      });
    }

    const tokenLumina = jwt.sign({ id: comercio.id }, process.env.JWT_SECRET, { expiresIn: '24h' });
    res.status(200).json({
      mensaje: 'Login con GitHub exitoso', token: tokenLumina,
      comercio: { id: comercio.id, nombre: comercio.nombre, email: comercio.email }
    });
  } catch (error) {
    res.status(500).json({ error: 'Error conectando con GitHub.' });
  }
});

// ==========================================
// 4. RUTAS DEL PANEL DEL COMERCIO
// ==========================================

app.get('/api/comercio/:id', verificarToken, async (req, res) => {
  try {
    const comercio = await prisma.comercio.findUnique({
      where: { id: req.params.id },
      select: { 
        id: true, nombre: true, email: true, api_key: true, url_webhook: true, 
        wallet_usdt: true, pago_movil_cedula: true, pago_movil_banco: true, 
        pago_movil_tel: true, zelle_email: true, zinli_email: true, paypal_client_id: true,
        telegram_chat_id: true, plan_actual: true, createdAt: true 
      }
    });
    res.status(200).json(comercio);
  } catch (error) { res.status(500).json({ error: 'Error al buscar el comercio.' }); }
});

// 💡 CORRECCIÓN: Rutas PUT fusionadas para guardar TODOS los datos (incluyendo Telegram)
app.put('/api/comercio/:id/config', verificarToken, async (req, res) => {
  const { id } = req.params;
  
  const { 
    url_webhook, wallet_usdt, pago_movil_cedula, pago_movil_banco, 
    pago_movil_tel, zelle_email, zinli_email, 
    paypal_client_id, telegram_chat_id 
  } = req.body;

  try {
    const comercio = await prisma.comercio.update({
      where: { id },
      data: {
        url_webhook, wallet_usdt, pago_movil_cedula, pago_movil_banco,
        pago_movil_tel, zelle_email, zinli_email,
        paypal_client_id, telegram_chat_id
      }
    });
    res.status(200).json({ mensaje: 'Configuración guardada exitosamente', comercio });
  } catch (error) {
    console.error("Error al guardar config:", error);
    res.status(500).json({ error: 'No se pudo actualizar la configuración' });
  }
});

app.get('/api/pagos/:comercioId', verificarToken, async (req, res) => {
  try {
    const transacciones = await prisma.transaccion.findMany({
      where: { comercioId: req.params.comercioId },
      orderBy: { fecha: 'desc' }
    });
    res.status(200).json(transacciones);
  } catch (error) { res.status(500).json({ error: 'Error al buscar historial.' }); }
});

app.put('/api/pagos/:id/estado', verificarToken, async (req, res) => {
  try {
    const { estado } = req.body; 
    
    // 1. Actualizamos la transacción y traemos los datos del comercio
    const transaccion = await prisma.transaccion.update({
      where: { id: req.params.id },
      data: { estado: estado },
      include: { comercio: true }
    });

    // 2. 🚀 LÓGICA DE SUSCRIPCIONES (Al cliente correcto)
    if (estado === 'aprobado' && transaccion.referenciaComercio && transaccion.referenciaComercio.startsWith('SUB-')) {
      const textoRef = transaccion.referenciaComercio;
      const sinPrefijo = textoRef.replace('SUB-', ''); 
      const ultimoGuion = sinPrefijo.lastIndexOf('-'); 
      const idClienteReal = sinPrefijo.substring(0, ultimoGuion); 
      
      const desc = transaccion.descripcion ? transaccion.descripcion.toLowerCase() : '';
      let nuevoPlan = 'starter';
      if (desc.includes('pro')) nuevoPlan = 'pro';
      if (desc.includes('business')) nuevoPlan = 'business';

      await prisma.comercio.update({
        where: { id: idClienteReal },
        data: { plan_actual: nuevoPlan }
      });
      console.log(`✅ [Lumina SaaS] Plan ${nuevoPlan.toUpperCase()} activado para cliente ID: ${idClienteReal}`);
    }

    // 3. 🛍️ NOTIFICACIÓN WEBHOOK (Dispara y Olvida)
    if (estado === 'aprobado' && transaccion.comercio && transaccion.comercio.url_webhook) {
      try {
        new URL(transaccion.comercio.url_webhook); 
        fetch(transaccion.comercio.url_webhook, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json', 
            'Authorization': `Bearer ${transaccion.comercio.api_key}` 
          },
          body: JSON.stringify({ evento: 'pago_exitoso', data: transaccion })
        }).catch(e => {}); 
      } catch (errorUrl) {
        console.log("⚠️ URL de webhook inválida. Se ignoró.");
      }
    }

   // 4. 📱 NOTIFICACIÓN POR TELEGRAM
    if (estado === 'aprobado' && transaccion.comercio.telegram_chat_id) {
      const tokenTelegram = process.env.TELEGRAM_TOKEN;
      const chatId = transaccion.comercio.telegram_chat_id;

      const mensaje = `
      💰 <b>¡Venta Confirmada!</b>
      --------------------------
      📦 <b>Producto:</b> ${transaccion.descripcion || 'Venta General'}
      💵 <b>Monto:</b> ${transaccion.monto} ${transaccion.moneda}
      💳 <b>Método:</b> ${transaccion.metodo.toUpperCase()}
      🔍 <b>Ref:</b> <code>${transaccion.referenciaComercio || transaccion.id.slice(0, 8)}</code>

      <i>Lumina Pay - Procesamiento en tiempo real</i> 🚀
            `;

      fetch(`https://api.telegram.org/bot${tokenTelegram}/sendMessage`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: chatId,
          text: mensaje,
          parse_mode: 'HTML'
        })
      }).catch(err => console.error("Error silencioso enviando a Telegram"));
    }

    // 5. Respondemos a tu página web INMEDIATAMENTE
    return res.status(200).json(transaccion);
    
  } catch (error) {
    console.error("🔥 Error crítico en la actualización:", error);
    return res.status(500).json({ error: 'Error al actualizar la transacción.' });
  }
});

// ==========================================
// RUTA PARA EDITAR EL PERFIL DE USUARIO
// ==========================================
app.put('/api/comercio/:id/perfil', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { nombre, nuevaPassword } = req.body;

  try {
    if (req.comercio.id !== id) {
      return res.status(403).json({ error: 'No tienes permiso para editar este perfil.' });
    }

    // 2. Preparamos los datos a actualizar
    const datosActualizados = {};
    
    if (nombre) {
      datosActualizados.nombre = nombre;
    }

    // 3. Si el usuario envió una nueva contraseña, la encriptamos antes de guardarla
    if (nuevaPassword) {
      const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
      if (!passwordRegex.test(nuevaPassword)) {
        return res.status(400).json({ error: 'La nueva contraseña es muy débil.' });
      }
      
      const salt = await bcrypt.genSalt(10);
      datosActualizados.password = await bcrypt.hash(nuevaPassword, salt);
    }

    // 4. Si no hay nada que actualizar, respondemos rápido
    if (Object.keys(datosActualizados).length === 0) {
      return res.status(400).json({ error: 'No se enviaron datos para actualizar.' });
    }

    // 5. Guardamos en la base de datos
    const comercioActualizado = await prisma.comercio.update({
      where: { id },
      data: datosActualizados,
      // 💡 IMPORTANTE: No devolvemos la contraseña en la respuesta
      select: { id: true, nombre: true, email: true } 
    });

    res.status(200).json({ 
      mensaje: 'Perfil actualizado con éxito', 
      comercio: comercioActualizado 
    });

  } catch (error) {
    console.error("Error al actualizar perfil:", error);
    res.status(500).json({ error: 'Error al actualizar el perfil.' });
  }
});

// ==========================================
// 5. RUTAS DE LA PASARELA DE PAGOS
// ==========================================
app.use('/api/checkout', checkoutRoutes); 


// ==========================================
// 6. RUTAS DE SÚPER ADMINISTRADOR (CENTRO DE MANDO)
// ==========================================

// 🛡️ GUARDIÁN: Solo el dueño de Lumina puede pasar
const verificarSuperAdmin = async (req, res, next) => {
  try {
    const admin = await prisma.comercio.findUnique({ where: { id: req.comercio.id } });
    
    const miCorreoAdmin = process.env.ADMIN_EMAIL; 

    if (admin.email !== miCorreoAdmin) {
      return res.status(403).json({ error: 'Acceso denegado. Solo el CEO puede entrar aquí.' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Error verificando permisos de administrador.' });
  }
};

// 👑 RUTA 1: Ver a todos los clientes registrados
app.get('/api/admin/comercios', verificarToken, verificarSuperAdmin, async (req, res) => {
  try {
    const comercios = await prisma.comercio.findMany({
      select: {
        id: true, 
        nombre: true, 
        email: true, 
        plan_actual: true, 
        verificado: true, 
        createdAt: true
      },
      orderBy: { createdAt: 'desc' } // Los más nuevos primero
    });
    res.status(200).json(comercios);
  } catch (error) {
    res.status(500).json({ error: 'Error al obtener la lista de clientes.' });
  }
});

// 👑 RUTA 2: Cambiar el plan de un cliente manualmente
app.put('/api/admin/comercios/:id/plan', verificarToken, verificarSuperAdmin, async (req, res) => {
  try {
    const { nuevoPlan } = req.body; // Puede ser 'starter', 'pro' o 'business'
    
    await prisma.comercio.update({
      where: { id: req.params.id },
      data: { plan_actual: nuevoPlan }
    });
    
    res.status(200).json({ mensaje: `Plan del usuario actualizado a ${nuevoPlan.toUpperCase()}` });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar el plan en la base de datos.' });
  }
});

// ==========================================
// 7. RUTAS DE RECUPERACIÓN DE CONTRASEÑA
// ==========================================

// 📩 Paso 1: Solicitar código de recuperación
app.post('/api/recuperar-password', async (req, res) => {
  const { email } = req.body;
  try {
    const comercio = await prisma.comercio.findUnique({ where: { email } });
    
    // Por seguridad, no revelamos si el correo existe o no, pero damos mensaje de éxito
    if (!comercio) {
      return res.status(200).json({ mensaje: 'Si el correo existe, recibirás un código pronto.' });
    }

    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();
    
    await prisma.comercio.update({
      where: { email },
      data: { codigoVerificacion: codigoOTP }
    });

    try {
      await resend.emails.send({
        from: 'Lumina Pay <soporte@luminapay.xyz>', 
        to: email,
        subject: '🔐 Recuperación de Contraseña - Lumina Pay',
        html: `
          <h2>Recuperación de cuenta</h2>
          <p>Hola ${comercio.nombre},</p>
          <p>Tu código de seguridad para restablecer tu contraseña es: <strong>${codigoOTP}</strong></p>
          <p>Si no solicitaste este cambio, ignora este correo. Tu cuenta está segura.</p>
        `
      });
    } catch (e) { console.error("Error silencioso al enviar correo de recuperación."); }

    res.status(200).json({ mensaje: 'Código enviado al correo.' });
  } catch (error) {
    res.status(500).json({ error: 'Error interno del servidor.' });
  }
});

// 🔑 Paso 2: Validar código y crear nueva contraseña
app.post('/api/reset-password', async (req, res) => {
  const { email, codigo, nuevaPassword } = req.body;

  try {
    const comercio = await prisma.comercio.findUnique({ where: { email } });
    
    if (!comercio || comercio.codigoVerificacion !== codigo) {
      return res.status(400).json({ error: 'Código inválido o expirado.' });
    }

    // Usamos la Regex relajada para que no te dé problemas con caracteres especiales
    const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;
    if (!passwordRegex.test(nuevaPassword)) {
      return res.status(400).json({ error: 'La contraseña debe tener 8 caracteres, mayúscula, minúscula, número y símbolo.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(nuevaPassword, salt);

    await prisma.comercio.update({
      where: { email },
      data: { 
        password: passwordEncriptada,
        codigoVerificacion: null // Destruimos el código para que no se re-use
      }
    });

    res.status(200).json({ mensaje: 'Contraseña actualizada con éxito.' });
  } catch (error) {
    res.status(500).json({ error: 'Error al restablecer la contraseña.' });
  }
});

// ==========================================
//  ESTADO DEL SERVIDOR
// ==========================================
app.get('/api/status', (req, res) => { res.json({ empresa: 'Lumina', estado: 'Activo' }); });

app.listen(PORT, () => {
  console.log(`🚀 Servidor de Lumina corriendo en el puerto ${PORT}`);
});