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
// 1. INICIALIZACIÓN, CONSTANTES Y CONFIGURACIÓN
// ==========================================
const app = express();
const prisma = new PrismaClient(); 
const PORT = process.env.PORT || 4000;

const resend = new Resend(process.env.RESEND_API_KEY);
const clienteGoogle = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// 💡 OPTIMIZACIÓN 1: Centralizamos la validación de contraseñas. 
// Ahora si quieres cambiarla en el futuro, solo modificas esta línea.
const PASSWORD_REGEX = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[\W_]).{8,}$/;

const origenesPermitidos = process.env.FRONTEND_URL 
  ? process.env.FRONTEND_URL.split(',') 
  : ['http://localhost:5173'];

app.use(cors({ origin: origenesPermitidos, credentials: true }));
app.use(express.json());

// ==========================================
// 2. MIDDLEWARES DE SEGURIDAD
// ==========================================
const verificarToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) return res.status(401).json({ error: 'Acceso denegado. No tienes un token válido.' });
  
  try {
    const tokenLimpio = token.replace('Bearer ', '');
    req.comercio = jwt.verify(tokenLimpio, process.env.JWT_SECRET);
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

// 🛡️ GUARDIÁN DE ADMIN (Optimizado)
const verificarSuperAdmin = async (req, res, next) => {
  try {
    const admin = await prisma.comercio.findUnique({ where: { id: req.comercio.id } });
    const miCorreoAdmin = process.env.ADMIN_EMAIL?.trim().toLowerCase(); 
    const correoUsuario = admin?.email?.trim().toLowerCase();

    if (correoUsuario !== miCorreoAdmin) {
      return res.status(403).json({ error: 'Acceso denegado. Solo el CEO puede entrar aquí.' });
    }
    next();
  } catch (error) {
    res.status(500).json({ error: 'Error verificando permisos.' });
  }
};

// ==========================================
// 3. RUTAS DE AUTENTICACIÓN Y RECUPERACIÓN
// ==========================================

app.post('/api/registro', async (req, res) => {
  if (!PASSWORD_REGEX.test(req.body.password)) {
    return res.status(400).json({ error: 'Contraseña muy débil o con caracteres no permitidos.' });
  }

  try {
    const { comercio, email, password } = req.body;
    
    if (await prisma.comercio.findUnique({ where: { email } })) {
      return res.status(400).json({ error: 'Este correo ya está registrado.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);
    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();

    await prisma.comercio.create({
      data: {
        nombre: comercio, email, password: passwordEncriptada,
        codigoVerificacion: codigoOTP, api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
      }
    });

    resend.emails.send({
      from: 'Lumina Pay <soporte@luminapay.xyz>', to: email,
      subject: '🛡️ Verifica tu cuenta en Lumina Pay',
      html: `<p>Tu código de verificación es: <strong>${codigoOTP}</strong></p>`
    }).catch(() => console.error("Error enviando correo"));

    res.status(201).json({ mensaje: 'Comercio creado. Revisa tu correo.' });
  } catch (error) { res.status(500).json({ error: 'Error al registrar comercio.' }); }
}); 

app.post('/api/verificar', async (req, res) => {
  try {
    const { email, codigo } = req.body;
    const comercio = await prisma.comercio.findUnique({ where: { email } });
    
    if (!comercio) return res.status(404).json({ error: 'Comercio no encontrado.' });
    if (comercio.verificado) return res.status(400).json({ error: 'Cuenta ya verificada.' });
    if (comercio.codigoVerificacion !== codigo) return res.status(400).json({ error: 'Código incorrecto.' });

    await prisma.comercio.update({
      where: { email }, data: { verificado: true, codigoVerificacion: null }
    });
    res.status(200).json({ mensaje: '¡Cuenta verificada con éxito!' });
  } catch (error) { res.status(500).json({ error: 'Error al verificar la cuenta.' }); }
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
    res.status(200).json({ mensaje: 'Login exitoso', token, comercio: { id: comercio.id, nombre: comercio.nombre, email: comercio.email } });
  } catch (error) { res.status(500).json({ error: 'Error al iniciar sesión.' }); }
});

// (Omití los logins de Google y Github por limpieza, asumo que ya los tienes controlados, si los necesitas déjalos igual).

app.post('/api/recuperar-password', async (req, res) => {
  try {
    const comercio = await prisma.comercio.findUnique({ where: { email: req.body.email } });
    if (!comercio) return res.status(200).json({ mensaje: 'Si el correo existe, recibirás un código pronto.' });

    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();
    await prisma.comercio.update({ where: { email: req.body.email }, data: { codigoVerificacion: codigoOTP } });

    resend.emails.send({
      from: 'Lumina Pay <soporte@luminapay.xyz>', to: req.body.email,
      subject: '🔐 Recuperación de Contraseña',
      html: `<p>Tu código de seguridad es: <strong>${codigoOTP}</strong></p>`
    }).catch(() => {});

    res.status(200).json({ mensaje: 'Código enviado al correo.' });
  } catch (error) { res.status(500).json({ error: 'Error del servidor.' }); }
});

app.post('/api/reset-password', async (req, res) => {
  try {
    const { email, codigo, nuevaPassword } = req.body;
    const comercio = await prisma.comercio.findUnique({ where: { email } });
    
    if (!comercio || comercio.codigoVerificacion !== codigo) return res.status(400).json({ error: 'Código inválido.' });
    if (!PASSWORD_REGEX.test(nuevaPassword)) return res.status(400).json({ error: 'Contraseña débil.' });

    const salt = await bcrypt.genSalt(10);
    await prisma.comercio.update({
      where: { email },
      data: { password: await bcrypt.hash(nuevaPassword, salt), codigoVerificacion: null }
    });
    res.status(200).json({ mensaje: 'Contraseña actualizada.' });
  } catch (error) { res.status(500).json({ error: 'Error al restablecer.' }); }
});

// ==========================================
// 4. RUTAS DEL PANEL DEL COMERCIO Y PAGOS
// ==========================================

app.get('/api/comercio/:id', verificarToken, async (req, res) => {
  try {
    const comercio = await prisma.comercio.findUnique({
      where: { id: req.params.id },
      select: { id: true, nombre: true, email: true, api_key: true, url_webhook: true, wallet_usdt: true, pago_movil_cedula: true, pago_movil_banco: true, pago_movil_tel: true, zelle_email: true, zinli_email: true, paypal_client_id: true, telegram_chat_id: true, plan_actual: true, createdAt: true }
    });
    res.status(200).json(comercio);
  } catch (error) { res.status(500).json({ error: 'Error al buscar el comercio.' }); }
});

app.put('/api/comercio/:id/config', verificarToken, async (req, res) => {
  try {
    const comercio = await prisma.comercio.update({
      where: { id: req.params.id }, data: req.body
    });
    res.status(200).json({ mensaje: 'Configuración guardada exitosamente', comercio });
  } catch (error) { res.status(500).json({ error: 'No se pudo actualizar la configuración' }); }
});

app.put('/api/comercio/:id/perfil', verificarToken, async (req, res) => {
  try {
    const { nombre, nuevaPassword } = req.body;
    if (req.comercio.id !== req.params.id) return res.status(403).json({ error: 'Sin permiso.' });

    const datosActualizados = {};
    if (nombre) datosActualizados.nombre = nombre;
    
    if (nuevaPassword) {
      if (!PASSWORD_REGEX.test(nuevaPassword)) return res.status(400).json({ error: 'Contraseña muy débil.' });
      datosActualizados.password = await bcrypt.hash(nuevaPassword, await bcrypt.genSalt(10));
    }

    if (Object.keys(datosActualizados).length === 0) return res.status(400).json({ error: 'Sin datos.' });

    const comercioActualizado = await prisma.comercio.update({
      where: { id: req.params.id }, data: datosActualizados,
      select: { id: true, nombre: true, email: true } 
    });
    res.status(200).json({ mensaje: 'Perfil actualizado', comercio: comercioActualizado });
  } catch (error) { res.status(500).json({ error: 'Error al actualizar perfil.' }); }
});

app.get('/api/pagos/:comercioId', verificarToken, async (req, res) => {
  try {
    const transacciones = await prisma.transaccion.findMany({
      where: { comercioId: req.params.comercioId }, orderBy: { fecha: 'desc' }
    });
    res.status(200).json(transacciones);
  } catch (error) { res.status(500).json({ error: 'Error al buscar historial.' }); }
});

app.put('/api/pagos/:id/estado', verificarToken, async (req, res) => {
  try {
    const { estado } = req.body; 
    const transaccion = await prisma.transaccion.update({
      where: { id: req.params.id }, data: { estado }, include: { comercio: true }
    });

    // 🚀 OPTIMIZACIÓN 2: LÓGICA DE SUSCRIPCIONES (Limpia y sin errores de UUID)
    if (estado === 'aprobado' && transaccion.referenciaComercio?.startsWith('SUB_')) {
      const nuevoPlan = transaccion.referenciaComercio.includes('BUSINESS') ? 'business' : 'pro';
      
      // ¡Usamos el ID directo del comercio que hizo la transacción!
      await prisma.comercio.update({
        where: { id: transaccion.comercioId },
        data: { plan_actual: nuevoPlan }
      });
      console.log(`✅ Plan ${nuevoPlan.toUpperCase()} activado automáticamente.`);
    }

    // 🛍️ NOTIFICACIÓN WEBHOOK
    if (estado === 'aprobado' && transaccion.comercio?.url_webhook) {
      fetch(transaccion.comercio.url_webhook, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${transaccion.comercio.api_key}` },
        body: JSON.stringify({ evento: 'pago_exitoso', data: transaccion })
      }).catch(() => {}); 
    }

   // 📱 NOTIFICACIÓN POR TELEGRAM
    if (estado === 'aprobado' && transaccion.comercio?.telegram_chat_id) {
      fetch(`https://api.telegram.org/bot${process.env.TELEGRAM_TOKEN}/sendMessage`, {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          chat_id: transaccion.comercio.telegram_chat_id, parse_mode: 'HTML',
          text: `💰 <b>¡Venta Confirmada!</b>\n💵 <b>Monto:</b> ${transaccion.monto} ${transaccion.moneda}`
        })
      }).catch(() => {});
    }

    return res.status(200).json(transaccion);
  } catch (error) { res.status(500).json({ error: 'Error al actualizar.' }); }
});

// ==========================================
// 5. PASARELA DE PAGOS Y SUSCRIPCIONES
// ==========================================
app.use('/api/checkout', checkoutRoutes); 

app.post('/api/suscripcion/generar', verificarToken, async (req, res) => {
  const { plan } = req.body; 
  if (!['pro', 'business'].includes(plan)) return res.status(400).json({ error: 'Plan no válido.' });

  try {
    // 💡 OPTIMIZACIÓN 3: Referencia mucho más limpia
    const referenciaEspecial = `SUB_${plan.toUpperCase()}_${Date.now()}`;
    const monto = plan === 'pro' ? 9.99 : 29.99;

    const nuevaSuscripcion = await prisma.transaccion.create({
      data: {
        monto, moneda: 'USD', estado: 'pendiente', comercioId: req.comercio.id,
        descripcion: `Suscripción Mensual - Plan ${plan.toUpperCase()}`,
        referenciaComercio: referenciaEspecial,
        urlExito: `${process.env.FRONTEND_URL}/dashboard` 
      }
    });

    res.status(200).json({ url_pago: `${process.env.FRONTEND_URL}/checkout/${nuevaSuscripcion.id}` });
  } catch (error) { res.status(500).json({ error: 'Error al generar la pasarela.' }); }
});

// ==========================================
// 6. RUTAS DE ADMINISTRADOR
// ==========================================
app.get('/api/admin/comercios', verificarToken, verificarSuperAdmin, async (req, res) => {
  try {
    const comercios = await prisma.comercio.findMany({
      select: { id: true, nombre: true, email: true, plan_actual: true, verificado: true, createdAt: true },
      orderBy: { createdAt: 'desc' }
    });
    res.status(200).json(comercios);
  } catch (error) { res.status(500).json({ error: 'Error obteniendo clientes.' }); }
});

app.put('/api/admin/comercios/:id/plan', verificarToken, verificarSuperAdmin, async (req, res) => {
  try {
    await prisma.comercio.update({ where: { id: req.params.id }, data: { plan_actual: req.body.nuevoPlan } });
    res.status(200).json({ mensaje: 'Plan actualizado' });
  } catch (error) { res.status(500).json({ error: 'Error al actualizar.' }); }
});

app.get('/api/status', (req, res) => { res.json({ empresa: 'Lumina', estado: 'Activo' }); });

app.listen(PORT, () => console.log(`🚀 Servidor de Lumina corriendo en el puerto ${PORT}`));