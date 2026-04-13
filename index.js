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
// Lee la variable FRONTEND_URL. Si hay varias separadas por coma, las convierte en lista.
const origenesPermitidos = process.env.FRONTEND_URL 
  ? process.env.FRONTEND_URL.split(',') 
  : ['http://localhost:5173'];

app.use(cors({
  origin: origenesPermitidos,
  credentials: true
}));

app.use(express.json());
app.use('/api', checkoutRoutes);

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
  const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$/;
  if (!passwordRegex.test(req.body.password)) {
    return res.status(400).json({ error: 'Contraseña muy débil.' });
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
        plan_actual: true, createdAt: true 
      }
    });
    res.status(200).json(comercio);
  } catch (error) { res.status(500).json({ error: 'Error al buscar el comercio.' }); }
});

app.put('/api/comercio/:id/config', verificarToken, async (req, res) => {
  try {
    const { 
      url_webhook, wallet_usdt, pago_movil_cedula, pago_movil_banco, 
      pago_movil_tel, zelle_email, zinli_email, paypal_client_id 
    } = req.body;
    
    await prisma.comercio.update({
      where: { id: req.params.id },
      data: { 
        url_webhook, wallet_usdt, pago_movil_cedula, pago_movil_banco, 
        pago_movil_tel, zelle_email, zinli_email, paypal_client_id
      }
    });
    res.status(200).json({ mensaje: 'Configuración guardada exitosamente' });
  } catch (error) { res.status(500).json({ error: 'Error al actualizar la configuración.' }); }
});

app.put('/api/comercio/:id/plan', verificarToken, async (req, res) => {
  try {
    const { plan } = req.body;
    await prisma.comercio.update({
      where: { id: req.params.id },
      data: { plan_actual: plan }
    });
    res.status(200).json({ mensaje: `¡Felicidades! Has cambiado al plan ${plan.toUpperCase()}` });
  } catch (error) { 
    res.status(500).json({ error: 'Error al actualizar el plan.' }); 
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
    
    const transaccion = await prisma.transaccion.update({
      where: { id: req.params.id },
      data: { estado: estado },
      include: { comercio: true }
    });

    if (estado === 'aprobado' && transaccion.comercio.url_webhook) {
      fetch(transaccion.comercio.url_webhook, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json', 
          'Authorization': `Bearer ${transaccion.comercio.api_key}` 
        },
        body: JSON.stringify({ evento: 'pago_exitoso', data: transaccion })
      }).catch(e => console.log("Webhook disparado en segundo plano"));
    }

    res.status(200).json({ mensaje: `Transacción marcada como ${estado}` });
  } catch (error) {
    res.status(500).json({ error: 'Error al actualizar la transacción.' });
  }
});

// ==========================================
// 5. RUTAS DE LA PASARELA DE PAGOS
// ==========================================
app.use('/api/checkout', checkoutRoutes); 

// ==========================================
// 6. ESTADO DEL SERVIDOR
// ==========================================
app.get('/api/status', (req, res) => { res.json({ empresa: 'Lumina', estado: 'Activo' }); });

app.listen(PORT, () => {
  console.log(`🚀 Servidor de Lumina corriendo en el puerto ${PORT}`);
});