import nodemailer from 'nodemailer';
import 'dotenv/config';
import jwt from 'jsonwebtoken';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client'; 
import bcrypt from 'bcryptjs'; 

// --- INICIALIZACIÓN ---
const app = express();
const prisma = new PrismaClient(); 
const PORT = 3000;

// ... código anterior donde creas el nuevoComercio ...

    // MODO DESARROLLADOR: Simulamos el envío del correo imprimiéndolo en consola
    console.log(`\n========================================`);
    console.log(`📧 SIMULADOR DE CORREO PARA: ${email}`);
    console.log(`🔐 Tu código de verificación es: ${codigoOTP}`);
    console.log(`========================================\n`);

    /* (Comentamos el cartero real por el bloqueo de Render gratuito)
    await transporter.sendMail({
      from: `"Equipo Lumina Pay" <${process.env.EMAIL_USUARIO}>`,
      to: email,
      subject: '🛡️ Verifica tu cuenta en Lumina Pay',
      // ... resto del correo ...
    });
    */

    res.status(201).json({ mensaje: 'Comercio creado. Revisa tu consola para ver el código.' });

// --- ESCUDO DE SEGURIDAD CORS ---
const dominiosPermitidos = [
  'https://pay-saas-frontend.vercel.app', // Tu dominio oficial principal
  'https://pay-saas-frontend-git-main-alejandronavas228s-projects.vercel.app', // El enlace temporal de Vercel
  'http://localhost:5173' // Tu computadora local
];

const opcionesCors = {
  origin: function (origin, callback) {
    if (!origin || dominiosPermitidos.includes(origin)) {
      callback(null, true);
    } else {
      console.error(`🚨 CORS BLOQUEÓ ESTA URL EXACTA: "${origin}"`); 
      callback(new Error('Acceso denegado: Bloqueado por el escudo CORS de Lumina'));
    }
  }
};

app.use(cors(opcionesCors));
// ---------------------------------
// ---------------------------------
app.use(express.json());

// --- MIDDLEWARES (Seguridad) ---
const verificarToken = (req, res, next) => {
  const token = req.header('Authorization');
  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado. No tienes un token válido.' });
  }
  try {
    const tokenLimpio = token.replace('Bearer ', '');
    const verificado = jwt.verify(tokenLimpio, process.env.JWT_SECRET);
    req.comercio = verificado;
    next();
  } catch (error) {
    res.status(401).json({ error: 'El token ha expirado o es inválido.' });
  }
};

// --- MIDDLEWARE: SEGURIDAD MÁQUINA A MÁQUINA (API KEYS) ---
const verificarApiKey = async (req, res, next) => {
  const apiKey = req.header('x-api-key'); // Las empresas enviarán su llave aquí
  
  if (!apiKey) {
    return res.status(401).json({ error: 'Acceso denegado. Falta la API Key corporativa.' });
  }

  try {
    // Buscamos en la base de datos a qué empresa le pertenece esta llave
    const comercio = await prisma.comercio.findFirst({ where: { api_key: apiKey } });
    
    if (!comercio) {
      return res.status(401).json({ error: 'API Key inválida o revocada.' });
    }

    // Si la llave es real, lo dejamos pasar y anotamos quién es
    req.comercioId = comercio.id; 
    next();
  } catch (error) {
    res.status(500).json({ error: 'Error validando credenciales de seguridad.' });
  }
};


// ==========================================
//           RUTAS DE AUTENTICACIÓN
// ==========================================

// 1. Registro de Comercios
// 1. Registro de Comercios (CON VERIFICACIÓN)
app.post('/api/registro', async (req, res) => {
  try {
    const { comercio, email, password } = req.body;
    const comercioExistente = await prisma.comercio.findUnique({ where: { email: email } });

    if (comercioExistente) {
      return res.status(400).json({ error: 'Este correo ya está registrado.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);

    // Generamos un código aleatorio de 6 dígitos
    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();

    const nuevoComercio = await prisma.comercio.create({
      data: {
        nombre: comercio,
        email: email,
        password: passwordEncriptada,
        verificado: false,
        codigoVerificacion: codigoOTP,
        api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
      }
    });

    // Enviamos el correo real
    await transporter.sendMail({
      from: `"Equipo Lumina Pay" <${process.env.EMAIL_USUARIO}>`,
      to: email,
      subject: '🛡️ Verifica tu cuenta en Lumina Pay',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
          <h2 style="color: #2563eb;">¡Bienvenido a Lumina, ${comercio}!</h2>
          <p>Para activar tu bóveda financiera y empezar a procesar pagos, introduce este código de seguridad en tu panel:</p>
          <div style="background-color: #f8fafc; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0f172a;">${codigoOTP}</span>
          </div>
          <p style="color: #64748b; font-size: 12px;">Si tú no solicitaste esta cuenta, ignora este correo.</p>
        </div>
      `
    });

    res.status(201).json({ mensaje: 'Comercio creado. Revisa tu correo para verificar tu cuenta.' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error en el servidor.' });
  }
});

// NUEVA RUTA: Verificar Código OTP
app.post('/api/verificar', async (req, res) => {
  try {
    const { email, codigo } = req.body;
    
    const comercio = await prisma.comercio.findUnique({ where: { email: email } });
    if (!comercio) return res.status(404).json({ error: 'Comercio no encontrado.' });
    if (comercio.verificado) return res.status(400).json({ error: 'Esta cuenta ya está verificada.' });
    if (comercio.codigoVerificacion !== codigo) return res.status(400).json({ error: 'Código incorrecto.' });

    // Si el código es correcto, activamos la cuenta y borramos el código
    await prisma.comercio.update({
      where: { email: email },
      data: { verificado: true, codigoVerificacion: null }
    });

    res.status(200).json({ mensaje: '¡Cuenta verificada con éxito!' });
  } catch (error) {
    res.status(500).json({ error: 'Error al verificar la cuenta.' });
  }
});

// 2. Login de Comercios
app.post('/api/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const comercio = await prisma.comercio.findUnique({ where: { email: email } });

    if (!comercio) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    if (!comercio.verificado) {
      return res.status(403).json({ 
        error: 'Cuenta no verificada. Por favor, revisa tu correo electrónico.',
        requiereVerificacion: true 
      });
    }

    const passwordValida = await bcrypt.compare(password, comercio.password);
    if (!passwordValida) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    const token = jwt.sign(
      { id: comercio.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.status(200).json({
      mensaje: 'Login exitoso',
      token: token, 
      comercio: { id: comercio.id, nombre: comercio.nombre, email: comercio.email }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error en el servidor al intentar iniciar sesión.' });
  }
});


// ==========================================
//           RUTAS DE PAGOS (CORE)
// ==========================================

// 3. Procesar un nuevo pago (Checkout) + WEBHOOK + API KEY SECURITY
app.post('/api/pagos/procesar', verificarApiKey, async (req, res) => {
  // B. ---> INICIO DEL WEBHOOK DINÁMICO <---
    try {
      // 1. Buscamos al comercio en la base de datos para ver si tiene un webhook guardado
      const comercio = await prisma.comercio.findUnique({ 
        where: { id: comercioIdReal } 
      });

      // 2. Si el comercio configuró una URL, le enviamos el aviso
      if (comercio.url_webhook) {
        fetch(comercio.url_webhook, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${comercio.api_key}` // Usamos su propia llave como seguridad
          },
          body: JSON.stringify({
            evento: 'pago_exitoso',
            data: {
              id_transaccion: nuevaTransaccion.id,
              monto: nuevaTransaccion.monto,
              referencia_cliente: nuevaTransaccion.referencia,
              estado: nuevaTransaccion.estado
            }
          })
        }).catch(err => console.error("Error enviando el Webhook:", err)); 
      } else {
        console.log(`El comercio ${comercio.nombre} no tiene Webhook configurado. Mensaje omitido.`);
      }
    } catch (errorWebhook) {
      console.error("Fallo al preparar el Webhook:", errorWebhook);
    }
});

// --- NUEVA RUTA: Procesar pagos desde Enlaces Públicos (Sin API Key) ---
app.post('/api/pagos/enlace-publico', async (req, res) => {
  try {
    const { comercioId, monto, moneda, metodo, referencia } = req.body;

    if (!comercioId || !monto) {
      return res.status(400).json({ error: 'Faltan datos requeridos.' });
    }

    // 1. Guardamos el pago usando el ID del enlace
    const nuevaTransaccion = await prisma.transaccion.create({
      data: {
        monto: monto,
        moneda: moneda,
        metodo: metodo,
        referencia: referencia || null, 
        estado: 'aprobado', 
        comercioId: comercioId 
      }
    });

    // 2. WEBHOOK: Avisamos a la tienda que el pago público fue un éxito
    try {
      const comercio = await prisma.comercio.findUnique({ where: { id: comercioId } });
      
      if (comercio && comercio.url_webhook) {
        fetch(comercio.url_webhook, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${comercio.api_key}` // Lumina usa la llave del comercio para identificarse
          },
          body: JSON.stringify({
            evento: 'pago_exitoso',
            data: {
              id_transaccion: nuevaTransaccion.id,
              monto: nuevaTransaccion.monto,
              referencia_cliente: nuevaTransaccion.referencia,
              estado: nuevaTransaccion.estado
            }
          })
        }).catch(err => console.error("Error silencioso del Webhook:", err)); 
      }
    } catch (errorWebhook) {
      console.error("Fallo al preparar el Webhook:", errorWebhook);
    }

    res.status(201).json({ mensaje: 'Pago procesado exitosamente', recibo: nuevaTransaccion.id });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error crítico al procesar el pago público.' });
  }
});

    
// 4. Obtener historial de pagos (Dashboard)
app.get('/api/pagos/:comercioId', verificarToken, async (req, res) => {
  try {
    const { comercioId } = req.params;
    const transacciones = await prisma.transaccion.findMany({
      where: { comercioId: comercioId },
      orderBy: { fecha: 'desc' }
    });
    res.status(200).json(transacciones);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error al buscar el historial de pagos.' });
  }
});


// ==========================================
//           RUTAS DE CONFIGURACIÓN
// ==========================================

// 5. Obtener datos del comercio
app.get('/api/comercio/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const comercio = await prisma.comercio.findUnique({
      where: { id: id },
      select: {
        id: true,
        nombre: true,
        email: true,
        api_key: true,
        createdAt: true
      }
    });

    if (!comercio) {
      return res.status(404).json({ error: 'Comercio no encontrado.' });
    }
    res.status(200).json(comercio);
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al buscar la configuración.' });
  }
});

// 6. Actualizar el Webhook del comercio
app.put('/api/comercio/:id/webhook', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    const { url_webhook } = req.body;

    const comercioActualizado = await prisma.comercio.update({
      where: { id: id },
      data: { url_webhook: url_webhook }
    });

    res.status(200).json({ 
      mensaje: 'Webhook actualizado exitosamente', 
      url_webhook: comercioActualizado.url_webhook 
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Error al actualizar el webhook en la base de datos.' });
  }
});

// Ruta de estado
app.get('/api/status', (req, res) => {
  res.json({ empresa: 'Lumina', estado: 'Activo' });
});

// --- ENCENDIDO ---
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});