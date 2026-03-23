import { OAuth2Client } from 'google-auth-library';
import { Resend } from 'resend';
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
const resend = new Resend(process.env.RESEND_API_KEY);
const clienteGoogle = new OAuth2Client("758151472142-ej6ncaq5nio8l2mjf8hobmrrmbbb7buc.apps.googleusercontent.com");

// --- CONFIGURACIÓN DE SEGURIDAD (CORS) ---
app.use(cors({
  origin: [
    'http://localhost:5173', 
    'https://pay-saas-frontend.vercel.app', 
    'https://luminapay.xyz', 
    'https://www.luminapay.xyz' 
  ],
  credentials: true
}));

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

const verificarApiKey = async (req, res, next) => {
  const apiKey = req.header('x-api-key'); 
  
  if (!apiKey) {
    return res.status(401).json({ error: 'Acceso denegado. Falta la API Key corporativa.' });
  }

  try {
    const comercio = await prisma.comercio.findFirst({ where: { api_key: apiKey } });
    
    if (!comercio) {
      return res.status(401).json({ error: 'API Key inválida o revocada.' });
    }

    req.comercioId = comercio.id; 
    next();
  } catch (error) {
    res.status(500).json({ error: 'Error validando credenciales de seguridad.' });
  }
};


// ==========================================
//          RUTAS DE AUTENTICACIÓN
// ==========================================

// 1. Registro de Comercios (CON VERIFICACIÓN OTP)
app.post('/api/registro', async (req, res) => {
  try {
    const { comercio, email, password } = req.body;
    
    // Validar si el correo ya existe
    const comercioExistente = await prisma.comercio.findUnique({ where: { email: email } });
    if (comercioExistente) {
      return res.status(400).json({ error: 'Este correo ya está registrado.' });
    }

    // Encriptar y generar código
    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);
    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();

    // Guardar en Base de Datos
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

    // Enviar correo con Resend
    try {
      await resend.emails.send({
        from: 'Lumina Pay <soporte@luminapay.xyz>', 
        to: email,
        subject: '🛡️ Verifica tu cuenta en Lumina Pay',
        html: `
          <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
            <h2 style="color: #2563eb;">¡Bienvenido a Lumina, ${comercio}!</h2>
            <p>Para activar tu bóveda financiera y empezar a procesar pagos, introduce este código de seguridad en tu panel:</p>
            <div style="background-color: #f8fafc; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
              <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0f172a;">${codigoOTP}</span>
            </div>
            <p style="color: #64748b; font-size: 12px;">Si tú no solicitaste esta cuenta, ignora este mensaje.</p>
          </div>
        `
      });
      console.log(`✅ Correo enviado exitosamente a ${email} vía Resend`);
    } catch (errorCorreo) {
      console.error("❌ Error enviando correo con Resend:", errorCorreo);
    }

    res.status(201).json({ mensaje: 'Comercio creado. Revisa tu correo.' });

  } catch (error) {
    console.error("Error en el registro:", error);
    res.status(500).json({ error: 'Hubo un error interno al registrar el comercio.' });
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

// 3. Solicitar recuperación de contraseña (Envía el correo)
app.post('/api/recuperar-password', async (req, res) => {
  try {
    const { email } = req.body;
    
    // 1. Verificamos si el correo existe en la base de datos
    const comercio = await prisma.comercio.findUnique({ where: { email: email } });
    if (!comercio) {
      // Por seguridad, siempre respondemos que se envió, para evitar que los hackers adivinen correos
      return res.status(200).json({ mensaje: 'Si el correo existe, hemos enviado un código.' });
    }

    // 2. Generamos un nuevo código de 6 dígitos
    const codigoOTP = Math.floor(100000 + Math.random() * 900000).toString();

    // 3. Lo guardamos en el usuario
    await prisma.comercio.update({
      where: { email: email },
      data: { codigoVerificacion: codigoOTP }
    });

    // 4. Enviamos el correo con Resend
    await resend.emails.send({
      from: 'Lumina Pay <soporte@luminapay.xyz>', 
      to: email,
      subject: '🔒 Recuperación de Contraseña - Lumina Pay',
      html: `
        <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px; border: 1px solid #eee; border-radius: 10px;">
          <h2 style="color: #2563eb;">Recupera tu acceso a Lumina</h2>
          <p>Hola, ${comercio.nombre}. Hemos recibido una solicitud para cambiar tu contraseña.</p>
          <p>Usa este código de seguridad de 6 dígitos para crear una nueva contraseña:</p>
          <div style="background-color: #f8fafc; padding: 15px; text-align: center; border-radius: 8px; margin: 20px 0;">
            <span style="font-size: 32px; font-weight: bold; letter-spacing: 5px; color: #0f172a;">${codigoOTP}</span>
          </div>
          <p style="color: #64748b; font-size: 12px;">Si no fuiste tú, ignora este correo. Tu cuenta está segura.</p>
        </div>
      `
    });

    res.status(200).json({ mensaje: 'Si el correo existe, hemos enviado un código.' });
  } catch (error) {
    console.error("Error al pedir recuperación:", error);
    res.status(500).json({ error: 'Hubo un problema al procesar la solicitud.' });
  }
});

// 4. Restablecer la contraseña (Verifica el código y guarda la nueva clave)
app.post('/api/restablecer-password', async (req, res) => {
  try {
    const { email, codigo, nuevaPassword } = req.body;

    // 1. Buscamos al usuario
    const comercio = await prisma.comercio.findUnique({ where: { email: email } });
    if (!comercio) return res.status(404).json({ error: 'Usuario no encontrado.' });

    // 2. Verificamos que el código sea el correcto
    if (comercio.codigoVerificacion !== codigo) {
      return res.status(400).json({ error: 'Código de seguridad incorrecto.' });
    }

    // 3. Encriptamos la nueva contraseña
    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(nuevaPassword, salt);

    // 4. Guardamos la nueva clave y borramos el código usado
    await prisma.comercio.update({
      where: { email: email },
      data: { 
        password: passwordEncriptada,
        codigoVerificacion: null // Limpiamos el código por seguridad
      }
    });

    res.status(200).json({ mensaje: '¡Contraseña actualizada con éxito! Ya puedes iniciar sesión.' });
  } catch (error) {
    console.error("Error al cambiar clave:", error);
    res.status(500).json({ error: 'No se pudo actualizar la contraseña.' });
  }
});

// --- NUEVA RUTA: Login con Google ---
app.post('/api/login/google', async (req, res) => {
  try {
    const { token } = req.body;
    
    // 1. Verificamos que el boleto sea 100% real con los servidores de Google
    const ticket = await clienteGoogle.verifyIdToken({
      idToken: token,
      audience: "758151472142-ej6ncaq5nio8l2mjf8hobmrrmbbb7buc.apps.googleusercontent.com",
    });
    
    // 2. Extraemos los datos del usuario de Google
    const payload = ticket.getPayload();
    const email = payload.email;
    const nombre = payload.name;

    // 3. Buscamos si ya existe en Lumina
    let comercio = await prisma.comercio.findUnique({ where: { email: email } });

    // 4. Si es la primera vez que entra, le creamos la cuenta en automático
    if (!comercio) {
      // Le generamos una contraseña aleatoria imposible de adivinar (porque entrará con Google)
      const salt = await bcrypt.genSalt(10);
      const passwordAleatoria = await bcrypt.hash(Math.random().toString(36).slice(-12), salt);

      comercio = await prisma.comercio.create({
        data: {
          nombre: nombre,
          email: email,
          password: passwordAleatoria,
          verificado: true, // ¡Como es de Google, sabemos que el correo es real! No necesita código OTP.
          api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
        }
      });
    }

    // 5. Le damos nuestro propio token VIP de Lumina para que navegue
    const tokenLumina = jwt.sign(
      { id: comercio.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    res.status(200).json({
      mensaje: 'Login con Google exitoso',
      token: tokenLumina,
      comercio: { id: comercio.id, nombre: comercio.nombre, email: comercio.email }
    });

  } catch (error) {
    console.error("Error en Google Login:", error);
    res.status(401).json({ error: 'Token de Google inválido o expirado.' });
  }
});


// ==========================================
//          RUTAS DE PAGOS (CORE)
// ==========================================

// 3. Procesar un nuevo pago (Checkout Manual vía API) + WEBHOOK
app.post('/api/pagos/procesar', verificarApiKey, async (req, res) => {
  try {
    const { monto, moneda, metodo, referencia } = req.body;
    const comercioIdReal = req.comercioId; 

    const nuevaTransaccion = await prisma.transaccion.create({
      data: {
        monto: monto,
        moneda: moneda,
        metodo: metodo,
        referencia: referencia || null,
        estado: 'aprobado',
        comercioId: comercioIdReal
      }
    });

    // B. ---> INICIO DEL WEBHOOK DINÁMICO <---
    try {
      const comercio = await prisma.comercio.findUnique({ 
        where: { id: comercioIdReal } 
      });

      if (comercio && comercio.url_webhook) {
        fetch(comercio.url_webhook, {
          method: 'POST',
          headers: { 
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${comercio.api_key}` 
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
      }
    } catch (errorWebhook) {
      console.error("Fallo al preparar el Webhook:", errorWebhook);
    }

    res.status(201).json({ 
      mensaje: 'Pago procesado exitosamente', 
      recibo: nuevaTransaccion.id 
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error al guardar el pago.' });
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
            'Authorization': `Bearer ${comercio.api_key}`
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
//          RUTAS DE CONFIGURACIÓN
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
        url_webhook: true, // Agregado para que retorne el webhook si existe
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