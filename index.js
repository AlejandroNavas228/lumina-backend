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

app.use(cors());
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


// ==========================================
//           RUTAS DE AUTENTICACIÓN
// ==========================================

// 1. Registro de Comercios
app.post('/api/registro', async (req, res) => {
  try {
    const { comercio, email, password } = req.body;
    const comercioExistente = await prisma.comercio.findUnique({ where: { email: email } });

    if (comercioExistente) {
      return res.status(400).json({ error: 'Este correo ya está registrado.' });
    }

    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);

    const nuevoComercio = await prisma.comercio.create({
      data: {
        nombre: comercio,
        email: email,
        password: passwordEncriptada,
        api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
      }
    });

    res.status(201).json({
      mensaje: 'Comercio creado exitosamente',
      comercio: { id: nuevoComercio.id, nombre: nuevoComercio.nombre, email: nuevoComercio.email }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error en el servidor.' });
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

// 3. Procesar un nuevo pago (Checkout) + WEBHOOK
app.post('/api/pagos/procesar', async (req, res) => {
  try {
    const { comercioId, monto, moneda, metodo, referencia } = req.body;

    if (!comercioId || !monto || !moneda || !metodo) {
      return res.status(400).json({ error: 'Faltan datos requeridos para procesar el pago.' });
    }

    // A. Guardamos el pago en la base de datos
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

    // B. ---> INICIO DEL WEBHOOK (Mensajero a la tienda) <---
    // Intentamos avisarle a la tienda sin bloquear la respuesta al cliente
    try {
      const urlDeLaTienda = "https://webhook.site/d6516949-e184-47e0-b956-860349345c68"; 
      
      // Enviamos la petición POST a la tienda
      fetch(urlDeLaTienda, {
        method: 'POST',
        headers: { 
          'Content-Type': 'application/json',
          'Authorization': 'Bearer lumina-secret-123'
        },
        body: JSON.stringify({
          evento: 'pago_exitoso',
          data: {
            id_transaccion: nuevaTransaccion.id,
            monto: nuevaTransaccion.monto,
            referencia_cliente: nuevaTransaccion.referencia,
            fecha: nuevaTransaccion.fecha, // Usamos 'fecha' porque así está en tu esquema
            estado: nuevaTransaccion.estado
          }
        })
      }).catch(err => console.error("Error silencioso del Webhook:", err)); 
      // Usamos .catch en lugar de await para que el cliente no tenga que esperar a que la tienda responda
      
    } catch (errorWebhook) {
      console.error("Fallo al preparar el Webhook:", errorWebhook);
    }
    // ---> FIN DEL WEBHOOK <---

    // C. Respondemos al cliente con el recibo de éxito
    res.status(201).json({
      mensaje: 'Pago procesado exitosamente',
      recibo: nuevaTransaccion.id
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error crítico al procesar el pago.' });
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

// Ruta de estado
app.get('/api/status', (req, res) => {
  res.json({ empresa: 'Lumina', estado: 'Activo' });
});

// --- ENCENDIDO ---
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});