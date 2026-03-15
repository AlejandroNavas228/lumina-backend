import 'dotenv/config';
import jwt from 'jsonwebtoken';
import express from 'express';
import cors from 'cors';
import { PrismaClient } from '@prisma/client'; // 1. Importamos Prisma
import bcrypt from 'bcryptjs'; // 2. Importamos el encriptador

// Inicializamos
const app = express();
const prisma = new PrismaClient(); // Activamos la conexión a la base de datos
const PORT = 3000;

app.use(cors());
app.use(express.json());

// Ruta de prueba (la que ya teníamos)
app.get('/api/status', (req, res) => {
  res.json({ empresa: 'ZaharaPay', estado: 'Activo' });
});

// --- RUTA DE REGISTRO DE COMERCIOS ---
app.post('/api/registro', async (req, res) => {
  try {
    // 1. Recibimos los datos que manda el frontend
    const { comercio, email, password } = req.body;

    // 2. Verificamos si el correo ya existe en la base de datos
    const comercioExistente = await prisma.comercio.findUnique({
      where: { email: email }
    });

    if (comercioExistente) {
      // Si existe, le devolvemos un error 400 (Bad Request)
      return res.status(400).json({ error: 'Este correo ya está registrado.' });
    }

    // 3. Encriptamos la contraseña (le damos 10 "vueltas" de seguridad)
    const salt = await bcrypt.genSalt(10);
    const passwordEncriptada = await bcrypt.hash(password, salt);

    // 4. Guardamos el nuevo comercio en la base de datos usando Prisma
    const nuevoComercio = await prisma.comercio.create({
      data: {
        nombre: comercio,
        email: email,
        password: passwordEncriptada,
        // Opcional: Generamos un API Key básico combinando el nombre y un número aleatorio
        api_key: `zp_live_${Math.random().toString(36).substring(2, 15)}`
      }
    });

    // 5. Respondemos con éxito (sin enviar la contraseña de vuelta por seguridad)
    res.status(201).json({
      mensaje: 'Comercio creado exitosamente',
      comercio: {
        id: nuevoComercio.id,
        nombre: nuevoComercio.nombre,
        email: nuevoComercio.email
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error en el servidor.' });
  }
});

// --- RUTA DE LOGIN ---
app.post('/api/login', async (req, res) => {
  try {
    // 1. Recibimos los datos que manda el frontend
    const { email, password } = req.body;

    // 2. Buscamos si existe un comercio con ese correo
    const comercio = await prisma.comercio.findUnique({
      where: { email: email }
    });

    // Si no existe, devolvemos un error genérico (Código 401: No autorizado)
    if (!comercio) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

    // 3. Comparamos la contraseña encriptada usando bcrypt
    // bcrypt.compare desencripta temporalmente la de la base de datos y verifica si hace "match"
    const passwordValida = await bcrypt.compare(password, comercio.password);

    if (!passwordValida) {
      return res.status(401).json({ error: 'Correo o contraseña incorrectos.' });
    }

   // 4. Si todo es correcto, CREAMOS EL TOKEN (El brazalete VIP)
    // El token guardará el ID del comercio y caducará en 24 horas
    const token = jwt.sign(
      { id: comercio.id }, 
      process.env.JWT_SECRET, 
      { expiresIn: '24h' }
    );

    // Le damos la bienvenida y le entregamos su token
    res.status(200).json({
      mensaje: 'Login exitoso',
      token: token, // <--- Aquí enviamos el brazalete
      comercio: {
        id: comercio.id,
        nombre: comercio.nombre,
        email: comercio.email
      }
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error en el servidor al intentar iniciar sesión.' });
  }
});

// --- RUTA PARA PROCESAR PAGOS (EL CHECKOUT) ---
app.post('/api/pagos/procesar', async (req, res) => {
  try {
    // 1. Recibimos los datos de la compra desde el frontend
    const { comercioId, monto, moneda, metodo, referencia } = req.body;

    // 2. Validación de seguridad básica
    if (!comercioId || !monto || !moneda || !metodo) {
      return res.status(400).json({ error: 'Faltan datos requeridos para procesar el pago.' });
    }

    // 3. Guardamos la transacción en la base de datos usando Prisma
    const nuevaTransaccion = await prisma.transaccion.create({
      data: {
        monto: monto,
        moneda: moneda,
        metodo: metodo,
        referencia: referencia || null, // Si es tarjeta, puede que no haya referencia de inmediato
        estado: 'aprobado', // En un sistema real, aquí consultaríamos al banco primero. Por ahora, asumimos éxito.
        comercioId: comercioId // El ID de la tienda dueña de este dinero
      }
    });

    // 4. Respondemos con el recibo de éxito
    res.status(201).json({
      mensaje: 'Pago procesado exitosamente',
      recibo: nuevaTransaccion.id
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error crítico al procesar el pago.' });
  }
});


// --- MIDDLEWARE: EL CADENERO DE SEGURIDAD ---
const verificarToken = (req, res, next) => {
  // 1. Buscamos el token en la cabecera de la petición
  const token = req.header('Authorization');

  // 2. Si no trae brazalete, lo rebotamos
  if (!token) {
    return res.status(401).json({ error: 'Acceso denegado. No tienes un token válido.' });
  }

  try {
    // 3. Verificamos que el brazalete sea real usando nuestra firma secreta
    // El token suele venir como "Bearer eyJhb...", así que le quitamos la palabra "Bearer "
    const tokenLimpio = token.replace('Bearer ', '');
    const verificado = jwt.verify(tokenLimpio, process.env.JWT_SECRET);
    
    // 4. Si es válido, lo dejamos pasar a la siguiente función (next)
    req.comercio = verificado;
    next();
  } catch (error) {
    res.status(401).json({ error: 'El token ha expirado o es inválido.' });
  }
};

// --- RUTA PARA OBTENER EL HISTORIAL DE PAGOS (DASHBOARD) ---
app.get('/api/pagos/:comercioId', verificarToken, async (req, res) => {
  try {
    // 1. Extraemos el ID del comercio desde la URL
    const { comercioId } = req.params;

    // 2. Buscamos todas las transacciones que le pertenezcan a esa tienda
    const transacciones = await prisma.transaccion.findMany({
      where: { 
        comercioId: comercioId 
      },
      orderBy: { 
        fecha: 'desc' // Ordenamos para que las más recientes salgan de primero
      }
    });

    // 3. Devolvemos la lista completa al frontend
    res.status(200).json(transacciones);

  } catch (error) {
    console.error(error);
    res.status(500).json({ error: 'Hubo un error al buscar el historial de pagos.' });
  }
});

// --- RUTA PARA OBTENER LA CONFIGURACIÓN DEL COMERCIO ---
// Usamos verificarToken porque estos datos son ultra secretos
app.get('/api/comercio/:id', verificarToken, async (req, res) => {
  try {
    const { id } = req.params;
    
    // Buscamos el comercio, pero le decimos a Prisma que NO nos traiga la contraseña
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

// Encendemos el servidor
app.listen(PORT, () => {
  console.log(`✅ Servidor corriendo en http://localhost:${PORT}`);
});