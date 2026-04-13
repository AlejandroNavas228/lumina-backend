import express from 'express';
import { PrismaClient } from '@prisma/client';
import { ethers } from 'ethers';

const router = express.Router();
const prisma = new PrismaClient();

// ==========================================
// CONFIGURACIÓN WEB3 (RADAR CRIPTO)
// ==========================================
const BSC_RPC_URL = 'https://bsc-dataseed.binance.org/';
const USDT_CONTRACT_ADDRESS = '0x55d398326f99059fF775485246999027B3197955';

// ==========================================
// MIDDLEWARES LOCALES
// ==========================================
const verificarApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API Key requerida' });

  const comercio = await prisma.comercio.findUnique({ where: { api_key: apiKey } });
  if (!comercio) return res.status(401).json({ error: 'API Key inválida' });

  req.comercioId = comercio.id;
  next();
};

// ==========================================
// RUTAS DE CHECKOUT
// ==========================================

// 1. Generar Link de Pago (Lo llama Zahara Store)
// Quitamos 'verificarApiKey' temporalmente para esta prueba
router.post('/', async (req, res) => { 
  try {
    // 👇 AQUÍ RECIBIMOS EL url_webhook DE ZAHARA
    const { monto, moneda, descripcion, referenciaComercio, urlExito, urlCancelado, url_webhook } = req.body;
    
    // Para probar, agarramos cualquier comercio que ya exista en tu base de datos
    const comercioPrueba = await prisma.comercio.findFirst();

    if (!comercioPrueba) {
        return res.status(400).json({ error: 'Debes crear al menos un comercio en la BD de Lumina primero.' });
    }

    const nuevaTransaccion = await prisma.transaccion.create({
      data: {
        monto: monto,
        moneda: moneda || 'USD',
        descripcion: descripcion,
        referenciaComercio: referenciaComercio,
        urlExito: urlExito,
        urlCancelado: urlCancelado,
        estado: 'pendiente',
        comercioId: comercioPrueba.id, 
        metodo: 'sandbox' 
      }
    });

    // 👇 AQUÍ GUARDAMOS EL "TELÉFONO ROJO" EN LA BASE DE DATOS DE LUMINA
    if (url_webhook) {
        await prisma.comercio.update({
            where: { id: comercioPrueba.id },
            data: { url_webhook: url_webhook }
        });
    }

    // Esta es la URL a la que mandaremos al cliente para que pague
    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    
    res.status(200).json({
      exito: true,
      url_pago: `${baseUrl}/checkout/${nuevaTransaccion.id}`,
      transaccion_id: nuevaTransaccion.id
    });
  } catch (error) {
    console.error("🔥 ERROR EN LUMINA:", error);
    res.status(500).json({ error: 'Error generando el link de pago.' });
  }
});


// 2. Obtener datos para la pantalla de Checkout (Ahorá es un Checkout Inteligente)
router.get('/:id', async (req, res) => {
  try {
    const transaccion = await prisma.transaccion.findUnique({
      where: { id: req.params.id },
      include: { 
        comercio: { 
          select: { 
            nombre: true,
            plan_actual: true,
            wallet_usdt: true,
            zelle_email: true,
            zinli_email: true,
            pago_movil_banco: true,  
            pago_movil_cedula: true, 
            pago_movil_tel: true,
            paypal_client_id: true
          } 
        } 
      }
    });

    if (!transaccion) return res.status(404).json({ error: 'Transacción no encontrada.' });
    if (transaccion.estado !== 'pendiente') return res.status(400).json({ error: 'Este pago ya fue procesado o cancelado.' });

   
    const metodosDisponibles = {
      web3: !!transaccion.comercio.wallet_usdt,
      zelle: !!transaccion.comercio.zelle_email, 
      zinli: !!transaccion.comercio.zinli_email,
      pago_movil: !!transaccion.comercio.pago_movil_tel,
      paypal: !!transaccion.comercio.paypal_client_id,
      binance: true 
    };

    res.status(200).json({
      ...transaccion,
      metodosDisponibles
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al cargar los datos del pago.' });
  }
});

// 3. Obtener Info de Billetera para Pago Cripto Web3
router.get('/:id/crypto-info', async (req, res) => {
  try {
    const transaccion = await prisma.transaccion.findUnique({
      where: { id: req.params.id },
      include: { comercio: true }
    });

    if (!transaccion) return res.status(404).json({ error: 'Transacción no encontrada' });
    
    if (!transaccion.comercio.wallet_usdt) {
      return res.status(400).json({ error: 'Esta tienda aún no acepta pagos en Criptomonedas directas.' });
    }

    res.status(200).json({
      monto: transaccion.monto,
      wallet: transaccion.comercio.wallet_usdt,
      moneda: 'USDT (Red BSC - BEP20)'
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al generar la orden cripto' });
  }
});

// 4. El Radar: Verificar si el pago llegó a la Blockchain
router.post('/:id/verificar-crypto', async (req, res) => {
  try {
    const { id } = req.params;
    const transaccion = await prisma.transaccion.findUnique({
      where: { id },
      include: { comercio: true }
    });

    if (!transaccion || transaccion.estado !== 'pendiente') {
      return res.status(400).json({ error: 'La transacción no es válida o ya fue procesada.' });
    }

    const walletTienda = transaccion.comercio.wallet_usdt;
    if (!walletTienda) return res.status(400).json({ error: 'La tienda no tiene una billetera configurada.' });

  // 1. Conectar a la Binance Smart Chain (BSC) usando 1RPC (Público y sin bloqueos)
    const provider = new ethers.JsonRpcProvider('https://1rpc.io/bnb');

    // 2. Conectar con el Contrato Inteligente de USDT en la red BSC
    const usdtAddress = '0x55d398326f99059fF775485246999027B3197955';
    // Le enseñamos a Lumina a leer los "eventos" de transferencias
    const abi = ["event Transfer(address indexed from, address indexed to, uint256 value)"];
    const usdtContract = new ethers.Contract(usdtAddress, abi, provider);

    // 3. Crear el Radar: Buscar transferencias que hayan llegado a la Wallet de la tienda
    const filtro = usdtContract.filters.Transfer(null, walletTienda);
    
    // Escaneamos los últimos 100 bloques (aprox. los últimos 5 minutos de la blockchain)
    const eventos = await usdtContract.queryFilter(filtro, -100);

    // 4. Analizar los resultados
    let pagoDetectado = false;
    let hashTransaccion = "";

    for (let evento of eventos) {
      // El dinero en la blockchain tiene 18 decimales. Lo formateamos a un número normal.
      const montoTransferido = ethers.formatUnits(evento.args[2], 18);
      // Comparamos el monto de la blockchain con el monto que pide Lumina
      if (parseFloat(montoTransferido) === parseFloat(transaccion.monto)) {
        pagoDetectado = true;
        hashTransaccion = evento.transactionHash; // Guardamos la prueba criptográfica
        break;
      }
    }

    // 5. El Veredicto
    if (pagoDetectado) {
      // Aprobamos el pago de forma automática y guardamos el Hash en la base de datos
      await prisma.transaccion.update({
        where: { id },
        data: { 
          estado: 'aprobado', 
          metodo: 'web3',
          referencia_cliente: hashTransaccion 
        }
      });

      // ¡Aquí también podríamos disparar el Webhook para avisarle a Zahara Store!
      if (transaccion.comercio.url_webhook) {
        fetch(transaccion.comercio.url_webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${transaccion.comercio.api_key}` },
          body: JSON.stringify({ evento: 'pago_exitoso', data: transaccion })
        }).catch(e => console.log("Webhook enviado silenciosamente"));
      }

      return res.status(200).json({ 
        mensaje: '¡Pago detectado y verificado en la Blockchain!', 
        hash: hashTransaccion 
      });
    } else {
      return res.status(400).json({ error: 'Aún no vemos el pago en la red. Si ya pagaste, espera 1 minuto y vuelve a verificar.' });
    }

  } catch (error) {
    console.error('Error del Radar Web3:', error);
    res.status(500).json({ error: 'Error de conexión con la blockchain.' });
  }
});


// 5. Pago de Prueba (Sandbox)
router.post('/:id/pagar', async (req, res) => {
  try {
    const { id } = req.params;
    const { metodo } = req.body; 

    const transaccion = await prisma.transaccion.update({
      where: { id },
      data: { estado: 'aprobado', metodo: metodo || 'sandbox' },
      include: { comercio: true }
    });

    if (transaccion.comercio.url_webhook) {
      try {
        fetch(transaccion.comercio.url_webhook, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${transaccion.comercio.api_key}` },
          body: JSON.stringify({ evento: 'pago_exitoso', data: transaccion })
        }).catch(() => console.log('Webhook disparado (sin esperar respuesta)'));
      } catch (e) { console.error("Error disparando webhook", e); }
    }

    res.status(200).json({ 
      mensaje: 'Pago exitoso', 
      urlExito: transaccion.urlExito || null 
    });

  } catch (error) {
    res.status(500).json({ error: 'Error al procesar el pago.' });
  }
});

// 6. Pago con Binance Pay
router.post('/:id/binance', async (req, res) => {
  try {
    const { id } = req.params;
    
    const transaccion = await prisma.transaccion.findUnique({
      where: { id: id }
    });

    if (!transaccion) return res.status(404).json({ error: 'Transacción no encontrada.' });
    if (transaccion.estado !== 'pendiente') return res.status(400).json({ error: 'Este pago ya fue procesado.' });

    const apiKey = process.env.BINANCE_API_KEY;
    const apiSecret = process.env.BINANCE_SECRET_KEY;

    if (!apiKey || apiKey === 'tu_api_key_de_binance_aqui') {
      console.log("Simulando conexión con Binance Pay (Faltan llaves reales)...");
      
      await prisma.transaccion.update({
        where: { id },
        data: { metodo: 'binance_pay' }
      });

      return res.status(200).json({
        mensaje: 'Orden creada en Binance (Simulación)',
        checkoutUrl: 'https://pay.binance.com/es/checkout/dummy-url-para-pruebas',
        tipo: 'simulacion'
      });
    }
  } catch (error) {
    console.error("Error al conectar con Binance:", error);
    res.status(500).json({ error: 'Error al generar la orden en Binance.' });
  }
});

// 7. Reportar pago manual (Zelle / Pago Móvil)
router.post('/:id/reportar-manual', async (req, res) => {
  try {
    const { id } = req.params;
    const { metodo, referencia } = req.body;

    const transaccion = await prisma.transaccion.findUnique({ where: { id } });
    if (!transaccion || transaccion.estado !== 'pendiente') {
      return res.status(400).json({ error: 'La transacción no es válida.' });
    }

    // Cambiamos el estado a "en_revision" (NO a aprobado todavía)
    await prisma.transaccion.update({
      where: { id },
      data: {
        estado: 'en_revision',
        metodo: metodo,
        referencia_cliente: referencia
      }
    });

    res.status(200).json({ mensaje: 'Pago reportado. Esperando confirmación de la tienda.' });
  } catch (error) {
    res.status(500).json({ error: 'Error al reportar el pago.' });
  }
});

export default router;