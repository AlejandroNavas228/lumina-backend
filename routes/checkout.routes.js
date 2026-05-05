import express from 'express';
import { PrismaClient } from '@prisma/client';
import { ethers } from 'ethers';

const router = express.Router();
const prisma = new PrismaClient();

// ==========================================
// HELPER: ACTIVACIÓN AUTOMÁTICA DE PLANES
// ==========================================
const activarPlanSiEsSuscripcion = async (transaccion) => {
  if (transaccion.estado === 'aprobado' && transaccion.referenciaComercio?.startsWith('SUB-')) {
    try {
      const partes = transaccion.referenciaComercio.split('-');
      const idCliente = partes[1]; 
      const desc = transaccion.descripcion.toLowerCase();

      let nuevoPlan = 'starter';
      if (desc.includes('pro')) nuevoPlan = 'pro';
      if (desc.includes('business')) nuevoPlan = 'business';

      await prisma.comercio.update({
        where: { id: idCliente },
        data: { plan_actual: nuevoPlan }
      });
      console.log(`🚀 [Lumina SaaS] Plan ${nuevoPlan.toUpperCase()} activado para cliente ID: ${idCliente}`);
    } catch (error) {
      console.error("❌ Error activando plan automático:", error);
    }
  }
};

// ==========================================
// MIDDLEWARE DE SEGURIDAD
// ==========================================
const verificarApiKey = async (req, res, next) => {
  const apiKey = req.headers['x-api-key'];
  if (!apiKey) return res.status(401).json({ error: 'API Key requerida' });

  const comercio = await prisma.comercio.findUnique({ where: { api_key: apiKey } });
  if (!comercio) return res.status(401).json({ error: 'API Key inválida' });

  req.comercioId = comercio.id;
  req.comercioKey = comercio.api_key;
  req.urlWebhook = comercio.url_webhook;
  next();
};

// ==========================================
// RUTAS DE CHECKOUT
// ==========================================

// 1. Generar Link de Pago
router.post('/', verificarApiKey, async (req, res) => { 
  try {
    const { monto, moneda, descripcion, referenciaComercio, urlExito, urlCancelado, url_webhook } = req.body;
    
    const nuevaTransaccion = await prisma.transaccion.create({
      data: {
        monto,
        moneda: moneda || 'USD',
        descripcion,
        referenciaComercio,
        urlExito,
        urlCancelado,
        estado: 'pendiente',
        comercioId: req.comercioId,
        metodo: 'sandbox' 
      }
    });

    const baseUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    res.status(200).json({
      exito: true,
      url_pago: `${baseUrl}/checkout/${nuevaTransaccion.id}`,
      transaccion_id: nuevaTransaccion.id
    });
  } catch (error) {
    res.status(500).json({ error: 'Error al generar link de pago.' });
  }
});

// 2. Obtener datos para la pantalla de Checkout
router.get('/:id', async (req, res) => {

if (req.params.id === 'demo' || req.params.id === 'demo_preview') {
    return res.status(200).json({
      // Los datos de la transacción van "sueltos" (igual que en Prisma)
      id: 'demo-1234',
      descripcion: 'Suscripción Pro (Ejemplo Demo)',
      monto: '10.00',
      moneda: 'USD',
      
      // El comercio va como un objeto anidado
      comercio: {
        nombre: 'Tienda Lumina Demo',
        pago_movil_banco: 'Banesco',
        pago_movil_cedula: 'V-12345678',
        pago_movil_tel: '0414-1234567',
        zelle_email: 'demo@luminapay.xyz',
        zinli_email: 'demo@luminapay.xyz',
        wallet_usdt: '0x00000000000000000000',
        paypal_client_id: 'test' 
      },

      // 💡 ¡FALTABA ESTO! El frontend necesita saber qué botones encender
      metodosDisponibles: {
        web3: true,
        zelle: true, 
        zinli: true,
        pago_movil: true,
        paypal: true,
        binance: true 
      }
    });
  }

  try {
    const transaccion = await prisma.transaccion.findUnique({
      where: { id: req.params.id },
      include: { 
        comercio: { 
          select: { 
            nombre: true,
            wallet_usdt: true,
            zelle_email: true,
            zinli_email: true,
            pago_movil_tel: true,
            pago_movil_banco: true,  
            pago_movil_cedula: true,
            paypal_client_id: true
          } 
        } 
      }
    });

    if (!transaccion) return res.status(404).json({ error: 'Transacción no encontrada.' });

    const metodosDisponibles = {
      web3: !!transaccion.comercio.wallet_usdt,
      zelle: !!transaccion.comercio.zelle_email, 
      zinli: !!transaccion.comercio.zinli_email,
      pago_movil: !!transaccion.comercio.pago_movil_tel,
      paypal: !!transaccion.comercio.paypal_client_id,
      binance: true 
    };

    res.status(200).json({ ...transaccion, metodosDisponibles });
  } catch (error) {
    res.status(500).json({ error: 'Error al cargar checkout.' });
  }
});

// 3. Radar Web3 (Verificar Blockchain)
router.post('/:id/verificar-crypto', async (req, res) => {
  try {
    const { id } = req.params;
    const transaccion = await prisma.transaccion.findUnique({
      where: { id },
      include: { comercio: true }
    });

    if (!transaccion || transaccion.estado !== 'pendiente') return res.status(400).json({ error: 'Invalido' });

    const provider = new ethers.JsonRpcProvider('https://1rpc.io/bnb');
    const usdtAddress = '0x55d398326f99059fF775485246999027B3197955';
    const abi = ["event Transfer(address indexed from, address indexed to, uint256 value)"];
    const usdtContract = new ethers.Contract(usdtAddress, abi, provider);
    const filtro = usdtContract.filters.Transfer(null, transaccion.comercio.wallet_usdt);
    const eventos = await usdtContract.queryFilter(filtro, -100);

    let pagoDetectado = false;
    let hashTransaccion = "";

    for (let evento of eventos) {
      const montoTransferido = ethers.formatUnits(evento.args[2], 18);
      if (parseFloat(montoTransferido) === parseFloat(transaccion.monto)) {
        pagoDetectado = true;
        hashTransaccion = evento.transactionHash;
        break;
      }
    }

    if (pagoDetectado) {
      const transaccionAprobada = await prisma.transaccion.update({
        where: { id },
        data: { estado: 'aprobado', metodo: 'web3', referencia_cliente: hashTransaccion },
        include: { comercio: true }
      });

      // ACTIVACIÓN AUTOMÁTICA SI ES PLAN
      await activarPlanSiEsSuscripcion(transaccionAprobada);

      return res.status(200).json({ mensaje: '¡Pago detectado!', hash: hashTransaccion });
    } else {
      return res.status(400).json({ error: 'Pago no detectado aún.' });
    }
  } catch (error) {
    res.status(500).json({ error: 'Error de radar.' });
  }
});

// 4. Pago Sandbox (Pruebas)
router.post('/:id/pagar', async (req, res) => {
  try {
    const { id } = req.params;
    const { metodo } = req.body; 

    const transaccion = await prisma.transaccion.update({
      where: { id },
      data: { estado: 'aprobado', metodo: metodo || 'sandbox' },
      include: { comercio: true }
    });

    // ACTIVACIÓN AUTOMÁTICA SI ES PLAN
    await activarPlanSiEsSuscripcion(transaccion);

    res.status(200).json({ mensaje: 'Pago exitoso', urlExito: transaccion.urlExito });
  } catch (error) {
    res.status(500).json({ error: 'Error procesando pago.' });
  }
});

// 5. Reportar Pago Manual (Zelle / Pago Móvil)
router.post('/:id/confirmar', async (req, res) => {

if (req.params.id === 'demo' || req.params.id === 'demo_preview') {
    return res.status(200).json({ mensaje: 'Pago demo procesado con éxito' });
  }

  try {
    const { id } = req.params;
    const { metodo, referencia } = req.body;

    await prisma.transaccion.update({
      where: { id },
      data: { estado: 'en_revision', metodo, referencia_cliente: referencia }
    });

    res.status(200).json({ mensaje: 'Pago reportado en revisión.' });
  } catch (error) {
    res.status(500).json({ error: 'Error al reportar.' });
  }
});

export default router;