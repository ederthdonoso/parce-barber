require('dotenv').config();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');
const { Resend } = require('resend');
const mysql = require('mysql2/promise');

const app = express();

app.use(
    helmet({
        contentSecurityPolicy: false
    })
);

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: {
        success: false,
        message: 'Demasiados intentos. Espera unos minutos e inténtalo nuevamente.'
    }
});
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET) {
    throw new Error('Falta JWT_SECRET en el archivo .env');
}

app.set('trust proxy', 1);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());


// ============================================================
// CONEXIÓN MYSQL
// ============================================================

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME,
    waitForConnections: true,
    connectionLimit: 10,
    queueLimit: 0
});


// ============================================================
// CORREO
// ============================================================

const resend = new Resend(process.env.RESEND_API_KEY);

const EMAIL_REMITENTE =
    `"Parce Barber" <${process.env.EMAIL_USUARIO || 'reservas@parcebarber.cl'}>`;


// ============================================================
// FUNCIONES AUXILIARES
// ============================================================

// "jefe" y "jefe barber" serán considerados administradores.
function esJefe(usuario) {
    if (!usuario || !usuario.rol) {
        return false;
    }

    const rol = String(usuario.rol).trim().toLowerCase();

    return rol === 'jefe' || rol === 'jefe barber';
}


// Comprueba directamente en BD si el barbero está activo.
// No confiamos en un ID enviado por el navegador.
async function esBarberoDisponible(barberoId) {
    try {
        const [rows] = await pool.query(
            `SELECT id
             FROM barberos
             WHERE id = ?
             AND activo = 1
             LIMIT 1`,
            [barberoId]
        );

        return rows.length > 0;

    } catch (error) {
        console.error('Error comprobando disponibilidad del barbero:', error);
        return false;
    }
}

// Comprueba si un día completo está bloqueado para un barbero.
async function esDiaBloqueado(barberoId, fecha) {

    try {

        const [rows] = await pool.query(
            `SELECT id
             FROM dias_bloqueados
             WHERE barberoId = ?
             AND fecha = ?
             LIMIT 1`,
            [
                barberoId,
                fecha
            ]
        );

        return rows.length > 0;

    } catch (error) {

        console.error(
            'Error comprobando día bloqueado:',
            error
        );

        return false;
    }
}

// Devuelve los perfiles de todos los barberos.
// Se utiliza también para citas históricas, por eso NO filtramos activo aquí.
async function obtenerMapaPerfiles() {
    try {
        const [rows] = await pool.query(
            'SELECT id, nombre FROM barberos'
        );

        const mapa = {};

        rows.forEach(barbero => {
            mapa[barbero.id] = barbero.nombre;
        });

        return mapa;

    } catch (error) {
        console.error('Error obteniendo perfiles:', error);

        return {};
    }
}


const DURACION_SESION = 8 * 60 * 60 * 1000;


// ============================================================
// SESIONES
// ============================================================

function crearSesion(res, usuario) {

    const token = jwt.sign(
        {
            id: usuario.id,
            nombre: usuario.nombre,
            rol: usuario.rol
        },
        JWT_SECRET,
        {
            expiresIn: '8h'
        }
    );

    res.cookie('parce_session', token, {
        httpOnly: true,
        secure: process.env.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: DURACION_SESION
    });
}


function requiereSesion(req, res, next) {

    try {

        const token = req.cookies.parce_session;

        if (!token) {
            return res.status(401).json({
                success: false,
                message: 'Debes iniciar sesión.'
            });
        }

        req.usuario = jwt.verify(token, JWT_SECRET);

        next();

    } catch (error) {

        return res.status(401).json({
            success: false,
            message: 'Tu sesión venció. Inicia sesión nuevamente.'
        });
    }
}


function requiereJefe(req, res, next) {

    if (!esJefe(req.usuario)) {

        return res.status(403).json({
            success: false,
            message: 'No tienes permiso para acceder a esta sección.'
        });
    }

    next();
}

function requiereBarbero(req, res, next) {

    if (!req.usuario || !req.usuario.rol) {
        return res.status(403).json({
            success: false,
            message: 'No tienes permisos para realizar esta acción.'
        });
    }

    const rol = String(req.usuario.rol)
        .trim()
        .toLowerCase();

    const rolesPermitidos = [
        'barbero',
        'jefe barber'
    ];

    if (!rolesPermitidos.includes(rol)) {
        return res.status(403).json({
            success: false,
            message: 'No tienes permisos para bloquear horarios.'
        });
    }

    next();
}

// Comprueba que la cuenta que está utilizando la sesión
// siga activa en MySQL.
async function requiereBarberoActivo(req, res, next) {

    try {

        const [rows] = await pool.query(
            `SELECT id, nombre, rol, activo
             FROM barberos
             WHERE id = ?
             LIMIT 1`,
            [req.usuario.id]
        );

        if (rows.length === 0) {

            return res.status(401).json({
                success: false,
                message: 'Tu cuenta ya no existe.'
            });
        }

        if (Number(rows[0].activo) !== 1) {

            res.clearCookie('parce_session');

            return res.status(403).json({
                success: false,
                message: 'Esta cuenta se encuentra desactivada.'
            });
        }

        // Actualizamos datos importantes de la sesión
        // desde la BD y no desde datos antiguos del JWT.
        req.usuario.nombre = rows[0].nombre;
        req.usuario.rol = rows[0].rol;

        next();

    } catch (error) {

        console.error('Error comprobando estado del barbero:', error);

        return res.status(500).json({
            success: false,
            message: 'No se pudo comprobar el estado de la cuenta.'
        });
    }
}


// ============================================================
// PROTEGER JEFE.HTML
// ============================================================

app.get(
    '/jefe.html',
    requiereSesion,
    requiereJefe,
    (req, res) => {
        res.sendFile(
            path.join(__dirname, 'public', 'jefe.html')
        );
    }
);


// Archivos públicos
app.use(
    express.static(
        path.join(__dirname, 'public')
    )
);


// ============================================================
// LOGIN
// ============================================================

app.post(
    '/api/auth/login',
    loginLimiter,
    async (req, res) => {

    try {

        const usuarioIngresado =
            String(req.body.usuario || '')
                .trim()
                .toLowerCase();

        const contrasena =
            String(req.body.contrasena || '');

        if (!usuarioIngresado || !contrasena) {

            return res.status(400).json({
                success: false,
                message: 'Ingresa usuario y contraseña.'
            });
        }


        const [filas] = await pool.query(
            `SELECT id, nombre, rol, usuario, contrasena, activo
             FROM barberos
             WHERE LOWER(usuario) = ?
             LIMIT 1`,
            [usuarioIngresado]
        );


        const usuario = filas[0];


        if (!usuario) {

            return res.status(401).json({
                success: false,
                message: 'Usuario o contraseña incorrectos.'
            });
        }


        // Primero comprobamos si está activo.
        if (Number(usuario.activo) !== 1) {

            return res.status(403).json({
                success: false,
                message: 'Esta cuenta se encuentra desactivada.'
            });
        }


        const passwordCorrecta =
            await bcrypt.compare(
                contrasena,
                usuario.contrasena
            );


        if (!passwordCorrecta) {

            return res.status(401).json({
                success: false,
                message: 'Usuario o contraseña incorrectos.'
            });
        }


        crearSesion(res, usuario);


        return res.json({
            success: true,
            usuario: {
                id: usuario.id,
                nombre: usuario.nombre,
                rol: usuario.rol,
                esJefe: esJefe(usuario)
            }
        });


    } catch (error) {

        console.error('Error al iniciar sesión:', error);

        return res.status(500).json({
            success: false,
            message: 'No se pudo iniciar sesión.'
        });
    }
});


// ============================================================
// CERRAR SESIÓN
// ============================================================

app.post('/api/auth/cerrar-sesion', (req, res) => {

    res.clearCookie('parce_session');

    res.json({
        success: true
    });
});


// ============================================================
// SESIÓN ACTUAL
// ============================================================

app.get(
    '/api/auth/sesion',
    requiereSesion,
    async (req, res) => {

        try {

            const [rows] = await pool.query(
                `SELECT id, nombre, rol, activo
                 FROM barberos
                 WHERE id = ?
                 LIMIT 1`,
                [req.usuario.id]
            );

            if (rows.length === 0) {

                res.clearCookie('parce_session');

                return res.status(401).json({
                    success: false,
                    message: 'Tu cuenta ya no existe.'
                });
            }

            if (Number(rows[0].activo) !== 1) {

                res.clearCookie('parce_session');

                return res.status(403).json({
                    success: false,
                    message: 'Esta cuenta se encuentra desactivada.'
                });
            }

            const usuario = rows[0];

            res.json({
                success: true,
                usuario: {
                    id: usuario.id,
                    nombre: usuario.nombre,
                    rol: usuario.rol,
                    esJefe: esJefe(usuario)
                }
            });

        } catch (error) {

            console.error('Error comprobando sesión:', error);

            res.status(500).json({
                success: false,
                message: 'No se pudo comprobar la sesión.'
            });
        }
    }
);


// ============================================================
// AGENDAR CITA DIRECTA
// ============================================================

app.post('/api/agenda-directa', async (req, res) => {

    try {

        const {
            barberoId,
            servicio,
            fecha,
            hora,
            cliente,
            telefono,
            email
        } = req.body;

        // ====================================================
// COMPROBAR DÍA BLOQUEADO
// ====================================================

const fechaLocal =
    new Date(`${fecha}T12:00:00`);

const diaSemana =
    fechaLocal.getDay();


// Los domingos nunca están disponibles.
if (diaSemana === 0) {

    return res.json({
        success: false,
        message:
            'Los domingos no atendemos. Por favor, elige otro día.'
    });
}


// Comprobar si el barbero bloqueó ese día.
if (
    await esDiaBloqueado(
        barberoId,
        fecha
    )
) {

    return res.json({
        success: false,
        message:
            'Este día no está disponible para este especialista. Por favor, elige otro día.'
    });
}


        // Comprobamos en BD que el barbero esté activo.
        if (!(await esBarberoDisponible(barberoId))) {

            return res.json({
                success: false,
                message:
                    'Este barbero ya no se encuentra disponible. Por favor, elige otro especialista.'
            });
        }


        // ====================================================
        // SERVICIOS DE 4 HORAS
        // ====================================================

        let esServicioLargo = false;

        let horasRequeridas = [hora];

        const serviciosJesus = [
            'Rulos permanentes',
            'Ondulado permanente'
        ];

        const serviciosParce = [
            'Tintura de pelo (visos)',
            'Tintura de pelo (global)'
        ];


        if (
            (Number(barberoId) === 2 &&
                serviciosJesus.includes(servicio))
            ||
            (Number(barberoId) === 1 &&
                serviciosParce.includes(servicio))
        ) {

            esServicioLargo = true;

            const horaBase =
                parseInt(
                    String(hora).split(':')[0]
                );

            horasRequeridas = [
                `${horaBase}:00`,
                `${horaBase + 1}:00`,
                `${horaBase + 2}:00`,
                `${horaBase + 3}:00`
            ];
        }


        // ====================================================
        // COMPROBAR DISPONIBILIDAD
        // ====================================================

        const [existentes] = await pool.query(
            `SELECT hora
             FROM agendamientos
             WHERE barberoId = ?
             AND fecha = ?
             AND hora IN (?)`,
            [
                barberoId,
                fecha,
                horasRequeridas
            ]
        );


        if (existentes.length > 0) {

            if (esServicioLargo) {

                return res.json({
                    success: false,
                    message:
                        'Este servicio requiere 4 horas continuas y no hay disponibilidad suficiente desde esa hora. Por favor, elige una hora más temprana u otro día.'
                });

            } else {

                return res.json({
                    success: false,
                    message:
                        'Esta hora ya fue tomada. Por favor recarga la página.'
                });
            }
        }


        // ====================================================
        // INSERTAR CITA
        // ====================================================

        for (let i = 0; i < horasRequeridas.length; i++) {

            const servicioGuardado =
                i === 0
                    ? servicio
                    : `${servicio} (Bloqueo Continuo)`;


            await pool.query(
                `INSERT INTO agendamientos
                (barberoId, servicio, fecha, hora, cliente, telefono, email)
                VALUES (?, ?, ?, ?, ?, ?, ?)`,
                [
                    barberoId,
                    servicioGuardado,
                    fecha,
                    horasRequeridas[i],
                    cliente,
                    telefono,
                    email
                ]
            );
        }


        // ====================================================
        // CORTE VIP
        // ====================================================

        const contacto = email || telefono;

        if (contacto) {

            await pool.query(
                `INSERT INTO clientes_cortes
                (contacto, cantidad)
                VALUES (?, 1)
                ON DUPLICATE KEY UPDATE
                cantidad = cantidad + 1`,
                [contacto]
            );
        }


        // ====================================================
        // CORREO
        // ====================================================

        const perfiles =
            await obtenerMapaPerfiles();

        await enviarCorreo(
            email,
            cliente,
            perfiles[barberoId] || 'Especialista Asignado',
            servicio,
            fecha,
            hora
        );


        res.json({
            success: true,
            message: 'Hora agendada correctamente.'
        });


    } catch (error) {

    console.error(
        'Error agendando cita:',
        error
    );


    // Error de clave única:
    // otro cliente tomó la misma hora.
    if (error.code === 'ER_DUP_ENTRY') {

        return res.status(409).json({
            success: false,
            message:
                'Esta hora acaba de ser tomada por otro cliente. Por favor, elige otra hora.'
        });
    }


    return res.status(500).json({
        success: false,
        message:
            'Error al agendar en la base de datos.'
    });
}
});


// ============================================================
// AGENDADO RÁPIDO
// ============================================================

app.post('/api/agendado-rapido', async (req, res) => {

    try {

        const {
            servicio,
            cliente,
            telefono,
            email
        } = req.body;


        const horasPermitidas = [
            '10:00',
            '11:00',
            '12:00',
            '13:00',
            '14:00',
            '15:00',
            '16:00',
            '17:00',
            '18:00',
            '19:00'
        ];


        // SOLO BARBEROS ACTIVOS
        const [barberosBD] = await pool.query(
            `SELECT id
             FROM barberos
             WHERE activo = 1
             ORDER BY id ASC`
        );


        const barberosIds =
            barberosBD.map(
                b => Number(b.id)
            );


        if (barberosIds.length === 0) {

            return res.json({
                success: false,
                message:
                    'No hay barberos disponibles en el sistema.'
            });
        }


        let hoy = new Date();

        let fechaAsignada = null;
        let horaAsignada = null;
        let barberoAsignado = null;


        const hoyStr =
            hoy.toISOString().split('T')[0];


        const [citasOcupadas] =
            await pool.query(
                `SELECT barberoId, fecha, hora
                 FROM agendamientos
                 WHERE fecha >= ?`,
                [hoyStr]
            );


        for (let d = 0; d < 7; d++) {

    const fechaPrueba =
        new Date(hoy);

    fechaPrueba.setDate(
        hoy.getDate() + d
    );


    // ========================================================
    // DOMINGOS NO LABORABLES
    // ========================================================

    if (fechaPrueba.getDay() === 0) {
        continue;
    }


            const fechaStr =
                fechaPrueba
                    .toISOString()
                    .split('T')[0];


            for (const hora of horasPermitidas) {

                if (d === 0) {

                    const horaActual =
                        hoy.getHours();

                    const horaEval =
                        parseInt(
                            hora.split(':')[0]
                        );

                    if (horaEval <= horaActual) {
                        continue;
                    }
                }


                for (const bId of barberosIds) {

    // ========================================================
    // COMPROBAR SI EL BARBERO BLOQUEÓ EL DÍA COMPLETO
    // ========================================================

    const diaBloqueado =
        await esDiaBloqueado(
            bId,
            fechaStr
        );


    if (diaBloqueado) {
        continue;
    }


    // ========================================================
    // COMPROBAR SI LA HORA ESTÁ OCUPADA
    // ========================================================

    const ocupado =
        citasOcupadas.find(
            a =>
                a.fecha === fechaStr &&
                a.hora === hora &&
                Number(a.barberoId) === Number(bId)
        );


    if (!ocupado) {

        fechaAsignada = fechaStr;
        horaAsignada = hora;
        barberoAsignado = bId;

        break;
    }
}


                if (fechaAsignada) {
                    break;
                }
            }


            if (fechaAsignada) {
                break;
            }
        }


        if (!fechaAsignada) {

            return res.json({
                success: false,
                message: 'No hay horas disponibles.'
            });
        }


        await pool.query(
            `INSERT INTO agendamientos
            (barberoId, servicio, fecha, hora, cliente, telefono, email)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
            [
                barberoAsignado,
                servicio,
                fechaAsignada,
                horaAsignada,
                cliente,
                telefono,
                email
            ]
        );


        const perfiles =
            await obtenerMapaPerfiles();


        await enviarCorreo(
            email,
            cliente,
            perfiles[barberoAsignado] || 'Especialista',
            servicio,
            fechaAsignada,
            horaAsignada
        );


        res.json({
            success: true,
            asignado: {
                barbero:
                    perfiles[barberoAsignado] ||
                    'Especialista',
                fecha: fechaAsignada,
                hora: horaAsignada
            }
        });


    } catch (error) {

        console.error(
            'Error en agendado rápido:',
            error
        );

        res.status(500).json({
            success: false,
            message: 'Error interno del servidor.'
        });
    }
});


// ============================================================
// MIS CITAS CLIENTE
// ============================================================

app.get('/api/mis-citas/:email', async (req, res) => {

    try {

        const email = String(req.params.email || '')
            .trim()
            .toLowerCase();


        // Validar que realmente parezca un correo
        if (
            !email ||
            email.length > 254 ||
            !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)
        ) {

            return res.status(400).json({
                success: false,
                message: 'Correo electrónico inválido.'
            });
        }


        const [citas] = await pool.query(
            `SELECT *
             FROM agendamientos
             WHERE LOWER(email) = ?
             AND fecha >= CURDATE()
             ORDER BY fecha ASC, hora ASC`,
            [email]
        );


        res.json({
            success: true,
            citas
        });


    } catch (error) {

        console.error(
            'Error buscando citas:',
            error
        );

        res.status(500).json({
            success: false,
            message: 'Error al buscar citas.'
        });
    }
});

// ============================================================
// CANCELAR CITA CLIENTE
// ============================================================

app.post('/api/cancelar-cita', async (req, res) => {

    try {

        const { idCita, email } = req.body;


        // ====================================================
        // VALIDAR DATOS
        // ====================================================

        if (!idCita || !email) {

            return res.status(400).json({
                success: false,
                message: 'Datos insuficientes para cancelar la cita.'
            });
        }


        const emailCliente =
            String(email)
                .trim()
                .toLowerCase();


        if (!emailCliente) {

            return res.status(400).json({
                success: false,
                message: 'Debes indicar el correo del cliente.'
            });
        }


        // ====================================================
        // BUSCAR LA CITA
        // Y COMPROBAR QUE PERTENEZCA AL CLIENTE
        // ====================================================

        const [citas] = await pool.query(
            `SELECT *
             FROM agendamientos
             WHERE id = ?
             AND LOWER(email) = LOWER(?)
             LIMIT 1`,
            [
                idCita,
                emailCliente
            ]
        );


        if (citas.length === 0) {

            return res.status(403).json({
                success: false,
                message: 'No tienes permiso para cancelar esta cita.'
            });
        }


        // ====================================================
        // CANCELAR
        // ====================================================

        const [resultado] = await pool.query(
            `DELETE FROM agendamientos
             WHERE id = ?
             AND LOWER(email) = LOWER(?)`,
            [
                idCita,
                emailCliente
            ]
        );


        if (resultado.affectedRows === 0) {

            return res.status(404).json({
                success: false,
                message: 'No se pudo cancelar la cita.'
            });
        }


        return res.json({
            success: true,
            message: 'Hora cancelada.'
        });


    } catch (error) {

        console.error(
            'Error cancelando cita:',
            error
        );

        return res.status(500).json({
            success: false,
            message: 'Error al cancelar.'
        });
    }
});


// ============================================================
// MODIFICAR CITA
// ============================================================

app.post('/api/modificar-cita', async (req, res) => {

    try {

        const {
            idCita,
            nuevoBarberoId,
            nuevaFecha,
            nuevaHora,
            email
        } = req.body;


        if (!idCita || !nuevoBarberoId || !nuevaFecha || !nuevaHora || !email) {
            return res.status(400).json({
                success: false,
                message: 'Faltan datos para modificar la cita.'
            });
        }


        // ====================================================
        // 1. BUSCAR LA CITA Y VERIFICAR QUE PERTENEZCA
        //    AL CLIENTE QUE ESTÁ HACIENDO LA MODIFICACIÓN
        // ====================================================

        const [citas] = await pool.query(
            `SELECT *
             FROM agendamientos
             WHERE id = ?
             AND LOWER(email) = LOWER(?)
             LIMIT 1`,
            [
                idCita,
                email.trim()
            ]
        );


        if (citas.length === 0) {

            return res.status(403).json({
                success: false,
                message:
                    'No tienes permiso para modificar esta cita.'
            });
        }


        const cita = citas[0];


        // ====================================================
        // 2. COMPROBAR QUE EL NUEVO BARBERO ESTÉ ACTIVO
        // ====================================================

        if (!(await esBarberoDisponible(nuevoBarberoId))) {

            return res.json({
                success: false,
                message:
                    'Este barbero ya no se encuentra disponible. Por favor, elige otro especialista.'
            });
        }


        // ====================================================
        // 3. COMPROBAR QUE LA NUEVA HORA ESTÉ LIBRE
        // ====================================================

        const [ocupado] = await pool.query(
            `SELECT id
             FROM agendamientos
             WHERE barberoId = ?
             AND fecha = ?
             AND hora = ?
             AND id != ?`,
            [
                nuevoBarberoId,
                nuevaFecha,
                nuevaHora,
                idCita
            ]
        );


        if (ocupado.length > 0) {

            return res.json({
                success: false,
                message: 'Hora ocupada.'
            });
        }


        // ====================================================
        // 4. ACTUALIZAR LA CITA
        // ====================================================

        const [resultado] = await pool.query(
            `UPDATE agendamientos
             SET barberoId = ?,
                 fecha = ?,
                 hora = ?
             WHERE id = ?
             AND LOWER(email) = LOWER(?)`,
            [
                nuevoBarberoId,
                nuevaFecha,
                nuevaHora,
                idCita,
                email.trim()
            ]
        );


        if (resultado.affectedRows === 0) {

            return res.json({
                success: false,
                message:
                    'No se pudo actualizar la cita.'
            });
        }


        // ====================================================
        // 5. OBTENER NOMBRE DEL NUEVO BARBERO
        // ====================================================

        const perfiles =
            await obtenerMapaPerfiles();


        // ====================================================
        // 6. ENVIAR CORREO
        // ====================================================

        await enviarCorreo(
            cita.email,
            cita.cliente,
            perfiles[nuevoBarberoId] ||
                'Especialista',
            cita.servicio,
            nuevaFecha,
            nuevaHora
        );


        return res.json({
            success: true,
            message: '¡Hora modificada!'
        });


    } catch (error) {

        console.error(
            'Error al modificar cita:',
            error
        );

        return res.status(500).json({
            success: false,
            message:
                'Error al modificar.'
        });
    }
});

// ============================================================
// AGENDA DEL BARBERO
// ============================================================

app.get(
    '/api/barbero/mi-agenda',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const [perfiles] =
                await pool.query(
                    `SELECT id, nombre, rol, horarios
                     FROM barberos
                     WHERE id = ?
                     AND activo = 1
                     LIMIT 1`,
                    [req.usuario.id]
                );


            if (perfiles.length === 0) {

                return res.status(404).json({
                    success: false,
                    message: 'No se encontró tu perfil.'
                });
            }


            // IMPORTANTE:
            // Incluimos barberoId porque barbero.html
            // utiliza este campo para filtrar sus citas.
            const [agendamientos] =
                await pool.query(
                    `SELECT
                        id,
                        barberoId,
                        servicio,
                        fecha,
                        hora,
                        cliente,
                        telefono,
                        email,
                        estado
                     FROM agendamientos
                     WHERE barberoId = ?
                     ORDER BY fecha ASC, hora ASC`,
                    [req.usuario.id]
                );


            const contactos = [
                ...new Set(
                    agendamientos
                        .map(
                            cita =>
                                cita.email ||
                                cita.telefono
                        )
                        .filter(Boolean)
                )
            ];


            let clientesCortes = {};


            if (contactos.length > 0) {

                const [cortes] =
                    await pool.query(
                        `SELECT contacto, cantidad
                         FROM clientes_cortes
                         WHERE contacto IN (?)`,
                        [contactos]
                    );


                cortes.forEach(cliente => {

                    clientesCortes[
                        cliente.contacto
                    ] = cliente.cantidad;

                });
            }


            res.json({
                success: true,
                perfil: perfiles[0],
                agendamientos,
                clientesCortes
            });


        } catch (error) {

            console.error(
                'Error cargando agenda del barbero:',
                error
            );

            res.status(500).json({
                success: false,
                message: 'No se pudo cargar la agenda.'
            });
        }
    }
);


// ============================================================
// DATOS DEL JEFE
// ============================================================

app.get(
    '/api/admin/datos',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const [citas] =
                await pool.query(
                    `SELECT *
                     FROM agendamientos
                     ORDER BY fecha ASC, hora ASC`
                );


            const [cortes] =
                await pool.query(
                    'SELECT * FROM clientes_cortes'
                );


            let clientesCortes = {};


            cortes.forEach(c => {

                clientesCortes[
                    c.contacto
                ] = c.cantidad;

            });


            // Aquí usamos TODOS los barberos, incluidos
            // los desactivados, para que las citas históricas
            // sigan mostrando correctamente su nombre.
            const perfiles =
                await obtenerMapaPerfiles();


            const agendamientos =
                citas.map(cita => ({

                    ...cita,

                    barberoName:
                        perfiles[cita.barberoId] ||
                        'Desconocido'

                }));


            // NUNCA enviamos contraseñas al navegador.
            const [barberos] =
                await pool.query(
                    `SELECT
                        id,
                        nombre,
                        rol,
                        historia,
                        usuario,
                        horarios,
                        activo
                     FROM barberos
                     ORDER BY id ASC`
                );


            res.json({
                agendamientos,
                clientesCortes,
                barberos
            });


        } catch (error) {

            console.error(
                'Error cargando datos administrativos:',
                error
            );

            res.status(500).json({
                agendamientos: [],
                clientesCortes: {},
                barberos: []
            });
        }
    }
);


// ============================================================
// GUARDAR BARBERO
// ============================================================

app.post(
    '/api/admin/guardar-barbero',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const {
                id,
                nombre,
                rol,
                historia,
                usuario,
                contrasena
            } = req.body;


            if (!nombre || !rol || !usuario) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Nombre, rol y usuario son obligatorios.'
                });
            }


            // =================================================
            // EDITAR
            // =================================================

            if (id) {

                // Si no se escribió contraseña,
                // mantenemos el hash actual.
                if (
                    !contrasena ||
                    contrasena.trim() === ''
                ) {

                    await pool.query(
                        `UPDATE barberos
                         SET nombre = ?,
                             rol = ?,
                             historia = ?,
                             usuario = ?
                         WHERE id = ?`,
                        [
                            nombre,
                            rol,
                            historia,
                            usuario,
                            id
                        ]
                    );

                } else {

                    const hash =
                        await bcrypt.hash(
                            contrasena,
                            12
                        );


                    await pool.query(
                        `UPDATE barberos
                         SET nombre = ?,
                             rol = ?,
                             historia = ?,
                             usuario = ?,
                             contrasena = ?
                         WHERE id = ?`,
                        [
                            nombre,
                            rol,
                            historia,
                            usuario,
                            hash,
                            id
                        ]
                    );
                }


                return res.json({
                    success: true,
                    message:
                        'Barbero actualizado correctamente.'
                });
            }


            // =================================================
            // CREAR
            // =================================================

            if (
                !contrasena ||
                contrasena.trim() === ''
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La contraseña es obligatoria para un nuevo barbero.'
                });
            }


            const hash =
                await bcrypt.hash(
                    contrasena,
                    12
                );


            await pool.query(
                `INSERT INTO barberos
                (
                    nombre,
                    rol,
                    historia,
                    usuario,
                    contrasena,
                    activo
                )
                VALUES (?, ?, ?, ?, ?, 1)`,
                [
                    nombre,
                    rol,
                    historia,
                    usuario,
                    hash
                ]
            );


            return res.json({
                success: true,
                message:
                    'Nuevo barbero incorporado al staff.'
            });


        } catch (error) {

            console.error(
                'Error al guardar barbero:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Error interno al guardar los datos del barbero.'
            });
        }
    }
);


// ============================================================
// DESACTIVAR BARBERO
// ============================================================

app.delete(
    '/api/admin/eliminar-barbero/:id',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

           const barberoId = Number(req.params.id);


if (
    !Number.isInteger(barberoId) ||
    barberoId <= 0
) {

    return res.status(400).json({
        success: false,
        message:
            'ID de barbero inválido.'
    });
}


// El jefe no puede desactivarse a sí mismo.
if (barberoId === Number(req.usuario.id)) {

    return res.status(400).json({
        success: false,
        message:
            'No puedes desactivar tu propia cuenta.'
    });
}


            // NO BORRAMOS EL REGISTRO.
            // Solo lo desactivamos.
            const [resultado] =
                await pool.query(
                    `UPDATE barberos
                     SET activo = 0
                     WHERE id = ?`,
                    [barberoId]
                );


            if (resultado.affectedRows === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        'No se encontró el barbero.'
                });
            }


            res.json({
                success: true,
                message:
                    'Barbero desactivado correctamente.'
            });


        } catch (error) {

            console.error(
                'Error al desactivar barbero:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'No se pudo desactivar el barbero.'
            });
        }
    }
);

// ============================================================
// OBTENER DÍAS BLOQUEADOS DEL BARBERO
// ============================================================

app.get(
    '/api/barbero/dias-bloqueados',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const [dias] =
                await pool.query(
                    `SELECT fecha
                     FROM dias_bloqueados
                     WHERE barberoId = ?
                     ORDER BY fecha ASC`,
                    [
                        req.usuario.id
                    ]
                );


            return res.json({
                success: true,
                dias: dias.map(
                    dia => dia.fecha
                )
            });


        } catch (error) {

            console.error(
                'Error obteniendo días bloqueados:',
                error
            );

            return res.status(500).json({
                success: false,
                dias: [],
                message:
                    'No se pudieron cargar los días bloqueados.'
            });
        }
    }
);


// ============================================================
// ELIMINAR CITA DESDE JEFE
// ============================================================

app.delete(
    '/api/admin/eliminar-cita/:id',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const [resultado] =
                await pool.query(
                    'DELETE FROM agendamientos WHERE id = ?',
                    [req.params.id]
                );


            res.json({
                success:
                    resultado.affectedRows > 0,
                message:
                    resultado.affectedRows > 0
                        ? 'Cita borrada.'
                        : 'No se encontró la cita.'
            });


        } catch (error) {

            console.error(
                'Error al eliminar cita:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Error al borrar.'
            });
        }
    }
);


// ============================================================
// BLOQUEAR HORARIO DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/bloquear',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const {
                fecha,
                hora
            } = req.body;


            if (!fecha || !hora) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Fecha y hora son obligatorias.'
                });
            }


            // IMPORTANTE:
            // NO usamos barberoId enviado por el navegador.
            // Usamos el ID de la sesión.
            await pool.query(
                `INSERT INTO agendamientos
                (
                    barberoId,
                    servicio,
                    fecha,
                    hora,
                    cliente,
                    telefono,
                    email,
                    estado
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
                [
                    req.usuario.id,
                    'BLOQUEADO',
                    fecha,
                    hora,
                    'Descanso / Inasistencia',
                    '-',
                    '-',
                    'Bloqueado'
                ]
            );


            res.json({
                success: true
            });


        } catch (error) {

            console.error(
                'Error al bloquear horario:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'No se pudo bloquear el horario.'
            });
        }
    }
);

// ============================================================
// BLOQUEAR DÍA COMPLETO DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/bloquear-dia',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const { fecha } = req.body;

            if (!fecha) {

                return res.status(400).json({
                    success: false,
                    message: 'Debes indicar una fecha.'
                });
            }


            // Los domingos son días no laborables
            // y quedan bloqueados automáticamente.
            const fechaLocal =
                new Date(`${fecha}T12:00:00`);

            const diaSemana =
                fechaLocal.getDay();

            if (diaSemana === 0) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Los domingos son días no laborables y ya están bloqueados.'
                });
            }


            await pool.query(
                `INSERT INTO dias_bloqueados
                (
                    barberoId,
                    fecha
                )
                VALUES (?, ?)
                ON DUPLICATE KEY UPDATE
                    fecha = VALUES(fecha)`,
                [
                    req.usuario.id,
                    fecha
                ]
            );


            return res.json({
                success: true,
                message: 'Día bloqueado correctamente.'
            });


        } catch (error) {

            console.error(
                'Error al bloquear día:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'No se pudo bloquear el día.'
            });
        }
    }
);

// ============================================================
// DESBLOQUEAR DÍA COMPLETO DEL BARBERO
// ============================================================

app.delete(
    '/api/barbero/desbloquear-dia/:fecha',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const fecha =
                String(req.params.fecha || '').trim();


            if (!fecha) {

                return res.status(400).json({
                    success: false,
                    message: 'Debes indicar una fecha.'
                });
            }


            // Los domingos son siempre no laborables.
            const fechaLocal =
                new Date(`${fecha}T12:00:00`);

            const diaSemana =
                fechaLocal.getDay();


            if (diaSemana === 0) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Los domingos no se pueden desbloquear porque son días no laborables.'
                });
            }


            const [resultado] =
                await pool.query(
                    `DELETE FROM dias_bloqueados
                     WHERE barberoId = ?
                     AND fecha = ?`,
                    [
                        req.usuario.id,
                        fecha
                    ]
                );


            return res.json({
                success: true,
                message:
                    resultado.affectedRows > 0
                        ? 'Día desbloqueado correctamente.'
                        : 'Ese día no estaba bloqueado.'
            });


        } catch (error) {

            console.error(
                'Error al desbloquear día:',
                error
            );

            return res.status(500).json({
                success: false,
                message:
                    'No se pudo desbloquear el día.'
            });
        }
    }
);

// ============================================================
// CANCELAR CITA DESDE PANEL DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/cancelar',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const { idCita } =
                req.body;


            if (!idCita) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Debes indicar la cita.'
                });
            }


            // Primero obtenemos la cita.
            const [citas] =
                await pool.query(
                    `SELECT *
                     FROM agendamientos
                     WHERE id = ?`,
                    [idCita]
                );


            if (citas.length === 0) {

                return res.status(404).json({
                    success: false,
                    message:
                        'La cita no existe.'
                });
            }


            const cita = citas[0];


            // SEGURIDAD:
            // El barbero solo puede cancelar citas suyas.
            if (
                Number(cita.barberoId) !==
                Number(req.usuario.id)
            ) {

                return res.status(403).json({
                    success: false,
                    message:
                        'No tienes permiso para cancelar esta cita.'
                });
            }


            const perfiles =
                await obtenerMapaPerfiles();


            const nombreBarbero =
                perfiles[cita.barberoId] ||
                'Tu Barbero';


            await pool.query(
                'DELETE FROM agendamientos WHERE id = ?',
                [idCita]
            );


            if (cita.email) {

    try {

        const { data, error } = await resend.emails.send({

            from: EMAIL_REMITENTE,

            to: [cita.email],

            subject:
                '⚠️ Tu cita ha sido cancelada por un imprevisto',

            html:
                `<div style="font-family: Arial; padding: 25px; max-width: 500px; margin: auto; background-color: #0a0a0a; color: #fff; border-radius: 12px; border: 1px solid #333;">

                    <h1 style="color: #ff3333; text-align:center;">
                        Cita Cancelada
                    </h1>

                    <p>
                        Hola <strong>${cita.cliente}</strong>,
                    </p>

                    <p>
                        Lamentamos informarte que tu barbero
                        <strong>${nombreBarbero}</strong>
                        ha tenido un imprevisto de fuerza mayor
                        y tuvimos que cancelar tu cita programada
                        para el <strong>${cita.fecha}</strong>
                        a las <strong>${cita.hora}</strong>.
                    </p>

                    <div style="background: #151515; padding: 15px; border-left: 4px solid #ffb700; margin-top: 15px;">

                        <p style="margin: 0;">
                            ¡Pero no te preocupes!
                            Queremos atenderte.
                            Por favor,
                            <strong>reagenda tu hora</strong>
                            en nuestro sistema.
                        </p>

                    </div>

                </div>`
        });

        if (error) {

            console.error(
                '❌ Error enviando cancelación con Resend:',
                error
            );

        } else {

            console.log(
                '📧 Correo de cancelación enviado:',
                data?.id
            );
        }

    } catch (error) {

        console.error(
            '❌ Error inesperado enviando correo de cancelación:',
            error
        );
    }
}

            res.json({
                success: true,
                message:
                    'Cita cancelada y cliente notificado.'
            });


        } catch (error) {

            console.error(
                'Error cancelando cita del barbero:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Error en el servidor.'
            });
        }
    }
);


// ============================================================
// SERVICIOS
// ============================================================

app.get('/api/servicios', async (req, res) => {

    try {

        const [servicios] =
            await pool.query(
                'SELECT * FROM servicios ORDER BY nombre ASC'
            );


        res.json({
            success: true,
            servicios
        });


    } catch (error) {

        console.error(
            'Error al cargar servicios:',
            error
        );

        res.status(500).json({
            success: false,
            message:
                'Error al cargar servicios'
        });
    }
});


// ============================================================
// GUARDAR SERVICIO
// ============================================================

app.post(
    '/api/admin/guardar-servicio',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const {
                id,
                nombre,
                precio
            } = req.body;


            if (!nombre) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El nombre del servicio es obligatorio.'
                });
            }


            if (id) {

                await pool.query(
                    `UPDATE servicios
                     SET nombre = ?, precio = ?
                     WHERE id = ?`,
                    [
                        nombre,
                        precio,
                        id
                    ]
                );


                return res.json({
                    success: true,
                    message:
                        'Servicio actualizado correctamente.'
                });
            }


            await pool.query(
                `INSERT INTO servicios
                (nombre, precio)
                VALUES (?, ?)`,
                [
                    nombre,
                    precio
                ]
            );


            res.json({
                success: true,
                message:
                    'Nuevo servicio creado exitosamente.'
            });


        } catch (error) {

            console.error(
                'Error guardando servicio:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'Error interno al guardar el servicio.'
            });
        }
    }
);


// ============================================================
// ELIMINAR SERVICIO
// ============================================================

app.delete(
    '/api/admin/eliminar-servicio/:id',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const [resultado] =
                await pool.query(
                    'DELETE FROM servicios WHERE id = ?',
                    [req.params.id]
                );


            res.json({
                success:
                    resultado.affectedRows > 0,
                message:
                    resultado.affectedRows > 0
                        ? 'Servicio eliminado de la lista.'
                        : 'No se encontró el servicio.'
            });


        } catch (error) {

            console.error(
                'Error eliminando servicio:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'No se pudo eliminar el servicio.'
            });
        }
    }
);


// ============================================================
// GUARDAR HORARIOS DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/guardar-horarios',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const { horarios } =
                req.body;


            // NO usamos barberoId del navegador.
            await pool.query(
                `UPDATE barberos
                 SET horarios = ?
                 WHERE id = ?`,
                [
                    horarios,
                    req.usuario.id
                ]
            );


            res.json({
                success: true,
                message:
                    'Tus horas se han guardado con éxito.'
            });


        } catch (error) {

            console.error(
                'Error guardando horarios:',
                error
            );

            res.status(500).json({
                success: false,
                message:
                    'No se pudieron guardar las horas.'
            });
        }
    }
);


// ============================================================
// HORARIOS PÚBLICOS
// ============================================================

app.get(
    '/api/horarios-publicos/:barberoId',
    async (req, res) => {

        try {

            const barberoId =
                Number(req.params.barberoId);

            const fecha =
                req.query.fecha;


            if (
                !Number.isInteger(barberoId) ||
                barberoId <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    horarios: [],
                    ocupadas: [],
                    message:
                        'Barbero inválido.'
                });
            }


            // Solo barberos activos.
            const [barberos] =
                await pool.query(
                    `SELECT horarios
                     FROM barberos
                     WHERE id = ?
                     AND activo = 1
                     LIMIT 1`,
                    [barberoId]
                );


            if (barberos.length === 0) {

                return res.status(404).json({
                    success: false,
                    horarios: [],
                    ocupadas: [],
                    message:
                        'Este barbero no está disponible.'
                });
            }


            let horasLista = [
                '10:00',
                '11:00',
                '12:00',
                '13:00',
                '14:00',
                '15:00',
                '16:00',
                '17:00',
                '18:00',
                '19:00'
            ];


            let ocupadas = [];


            if (barberos[0].horarios) {

                horasLista =
                    barberos[0]
                        .horarios
                        .split(',')
                        .map(
                            h => h.trim()
                        )
                        .filter(
                            h => h !== ''
                        );
            }


            if (fecha) {

    // ========================================================
    // DOMINGOS BLOQUEADOS AUTOMÁTICAMENTE
    // ========================================================

    const fechaLocal =
        new Date(`${fecha}T12:00:00`);

    const diaSemana =
        fechaLocal.getDay();


    if (diaSemana === 0) {

        return res.json({
            success: true,
            horarios: [],
            ocupadas: horasLista,
            diaBloqueado: true
        });
    }


    // ========================================================
    // COMPROBAR SI EL BARBERO BLOQUEÓ EL DÍA
    // ========================================================

    const diaBloqueado =
        await esDiaBloqueado(
            barberoId,
            fecha
        );


    if (diaBloqueado) {

        return res.json({
            success: true,
            horarios: [],
            ocupadas: horasLista,
            diaBloqueado: true
        });
    }


    // ========================================================
    // HORAS OCUPADAS NORMALMENTE
    // ========================================================

    const [citasExistentes] =
        await pool.query(
            `SELECT hora
             FROM agendamientos
             WHERE barberoId = ?
             AND fecha = ?`,
            [
                barberoId,
                fecha
            ]
        );


    ocupadas =
        citasExistentes.map(
            cita => cita.hora
        );
}


            res.json({
                success: true,
                horarios: horasLista,
                ocupadas
            });


        } catch (error) {

            console.error(
                'Error al obtener horarios:',
                error
            );

            res.status(500).json({
                success: false,
                horarios: [],
                ocupadas: []
            });
        }
    }
);


// ============================================================
// CORREO DE CONFIRMACIÓN
// ============================================================

async function enviarCorreo(
    email,
    cliente,
    barbero,
    servicio,
    fecha,
    hora
) {

    if (!email) {
        console.log('📧 No se envió correo: cliente sin email.');
        return;
    }

    try {

        const { data, error } = await resend.emails.send({

            from: EMAIL_REMITENTE,

            to: [email],

            subject:
                '¡Cita confirmada en Parce Barber! ✂️🔥',

            html:
                `<div style="font-family: Arial, sans-serif; padding: 25px; background-color: #0a0a0a; color: #ffffff; border: 1px solid #333; border-radius: 12px; max-width: 600px; margin: auto;">

                    <h1 style="color: #ffb700; text-align: center;">
                        ✂️ Parce Barber
                    </h1>

                    <h2 style="color: #ffffff; text-align: center;">
                        Reserva Confirmada
                    </h2>

                    <p>
                        Hola <strong>${cliente}</strong>,
                    </p>

                    <p>
                        Tu hora ha sido agendada correctamente.
                    </p>

                    <div style="background: #151515; padding: 20px; border-radius: 10px; margin-top: 20px;">

                        <p>
                            <strong>Barbero:</strong>
                            ${barbero}
                        </p>

                        <p>
                            <strong>Servicio:</strong>
                            ${servicio}
                        </p>

                        <p>
                            <strong>Día:</strong>
                            ${fecha}
                        </p>

                        <p>
                            <strong>Hora:</strong>
                            <span style="color:#ffb700; font-size: 20px;">
                                ${hora}
                            </span>
                        </p>

                    </div>

                    <p style="margin-top: 25px;">
                        ¡Te esperamos en Parce Barber! 🔥
                    </p>

                </div>`
        });

        if (error) {

            console.error(
                '❌ Error enviando correo con Resend:',
                error
            );

            return;
        }

        console.log(
            '📧 Correo enviado correctamente con Resend:',
            data?.id
        );

    } catch (error) {

        console.error(
            '❌ Error inesperado enviando correo:',
            error
        );
    }
}


// ============================================================
// INICIAR SERVIDOR
// ============================================================

app.listen(PORT, async () => {

    try {

        await pool.query('SELECT 1');

        console.log(
            `✅ Servidor ONLINE en http://localhost:${PORT}`
        );

        console.log(
            '💾 Base de Datos MySQL CONECTADA correctamente.'
        );

    } catch (error) {

        console.error(
            '❌ Error de BD',
            error
        );
    }
});