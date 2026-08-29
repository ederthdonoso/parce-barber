require('dotenv').config();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const helmet = require('helmet');
const express = require('express');
const rateLimit = require('express-rate-limit');
const path = require('path');
const crypto = require('crypto');
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

const sugerenciasLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 8,
    standardHeaders: true,
    legacyHeaders: false,

    message: {
        success: false,
        message:
            'Has enviado varias sugerencias. Espera unos minutos antes de volver a intentarlo.'
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
// ASEGURAR TABLA DE SUGERENCIAS
// ============================================================

async function asegurarTablaSugerencias() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS sugerencias (
            id INT NOT NULL AUTO_INCREMENT,
            mensaje VARCHAR(1000) NOT NULL,
            leida TINYINT(1) NOT NULL DEFAULT 0,
            creado_en TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,

            PRIMARY KEY (id),

            INDEX idx_sugerencias_leida_fecha (
                leida,
                creado_en
            )
        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    `);

}

// ============================================================
// ASEGURAR TABLA DE VALORACIONES
// ============================================================

async function asegurarTablaValoraciones() {

    await pool.query(`
        CREATE TABLE IF NOT EXISTS valoraciones (

            id INT NOT NULL AUTO_INCREMENT,

            agendamiento_id INT NOT NULL,

            barbero_id INT NOT NULL,

            cliente VARCHAR(120) NOT NULL,

            servicio VARCHAR(180) NOT NULL,

            token CHAR(64) NOT NULL,

            puntuacion DECIMAL(2,1) DEFAULT NULL,

            comentario VARCHAR(1200) DEFAULT NULL,

            creado_en TIMESTAMP NOT NULL
                DEFAULT CURRENT_TIMESTAMP,

            valorado_en TIMESTAMP NULL
                DEFAULT NULL,

            PRIMARY KEY (id),

            UNIQUE KEY unica_valoracion_cita (
                agendamiento_id
            ),

            UNIQUE KEY unico_token_valoracion (
                token
            ),

            INDEX idx_valoraciones_barbero (
                barbero_id,
                valorado_en
            ),

            INDEX idx_valoraciones_promedio (
                barbero_id,
                puntuacion
            )

        )
        ENGINE=InnoDB
        DEFAULT CHARSET=utf8mb4
        COLLATE=utf8mb4_unicode_ci
    `);

}


// ============================================================
// GENERAR TOKEN SEGURO PARA VALORACIÓN
// ============================================================

function crearTokenValoracion() {

    return crypto
        .randomBytes(32)
        .toString('hex');

}

// ============================================================
// URL PÚBLICA DEL SISTEMA
// ============================================================

function obtenerUrlPublica() {

    const configurada =
        String(
            process.env.APP_URL || ''
        )
            .trim()
            .replace(/\/+$/, '');


    if (configurada) {
        return configurada;
    }


    const dominioRailway =
        String(
            process.env.RAILWAY_PUBLIC_DOMAIN || ''
        ).trim();


    if (dominioRailway) {

        return `https://${dominioRailway}`;

    }


    // En desarrollo local.
    return `http://localhost:${PORT}`;

}


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

// ============================================================
// AYUDANTES PARA GESTIONAR CITAS DEL BARBERO
// ============================================================

function esBloqueoContinuo(servicio) {

    return /\(Bloqueo Continuo\)\s*$/i.test(
        String(servicio || '').trim()
    );

}


function servicioBase(servicio) {

    return String(servicio || '')
        .replace(
            /\s*\(Bloqueo Continuo\)\s*$/i,
            ''
        )
        .trim();

}


function esServicioLargoParaBarbero(
    barberoId,
    servicio
) {

    const nombre =
        servicioBase(servicio);


    const serviciosJesus = [
        'Rulos permanentes',
        'Ondulado permanente'
    ];


    const serviciosParce = [
        'Tintura de pelo (visos)',
        'Tintura de pelo (global)'
    ];


    return (
        Number(barberoId) === 2 &&
        serviciosJesus.includes(nombre)
    )
    ||
    (
        Number(barberoId) === 1 &&
        serviciosParce.includes(nombre)
    );

}


function obtenerHorasContinuas(
    hora,
    cantidad = 4
) {

    const coincidencia =
        /^(\d{1,2}):(\d{2})$/.exec(
            String(hora || '').trim()
        );


    if (!coincidencia) {
        return null;
    }


    const horaBase =
        Number(coincidencia[1]);


    const minutos =
        Number(coincidencia[2]);


    if (
        horaBase < 0 ||
        horaBase > 23 ||
        minutos !== 0 ||
        horaBase + cantidad - 1 > 23
    ) {

        return null;

    }


    return Array.from(
        { length: cantidad },
        (_, indice) =>
            `${String(
                horaBase + indice
            ).padStart(2, '0')}:00`
    );

}


function emailValidoBasico(email) {

    if (!email) {
        return true;
    }


    return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
        String(email).trim()
    );

}


function fechaISODesdeBD(valor) {

    if (!valor) {
        return '';
    }


    if (typeof valor === 'string') {

        const coincidencia =
            valor.match(
                /^\d{4}-\d{2}-\d{2}/
            );


        if (coincidencia) {

            return coincidencia[0];

        }

    }


    const fecha =
        new Date(valor);


    if (
        Number.isNaN(
            fecha.getTime()
        )
    ) {

        return String(valor);

    }


    return fecha
        .toISOString()
        .slice(0, 10);

}


// ============================================================
// CORREO: CITA MODIFICADA
// ============================================================

async function enviarCorreoCambioCita({
    email,
    cliente,
    barbero,
    servicio,
    fechaAnterior,
    horaAnterior,
    nuevaFecha,
    nuevaHora
}) {

    if (!email) {
        return false;
    }


    try {

        const { data, error } =
            await resend.emails.send({

                from:
                    EMAIL_REMITENTE,

                to:
                    [email],

                subject:
                    'Tu cita en Parce Barber fue modificada ✂️',

                html: `
                    <div
                        style="
                            font-family:Arial,sans-serif;
                            padding:25px;
                            max-width:600px;
                            margin:auto;
                            background:#0a0a0a;
                            color:#fff;
                            border:1px solid #333;
                            border-radius:12px;
                        "
                    >

                        <h1
                            style="
                                color:#ffb700;
                                text-align:center;
                            "
                        >
                            ✂️ Parce Barber
                        </h1>

                        <h2 style="text-align:center;">
                            Tu cita fue modificada
                        </h2>

                        <p>
                            Hola
                            <strong>${cliente}</strong>,
                        </p>

                        <p>
                            Tu barbero
                            <strong>${barbero}</strong>
                            actualizó tu reserva.
                        </p>


                        <div
                            style="
                                background:#151515;
                                padding:16px;
                                border-radius:10px;
                                margin-top:20px;
                            "
                        >

                            <strong style="color:#888;">
                                ANTES
                            </strong>

                            <p>
                                ${fechaAnterior}
                                ·
                                ${horaAnterior}
                            </p>

                        </div>


                        <div
                            style="
                                background:#151515;
                                padding:16px;
                                border-radius:10px;
                                margin-top:12px;
                                border-left:4px solid #ffb700;
                            "
                        >

                            <strong style="color:#ffb700;">
                                NUEVA CITA
                            </strong>

                            <p style="font-size:18px;">
                                ${nuevaFecha}
                                ·
                                ${nuevaHora}
                            </p>

                        </div>


                        <p style="margin-top:20px;">
                            <strong>Servicio:</strong>
                            ${servicio}
                        </p>


                        <p style="margin-top:25px;">
                            ¡Te esperamos! 🔥
                        </p>

                    </div>
                `

            });


        if (error) {

            console.error(
                '❌ Error enviando correo de cambio:',
                error
            );

            return false;

        }


        console.log(
            '📧 Correo de cambio enviado:',
            data?.id
        );


        return true;


    } catch (error) {

        console.error(
            '❌ Error inesperado enviando correo de cambio:',
            error
        );


        return false;

    }

}


// ============================================================
// CORREO: CITA CANCELADA
// ============================================================

async function enviarCorreoCancelacionCita({
    email,
    cliente,
    barbero,
    servicio,
    fecha,
    hora
}) {

    if (!email) {
        return false;
    }


    try {

        const { data, error } =
            await resend.emails.send({

                from:
                    EMAIL_REMITENTE,

                to:
                    [email],

                subject:
                    'Tu cita en Parce Barber fue cancelada',

                html: `
                    <div
                        style="
                            font-family:Arial,sans-serif;
                            padding:25px;
                            max-width:600px;
                            margin:auto;
                            background:#0a0a0a;
                            color:#fff;
                            border:1px solid #333;
                            border-radius:12px;
                        "
                    >

                        <h1
                            style="
                                color:#ff3333;
                                text-align:center;
                            "
                        >
                            Cita cancelada
                        </h1>


                        <p>
                            Hola
                            <strong>${cliente}</strong>,
                        </p>


                        <p>
                            Tu cita con
                            <strong>${barbero}</strong>
                            fue cancelada.
                        </p>


                        <div
                            style="
                                background:#151515;
                                padding:18px;
                                border-radius:10px;
                                margin-top:20px;
                            "
                        >

                            <p>
                                <strong>Servicio:</strong>
                                ${servicio}
                            </p>

                            <p>
                                <strong>Fecha:</strong>
                                ${fecha}
                            </p>

                            <p>
                                <strong>Hora:</strong>
                                ${hora}
                            </p>

                        </div>


                        <p style="margin-top:22px;">
                            Puedes volver a reservar una nueva
                            hora desde nuestra página.
                        </p>

                    </div>
                `

            });


        if (error) {

            console.error(
                '❌ Error enviando correo de cancelación:',
                error
            );


            return false;

        }


        console.log(
            '📧 Correo de cancelación enviado:',
            data?.id
        );


        return true;


    } catch (error) {

        console.error(
            '❌ Error inesperado enviando correo de cancelación:',
            error
        );


        return false;

    }

}

// ============================================================
// HORARIOS DE ALMUERZO
// ============================================================

const HORARIOS_ALMUERZO = Object.freeze({

    // Parce Barber
    1: '15:00',

    // Jesús Peña
    2: '16:00',

    // Yuseth Priik
    3: '14:00'

});


function obtenerHoraAlmuerzo(
    barberoId
) {

    return (
        HORARIOS_ALMUERZO[
            Number(barberoId)
        ]
        ||
        null
    );

}

const DURACION_SESION =
    30 * 24 * 60 * 60 * 1000;


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
    expiresIn: '30d'
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
// PROTEGER HORARIO DE ALMUERZO
// ====================================================

const horaAlmuerzo =
    obtenerHoraAlmuerzo(
        barberoId
    );


if (
    horaAlmuerzo
    &&
    horasRequeridas.includes(
        horaAlmuerzo
    )
) {

    return res.status(409).json({

        success: false,

        message:
            'Ese horario corresponde al almuerzo del especialista. Por favor, elige otra hora.'

    });

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
// SINCRONIZADO CON HORARIOS DE CADA BARBERO
// ============================================================

app.post(
    '/api/agendado-rapido',
    async (req, res) => {

        let conexion = null;


        try {

            const servicio =
                String(
                    req.body.servicio || ''
                ).trim();


            const cliente =
                String(
                    req.body.cliente || ''
                ).trim();


            const telefono =
                String(
                    req.body.telefono || ''
                ).trim();


            const email =
                String(
                    req.body.email || ''
                ).trim();


            // ====================================================
            // VALIDAR DATOS
            // ====================================================

            if (
                !servicio ||
                !cliente ||
                !telefono ||
                !email
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Completa servicio, nombre, teléfono y correo antes de continuar.'

                });

            }


            // ====================================================
            // NORMALIZAR HORAS
            // ====================================================

            function normalizarHora(
                valor
            ) {

                const coincidencia =
                    /^(\d{1,2}):(\d{2})/.exec(
                        String(
                            valor || ''
                        ).trim()
                    );


                if (!coincidencia) {
                    return null;
                }


                const hora =
                    Number(
                        coincidencia[1]
                    );


                const minutos =
                    Number(
                        coincidencia[2]
                    );


                if (
                    hora < 0 ||
                    hora > 23 ||
                    minutos < 0 ||
                    minutos > 59
                ) {

                    return null;

                }


                return (
                    `${String(
                        hora
                    ).padStart(
                        2,
                        '0'
                    )}:${String(
                        minutos
                    ).padStart(
                        2,
                        '0'
                    )}`
                );

            }


            function horaAMinutos(
                hora
            ) {

                const [
                    h,
                    m
                ] =
                    hora
                        .split(':')
                        .map(Number);


                return (
                    h * 60 + m
                );

            }


            function sumarHoras(
                hora,
                cantidad
            ) {

                const minutosBase =
                    horaAMinutos(
                        hora
                    );


                const resultado =
                    [];


                for (
                    let i = 0;
                    i < cantidad;
                    i++
                ) {

                    const total =
                        minutosBase +
                        i * 60;


                    if (
                        total >=
                        24 * 60
                    ) {

                        return null;

                    }


                    const h =
                        Math.floor(
                            total / 60
                        );


                    const m =
                        total % 60;


                    resultado.push(

                        `${String(
                            h
                        ).padStart(
                            2,
                            '0'
                        )}:${String(
                            m
                        ).padStart(
                            2,
                            '0'
                        )}`

                    );

                }


                return resultado;

            }


            // ====================================================
            // HORA ACTUAL EN CHILE
            // ====================================================

            const partesChile =
                new Intl.DateTimeFormat(

                    'en-US',

                    {

                        timeZone:
                            'America/Santiago',

                        year:
                            'numeric',

                        month:
                            '2-digit',

                        day:
                            '2-digit',

                        hour:
                            '2-digit',

                        minute:
                            '2-digit',

                        hourCycle:
                            'h23'

                    }

                )
                    .formatToParts(
                        new Date()
                    );


            const ahoraChile =
                {};


            partesChile.forEach(
                parte => {

                    if (
                        parte.type !==
                        'literal'
                    ) {

                        ahoraChile[
                            parte.type
                        ] =
                            parte.value;

                    }

                }
            );


            const anioHoy =
                Number(
                    ahoraChile.year
                );


            const mesHoy =
                Number(
                    ahoraChile.month
                );


            const diaHoy =
                Number(
                    ahoraChile.day
                );


            const minutosAhora =
                Number(
                    ahoraChile.hour
                ) * 60
                +
                Number(
                    ahoraChile.minute
                );


            // ====================================================
            // GENERAR FECHAS
            // ====================================================

            function datosFecha(
                diasAdelante
            ) {

                const fecha =
                    new Date(

                        Date.UTC(

                            anioHoy,

                            mesHoy - 1,

                            diaHoy +
                                diasAdelante,

                            12

                        )

                    );


                const anio =
                    fecha
                        .getUTCFullYear();


                const mes =
                    String(
                        fecha
                            .getUTCMonth() +
                        1
                    )
                        .padStart(
                            2,
                            '0'
                        );


                const dia =
                    String(
                        fecha
                            .getUTCDate()
                    )
                        .padStart(
                            2,
                            '0'
                        );


                return {

                    fecha:
                        `${anio}-${mes}-${dia}`,

                    diaSemana:
                        fecha.getUTCDay()

                };

            }


            const primeraFecha =
                datosFecha(
                    0
                ).fecha;


            const ultimaFecha =
                datosFecha(
                    6
                ).fecha;


            // ====================================================
            // OBTENER BARBEROS
            // CON SUS HORARIOS REALES
            // ====================================================

            const [
                barberosBD
            ] =
                await pool.query(

                    `SELECT
                        id,
                        nombre,
                        horarios
                     FROM barberos
                     WHERE activo = 1
                     ORDER BY id ASC`

                );


            const barberos =
                barberosBD

                    .map(
                        barbero => {


                            const horarios =
                                String(
                                    barbero.horarios ||
                                    ''
                                )

                                    .split(',')

                                    .map(
                                        normalizarHora
                                    )

                                    .filter(
                                        Boolean
                                    );


                            return {

                                id:
                                    Number(
                                        barbero.id
                                    ),

                                nombre:
                                    barbero.nombre,

                                horarios:
                                    [
                                        ...new Set(
                                            horarios
                                        )
                                    ]

                            };

                        }
                    )

                    /*
                     * Si un barbero no tiene
                     * horarios configurados,
                     * el agendado rápido NO
                     * puede asignarle una cita.
                     */
                    .filter(
                        barbero =>
                            barbero
                                .horarios
                                .length >
                            0
                    );


            if (
                barberos.length === 0
            ) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        message:
                            'No hay barberos con horarios disponibles.'

                    });

            }


            // ====================================================
            // CARGAR CITAS YA OCUPADAS
            // ====================================================

            const [
                citasOcupadas
            ] =
                await pool.query(

                    `SELECT
                        barberoId,
                        CAST(fecha AS CHAR)
                            AS fecha,
                        LEFT(
                            CAST(hora AS CHAR),
                            5
                        ) AS hora
                     FROM agendamientos
                     WHERE fecha
                     BETWEEN ?
                     AND ?`,

                    [
                        primeraFecha,
                        ultimaFecha
                    ]

                );


            const ocupadasSet =
                new Set(

                    citasOcupadas.map(
                        cita => {

                            return (

                                `${Number(
                                    cita.barberoId
                                )}|${
                                    String(
                                        cita.fecha
                                    )
                                        .slice(
                                            0,
                                            10
                                        )
                                }|${
                                    normalizarHora(
                                        cita.hora
                                    )
                                }`

                            );

                        }
                    )

                );


            // ====================================================
            // DÍAS BLOQUEADOS
            // ====================================================

            const [
                diasBloqueados
            ] =
                await pool.query(

                    `SELECT
                        barberoId,
                        CAST(fecha AS CHAR)
                            AS fecha
                     FROM dias_bloqueados
                     WHERE fecha
                     BETWEEN ?
                     AND ?`,

                    [
                        primeraFecha,
                        ultimaFecha
                    ]

                );


            const diasBloqueadosSet =
                new Set(

                    diasBloqueados.map(
                        dia =>

                            `${Number(
                                dia.barberoId
                            )}|${
                                String(
                                    dia.fecha
                                )
                                    .slice(
                                        0,
                                        10
                                    )
                            }`

                    )

                );


            // ====================================================
            // SERVICIOS ESPECIALES
            // ====================================================

            const serviciosJesus =
                [

                    'Rulos permanentes',

                    'Ondulado permanente'

                ];


            const serviciosParce =
                [

                    'Tintura de pelo (visos)',

                    'Tintura de pelo (global)'

                ];


            function barberoPuedeRealizarServicio(
                barberoId
            ) {

                /*
                 * Servicios exclusivos
                 * de Jesús.
                 */

                if (
                    serviciosJesus
                        .includes(
                            servicio
                        )
                ) {

                    return (
                        Number(
                            barberoId
                        ) === 2
                    );

                }


                /*
                 * Servicios exclusivos
                 * de Parce.
                 */

                if (
                    serviciosParce
                        .includes(
                            servicio
                        )
                ) {

                    return (
                        Number(
                            barberoId
                        ) === 1
                    );

                }


                /*
                 * Servicios normales.
                 */

                return true;

            }


            function horasServicio(
                barberoId
            ) {

                if (
                    Number(
                        barberoId
                    ) === 2
                    &&
                    serviciosJesus
                        .includes(
                            servicio
                        )
                ) {

                    return 4;

                }


                if (
                    Number(
                        barberoId
                    ) === 1
                    &&
                    serviciosParce
                        .includes(
                            servicio
                        )
                ) {

                    return 4;

                }


                return 1;

            }


            // ====================================================
            // BUSCAR LA HORA MÁS CERCANA
            // ====================================================

            let fechaAsignada =
                null;


            let horaAsignada =
                null;


            let barberoAsignado =
                null;


            let horasRequeridasAsignadas =
                null;


            /*
             * Buscamos máximo
             * los próximos 7 días.
             */

            for (
                let d = 0;
                d < 7 &&
                !fechaAsignada;
                d++
            ) {

                const infoFecha =
                    datosFecha(
                        d
                    );


                // ================================
                // DOMINGO
                // ================================

                if (
                    infoFecha
                        .diaSemana ===
                    0
                ) {

                    continue;

                }


                /*
                 * Aquí juntamos TODAS
                 * las horas reales de
                 * todos los barberos.
                 */

                const candidatos =
                    [];


                for (
                    const barbero
                    of barberos
                ) {

                    // ============================
                    // SERVICIO EXCLUSIVO
                    // ============================

                    if (
                        !barberoPuedeRealizarServicio(
                            barbero.id
                        )
                    ) {

                        continue;

                    }


                    // ============================
                    // DÍA BLOQUEADO
                    // ============================

                    if (
                        diasBloqueadosSet
                            .has(

                                `${barbero.id}|${infoFecha.fecha}`

                            )
                    ) {

                        continue;

                    }


                    // ============================
                    // HORARIO REAL DEL BARBERO
                    // ============================

                    for (
                        const hora
                        of barbero.horarios
                    ) {

                        /*
                         * Si estamos buscando
                         * para hoy, no usamos
                         * horas que ya pasaron.
                         */

                        if (
                            d === 0
                            &&
                            horaAMinutos(
                                hora
                            )
                            <=
                            minutosAhora
                        ) {

                            continue;

                        }


                        candidatos.push({

                            barbero,

                            hora

                        });

                    }

                }


                /*
                 * Ordenar primero por
                 * la hora más cercana.
                 */

                candidatos.sort(

                    (a, b) =>

                        horaAMinutos(
                            a.hora
                        )
                        -
                        horaAMinutos(
                            b.hora
                        )

                        ||

                        a.barbero.id
                        -
                        b.barbero.id

                );


                // ================================
                // ENCONTRAR PRIMERA DISPONIBLE
                // ================================

                for (
                    const candidato
                    of candidatos
                ) {

                    const barbero =
                        candidato
                            .barbero;


                    const hora =
                        candidato
                            .hora;


                    const cantidad =
                        horasServicio(
                            barbero.id
                        );


                    const horasRequeridas =
                        sumarHoras(

                            hora,

                            cantidad

                        );


                    if (
                        !horasRequeridas
                    ) {

                        continue;

                    }

                    // ============================
// RESPETAR ALMUERZO
// ============================

const horaAlmuerzo =
    obtenerHoraAlmuerzo(
        barbero.id
    );


if (
    horaAlmuerzo
    &&
    horasRequeridas.includes(
        horaAlmuerzo
    )
) {

    continue;

}


                    /*
                     * MUY IMPORTANTE:
                     *
                     * Si necesita 4 horas,
                     * las 4 deben existir
                     * dentro del horario
                     * configurado del barbero.
                     */

                    const dentroDelHorario =
                        horasRequeridas
                            .every(
                                h =>

                                    barbero
                                        .horarios
                                        .includes(
                                            h
                                        )
                            );


                    if (
                        !dentroDelHorario
                    ) {

                        continue;

                    }


                    /*
                     * Verificar que ninguna
                     * de las horas esté ocupada.
                     */

                    const algunaOcupada =
                        horasRequeridas
                            .some(
                                h =>

                                    ocupadasSet
                                        .has(

                                            `${barbero.id}|${infoFecha.fecha}|${h}`

                                        )
                            );


                    if (
                        algunaOcupada
                    ) {

                        continue;

                    }


                    // ============================
                    // ENCONTRAMOS HORA
                    // ============================

                    fechaAsignada =
                        infoFecha
                            .fecha;


                    horaAsignada =
                        hora;


                    barberoAsignado =
                        barbero;


                    horasRequeridasAsignadas =
                        horasRequeridas;


                    break;

                }

            }


            // ====================================================
            // NO HAY DISPONIBILIDAD
            // ====================================================

            if (
                !fechaAsignada ||
                !horaAsignada ||
                !barberoAsignado
            ) {

                return res
                    .status(404)
                    .json({

                        success:
                            false,

                        message:
                            'No hay horas disponibles dentro de los horarios configurados de los barberos durante los próximos 7 días.'

                    });

            }


            // ====================================================
            // TRANSACCIÓN
            // ====================================================

            conexion =
                await pool
                    .getConnection();


            await conexion
                .beginTransaction();


            // ====================================================
            // VOLVER A COMPROBAR DÍA BLOQUEADO
            // ====================================================

            const [
                bloqueoFinal
            ] =
                await conexion.query(

                    `SELECT id
                     FROM dias_bloqueados
                     WHERE barberoId = ?
                     AND fecha = ?
                     LIMIT 1`,

                    [
                        barberoAsignado.id,
                        fechaAsignada
                    ]

                );


            if (
                bloqueoFinal.length >
                0
            ) {

                await conexion
                    .rollback();


                conexion.release();


                conexion =
                    null;


                return res
                    .status(409)
                    .json({

                        success:
                            false,

                        message:
                            'El barbero acaba de bloquear ese día. Intenta nuevamente.'

                    });

            }


            // ====================================================
            // VOLVER A COMPROBAR HORAS
            // ====================================================

            const [
                conflictos
            ] =
                await conexion.query(

                    `SELECT id
                     FROM agendamientos
                     WHERE barberoId = ?
                     AND fecha = ?
                     AND hora IN (?)`,

                    [

                        barberoAsignado.id,

                        fechaAsignada,

                        horasRequeridasAsignadas

                    ]

                );


            if (
                conflictos.length >
                0
            ) {

                await conexion
                    .rollback();


                conexion.release();


                conexion =
                    null;


                return res
                    .status(409)
                    .json({

                        success:
                            false,

                        message:
                            'La hora acaba de ser tomada. Intenta nuevamente para buscar la siguiente disponible.'

                    });

            }


            // ====================================================
            // GUARDAR CITA
            // ====================================================

            for (
                let i = 0;
                i <
                horasRequeridasAsignadas.length;
                i++
            ) {

                const servicioGuardado =
                    i === 0

                        ? servicio

                        : `${servicio} (Bloqueo Continuo)`;


                await conexion.query(

                    `INSERT INTO agendamientos
                    (
                        barberoId,
                        servicio,
                        fecha,
                        hora,
                        cliente,
                        telefono,
                        email
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,

                    [

                        barberoAsignado.id,

                        servicioGuardado,

                        fechaAsignada,

                        horasRequeridasAsignadas[i],

                        cliente,

                        telefono,

                        email

                    ]

                );

            }


            // ====================================================
            // HISTORIAL VIP
            // ====================================================

            const contacto =
                email ||
                telefono;


            if (
                contacto
            ) {

                await conexion.query(

                    `INSERT INTO clientes_cortes
                    (
                        contacto,
                        cantidad
                    )
                    VALUES (?, 1)
                    ON DUPLICATE KEY UPDATE
                    cantidad = cantidad + 1`,

                    [
                        contacto
                    ]

                );

            }


            await conexion
                .commit();


            conexion.release();


            conexion =
                null;


            // ====================================================
            // CORREO
            // ====================================================

            await enviarCorreo(

                email,

                cliente,

                barberoAsignado.nombre ||
                    'Especialista',

                servicio,

                fechaAsignada,

                horaAsignada

            );


            // ====================================================
            // RESPUESTA
            // ====================================================

            return res.json({

                success:
                    true,

                asignado: {

                    barbero:
                        barberoAsignado.nombre ||
                        'Especialista',

                    fecha:
                        fechaAsignada,

                    hora:
                        horaAsignada

                }

            });


        } catch (error) {

            if (
                conexion
            ) {

                try {

                    await conexion
                        .rollback();

                } catch (_) {}


                conexion.release();

            }


            console.error(

                'Error en agendado rápido:',

                error

            );


            if (
                error.code ===
                'ER_DUP_ENTRY'
            ) {

                return res
                    .status(409)
                    .json({

                        success:
                            false,

                        message:
                            'La hora acaba de ser tomada. Intenta nuevamente.'

                    });

            }


            return res
                .status(500)
                .json({

                    success:
                        false,

                    message:
                        'Error interno del servidor.'

                });

        }

    }
);

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

        const cita =
    citas[0];


if (
    String(
        cita.estado || ''
    )
        .trim()
        .toLowerCase() ===
    'finalizada'
) {

    return res.status(409).json({
        success: false,
        message:
            'Este servicio ya fue realizado y no puede cancelarse.'
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
// NO MODIFICAR UNA CITA YA FINALIZADA
// ====================================================

if (
    String(
        cita.estado || ''
    )
        .trim()
        .toLowerCase() ===
    'finalizada'
) {

    return res.status(409).json({
        success: false,
        message:
            'Este servicio ya fue realizado y no puede modificarse.'
    });

}


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
// NO PERMITIR QUE EL CLIENTE MUEVA SU CITA AL ALMUERZO
// ====================================================

const horaAlmuerzoNuevo =
    obtenerHoraAlmuerzo(
        nuevoBarberoId
    );


if (
    horaAlmuerzoNuevo
    &&
    nuevaHora ===
        horaAlmuerzoNuevo
) {

    return res.status(409).json({

        success: false,

        message:
            'Esa hora corresponde al almuerzo del especialista. Selecciona otra hora.'

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

    perfil:
        perfiles[0],

    agendamientos,

    clientesCortes,

    horaAlmuerzo:
        obtenerHoraAlmuerzo(
            req.usuario.id
        )

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
// AGREGAR HORA EXTRA DESDE EL PANEL DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/hora-extra',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const {
                fecha,
                hora,
                servicio,
                cliente,
                telefono,
                email
            } = req.body;


            const fechaLimpia =
                String(fecha || '').trim();


            const horaLimpia =
                String(hora || '').trim();


            const servicioLimpio =
                String(servicio || '').trim();


            const clienteLimpio =
                String(cliente || '').trim();


            const telefonoLimpio =
                String(telefono || '').trim();


            const emailLimpio =
                String(email || '').trim();


            /*
             * Campos obligatorios.
             */

            if (
                !fechaLimpia ||
                !horaLimpia ||
                !servicioLimpio ||
                !clienteLimpio
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Fecha, hora, servicio y nombre del cliente son obligatorios.'

                });

            }


            /*
             * Validar formato de fecha.
             */

            if (
                !/^\d{4}-\d{2}-\d{2}$/.test(
                    fechaLimpia
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'La fecha no es válida.'

                });

            }


            /*
             * Validar formato de hora.
             */

            if (
                !/^\d{2}:\d{2}$/.test(
                    horaLimpia
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'La hora no es válida.'

                });

            }


            const [
                horaNumero,
                minutoNumero
            ] =
                horaLimpia
                    .split(':')
                    .map(Number);


            if (
                horaNumero < 0 ||
                horaNumero > 23 ||
                minutoNumero < 0 ||
                minutoNumero > 59
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'La hora no es válida.'

                });

            }


            /*
             * Domingo sigue siendo día no laborable.
             */

            const fechaLocal =
                new Date(
                    `${fechaLimpia}T12:00:00`
                );


            if (
                fechaLocal.getDay() === 0
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Los domingos son días no laborables y no se pueden agendar horas extra.'

                });

            }


            /*
             * Si el barbero bloqueó el día completo,
             * tampoco permitimos una hora extra.
             */

            if (
                await esDiaBloqueado(
                    req.usuario.id,
                    fechaLimpia
                )
            ) {

                return res.status(400).json({

                    success: false,

                    message:
                        'Este día está bloqueado. Desbloquéalo antes de agregar una hora extra.'

                });

            }


            /*
             * ====================================================
             * SERVICIOS DE 4 HORAS
             * ====================================================
             *
             * Conservamos la misma lógica de tu sistema.
             */

            let esServicioLargo = false;

            let horasRequeridas = [
                horaLimpia
            ];


            const serviciosJesus = [

                'Rulos permanentes',

                'Ondulado permanente'

            ];


            const serviciosParce = [

                'Tintura de pelo (visos)',

                'Tintura de pelo (global)'

            ];


            if (
                (
                    Number(req.usuario.id) === 2 &&
                    serviciosJesus.includes(
                        servicioLimpio
                    )
                )
                ||
                (
                    Number(req.usuario.id) === 1 &&
                    serviciosParce.includes(
                        servicioLimpio
                    )
                )
            ) {

                esServicioLargo = true;


                const horaBase =
                    horaNumero;


                /*
                 * Necesita 4 horas continuas.
                 */

                if (
                    horaBase + 3 > 23
                ) {

                    return res.status(400).json({

                        success: false,

                        message:
                            'Este servicio requiere 4 horas continuas y no cabe desde esa hora.'

                    });

                }


                horasRequeridas = [

                    `${String(horaBase).padStart(2, '0')}:00`,

                    `${String(horaBase + 1).padStart(2, '0')}:00`,

                    `${String(horaBase + 2).padStart(2, '0')}:00`,

                    `${String(horaBase + 3).padStart(2, '0')}:00`

                ];

            }


            /*
             * ====================================================
             * COMPROBAR CONFLICTOS
             * ====================================================
             *
             * No importa si la cita es normal o extra.
             * Si ya existe algo en esa hora, no dejamos
             * crear otra cita.
             */

            const [existentes] =
                await pool.query(

                    `SELECT
                        id,
                        hora,
                        servicio,
                        estado
                     FROM agendamientos
                     WHERE barberoId = ?
                     AND fecha = ?
                     AND hora IN (?)`,

                    [
                        req.usuario.id,
                        fechaLimpia,
                        horasRequeridas
                    ]

                );


            if (
                existentes.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        esServicioLargo

                            ? 'No hay 4 horas continuas disponibles desde esa hora. Una o más horas ya están ocupadas o bloqueadas.'

                            : `La hora ${horaLimpia} ya está ocupada o bloqueada. Elige otra hora.`

                });

            }


            /*
             * ====================================================
             * CREAR LA HORA EXTRA
             * ====================================================
             *
             * Se utiliza la misma tabla:
             *
             * agendamientos
             *
             * pero con:
             *
             * estado = "Hora extra"
             *
             * Así no necesitamos modificar MySQL.
             */

            for (
                let i = 0;
                i < horasRequeridas.length;
                i++
            ) {

                const servicioGuardado =
                    i === 0

                        ? servicioLimpio

                        : `${servicioLimpio} (Bloqueo Continuo)`;


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

                        servicioGuardado,

                        fechaLimpia,

                        horasRequeridas[i],

                        clienteLimpio,

                        telefonoLimpio,

                        emailLimpio,

                        'Hora extra'

                    ]

                );

            }


            /*
             * ====================================================
             * HISTORIAL DE CLIENTES
             * ====================================================
             */

            const contacto =
                emailLimpio ||
                telefonoLimpio;


            if (contacto) {

                await pool.query(

                    `INSERT INTO clientes_cortes
                    (
                        contacto,
                        cantidad
                    )
                    VALUES (?, 1)
                    ON DUPLICATE KEY UPDATE
                    cantidad = cantidad + 1`,

                    [
                        contacto
                    ]

                );

            }


            /*
             * ====================================================
             * CORREO DE CONFIRMACIÓN
             * ====================================================
             */

            if (emailLimpio) {

                const perfiles =
                    await obtenerMapaPerfiles();


                await enviarCorreo(

                    emailLimpio,

                    clienteLimpio,

                    perfiles[
                        req.usuario.id
                    ] || 'Tu Barbero',

                    servicioLimpio,

                    fechaLimpia,

                    horaLimpia

                );

            }


            /*
             * ====================================================
             * RESPUESTA
             * ====================================================
             */

            return res.json({

                success: true,

                message:

                    esServicioLargo

                        ? 'Hora extra creada correctamente. Se reservaron 4 horas continuas.'

                        : 'Hora extra creada correctamente.'

            });


        } catch (error) {

            console.error(
                'Error creando hora extra:',
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    'No se pudo crear la hora extra.'

            });

        }

    }
);

// ============================================================
// AGENDAR CLIENTE DESDE EL PANEL DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/agendar-cliente',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const fecha =
                String(
                    req.body.fecha || ''
                ).trim();

            const hora =
                String(
                    req.body.hora || ''
                ).trim();

            const servicio =
                String(
                    req.body.servicio || ''
                ).trim();

            const cliente =
                String(
                    req.body.cliente || ''
                ).trim();

            const email =
    String(
        req.body.email || ''
    ).trim();


if (
    email &&
    !emailValidoBasico(email)
) {

    return res.status(400).json({
        success: false,
        message:
            'El correo ingresado no es válido.'
    });

}


            // ====================================================
            // CAMPOS OBLIGATORIOS
            // ====================================================

            if (
                !fecha ||
                !hora ||
                !servicio ||
                !cliente
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Fecha, hora, servicio y nombre del cliente son obligatorios.'
                });

            }


            // ====================================================
            // VALIDAR FECHA
            // ====================================================

            if (
                !/^\d{4}-\d{2}-\d{2}$/.test(
                    fecha
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La fecha no es válida.'
                });

            }


            // ====================================================
            // VALIDAR HORA
            // ====================================================

            if (
                !/^\d{2}:\d{2}$/.test(
                    hora
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La hora no es válida.'
                });

            }


            // ====================================================
            // DOMINGOS
            // ====================================================

            const fechaLocal =
                new Date(
                    `${fecha}T12:00:00`
                );


            if (
                fechaLocal.getDay() === 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Los domingos son días no laborables.'
                });

            }


            // ====================================================
            // DÍA BLOQUEADO
            // ====================================================

            if (
                await esDiaBloqueado(
                    req.usuario.id,
                    fecha
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Este día está bloqueado. Desbloquéalo antes de agendar.'
                });

            }


            // ====================================================
            // OBTENER HORARIOS DEL BARBERO
            // ====================================================

            const [perfiles] =
                await pool.query(

                    `SELECT horarios
                     FROM barberos
                     WHERE id = ?
                     AND activo = 1
                     LIMIT 1`,

                    [
                        req.usuario.id
                    ]

                );


            if (
                perfiles.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        'No se encontró tu perfil.'
                });

            }


            const horariosConfigurados =
                String(
                    perfiles[0].horarios ||
                    ''
                )
                    .split(',')
                    .map(
                        h => h.trim()
                    )
                    .filter(Boolean);


            // Esta ruta es para citas NORMALES.
            // Si quiere agendar fuera de su horario,
            // debe utilizar Hora Extra.

            if (
                !horariosConfigurados.includes(
                    hora
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Esta hora no pertenece a tus horarios normales. Para una hora fuera de tu jornada utiliza "Agregar hora extra".'
                });

            }


            // ====================================================
            // COMPROBAR SERVICIO
            // ====================================================

            const [serviciosBD] =
                await pool.query(

                    `SELECT nombre
                     FROM servicios
                     WHERE nombre = ?
                     LIMIT 1`,

                    [
                        servicio
                    ]

                );


            if (
                serviciosBD.length === 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El servicio seleccionado no existe.'
                });

            }


            // ====================================================
            // SERVICIOS DE 4 HORAS
            // ====================================================

            let esServicioLargo = false;

            let horasRequeridas = [
                hora
            ];


            const serviciosJesus = [

                'Rulos permanentes',

                'Ondulado permanente'

            ];


            const serviciosParce = [

                'Tintura de pelo (visos)',

                'Tintura de pelo (global)'

            ];


            if (
                (
                    Number(
                        req.usuario.id
                    ) === 2
                    &&
                    serviciosJesus.includes(
                        servicio
                    )
                )
                ||
                (
                    Number(
                        req.usuario.id
                    ) === 1
                    &&
                    serviciosParce.includes(
                        servicio
                    )
                )
            ) {

                esServicioLargo =
                    true;


                const horaBase =
                    Number(
                        hora.split(':')[0]
                    );


                horasRequeridas = [

                    `${String(
                        horaBase
                    ).padStart(
                        2,
                        '0'
                    )}:00`,

                    `${String(
                        horaBase + 1
                    ).padStart(
                        2,
                        '0'
                    )}:00`,

                    `${String(
                        horaBase + 2
                    ).padStart(
                        2,
                        '0'
                    )}:00`,

                    `${String(
                        horaBase + 3
                    ).padStart(
                        2,
                        '0'
                    )}:00`

                ];


                // Como esta es una cita NORMAL,
                // las 4 horas deben estar dentro
                // de su disponibilidad normal.

                const todasDentroDelHorario =
                    horasRequeridas.every(
                        h =>
                            horariosConfigurados
                                .includes(h)
                    );


                if (
                    !todasDentroDelHorario
                ) {

                    return res.status(400).json({
                        success: false,
                        message:
                            'Este servicio necesita 4 horas continuas dentro de tu horario normal. Si quieres extender la jornada utiliza "Agregar hora extra".'
                    });

                }

            }


            // ====================================================
            // COMPROBAR QUE SIGA DISPONIBLE
            // ====================================================

            const [existentes] =
                await pool.query(

                    `SELECT
                        id,
                        hora,
                        servicio,
                        estado
                     FROM agendamientos
                     WHERE barberoId = ?
                     AND fecha = ?
                     AND hora IN (?)`,

                    [
                        req.usuario.id,
                        fecha,
                        horasRequeridas
                    ]

                );


            if (
                existentes.length > 0
            ) {

                return res.status(409).json({

                    success: false,

                    message:
                        esServicioLargo

                            ? 'No hay 4 horas continuas disponibles desde esa hora.'

                            : `La hora ${hora} ya fue ocupada. La agenda se actualizará automáticamente.`

                });

            }


            // ====================================================
            // CREAR CITA
            // ====================================================

            for (
                let i = 0;
                i < horasRequeridas.length;
                i++
            ) {

                const servicioGuardado =
                    i === 0

                        ? servicio

                        : `${servicio} (Bloqueo Continuo)`;


                await pool.query(

                    `INSERT INTO agendamientos
                    (
                        barberoId,
                        servicio,
                        fecha,
                        hora,
                        cliente,
                        telefono,
                        email
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?)`,

                    [

                        req.usuario.id,

                        servicioGuardado,

                        fecha,

                        horasRequeridas[i],

                        cliente,

'',

email

                    ]

                );

            }


            // ====================================================
            // RESPUESTA
            // ====================================================

            return res.json({

                success: true,

                message:
                    esServicioLargo

                        ? 'Cliente agendado correctamente. Se reservaron 4 horas continuas.'

                        : 'Cliente agendado correctamente.'

            });


        } catch (error) {

            console.error(
                'Error agendando cliente desde panel:',
                error
            );


            return res.status(500).json({

                success: false,

                message:
                    'No se pudo agendar al cliente.'

            });

        }

    }
);

// ============================================================
// SUGERENCIAS DE CLIENTES
// ============================================================


// ============================================================
// GUARDAR SUGERENCIA DESDE LA WEB PÚBLICA
// ============================================================

app.post(
    '/api/sugerencias',
    sugerenciasLimiter,
    async (req, res) => {

        try {

            const mensaje =
                String(
                    req.body.mensaje || ''
                ).trim();


            if (!mensaje) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Escribe una sugerencia antes de enviarla.'
                });

            }


            if (mensaje.length < 3) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La sugerencia es demasiado corta.'
                });

            }


            if (mensaje.length > 1000) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La sugerencia no puede superar los 1000 caracteres.'
                });

            }


            await pool.query(
                `INSERT INTO sugerencias
                (
                    mensaje,
                    leida
                )
                VALUES (?, 0)`,
                [
                    mensaje
                ]
            );


            return res.status(201).json({
                success: true,
                message:
                    '¡Gracias por tu opinión! La sugerencia fue enviada.'
            });


        } catch (error) {

            console.error(
                'Error guardando sugerencia:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo enviar la sugerencia.'
            });

        }

    }
);


// ============================================================
// VER SUGERENCIAS — SOLO JEFE
// ============================================================

app.get(
    '/api/admin/sugerencias',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const [sugerencias] =
                await pool.query(
                    `SELECT
                        id,
                        mensaje,
                        leida,
                        creado_en
                     FROM sugerencias
                     ORDER BY creado_en DESC, id DESC`
                );


            return res.json({
                success: true,
                sugerencias
            });


        } catch (error) {

            console.error(
                'Error cargando sugerencias:',
                error
            );


            return res.status(500).json({
                success: false,
                sugerencias: [],
                message:
                    'No se pudieron cargar las sugerencias.'
            });

        }

    }
);


// ============================================================
// MARCAR SUGERENCIA COMO LEÍDA — SOLO JEFE
// ============================================================

app.patch(
    '/api/admin/sugerencias/:id/leida',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            if (
                !Number.isInteger(id) ||
                id <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Sugerencia inválida.'
                });

            }


            const [resultado] =
                await pool.query(
                    `UPDATE sugerencias
                     SET leida = 1
                     WHERE id = ?`,
                    [
                        id
                    ]
                );


            return res.json({

                success:
                    resultado.affectedRows > 0,

                message:
                    resultado.affectedRows > 0

                        ? 'Sugerencia marcada como leída.'

                        : 'No se encontró la sugerencia.'

            });


        } catch (error) {

            console.error(
                'Error marcando sugerencia:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo actualizar la sugerencia.'
            });

        }

    }
);


// ============================================================
// ELIMINAR SUGERENCIA — SOLO JEFE
// ============================================================

app.delete(
    '/api/admin/sugerencias/:id',
    requiereSesion,
    requiereJefe,
    async (req, res) => {

        try {

            const id =
                Number(
                    req.params.id
                );


            if (
                !Number.isInteger(id) ||
                id <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Sugerencia inválida.'
                });

            }


            const [resultado] =
                await pool.query(
                    `DELETE FROM sugerencias
                     WHERE id = ?`,
                    [
                        id
                    ]
                );


            return res.json({

                success:
                    resultado.affectedRows > 0,

                message:
                    resultado.affectedRows > 0

                        ? 'Sugerencia eliminada.'

                        : 'No se encontró la sugerencia.'

            });


        } catch (error) {

            console.error(
                'Error eliminando sugerencia:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo eliminar la sugerencia.'
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
// UNA HORA O UN RANGO DE HORAS
// ============================================================

app.post(
    '/api/barbero/bloquear',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        let conexion =
            null;


        try {

            const fecha =
                String(
                    req.body.fecha ||
                    ''
                )
                    .trim();


            const hora =
                String(
                    req.body.hora ||
                    ''
                )
                    .trim();


            const horaHasta =
                String(
                    req.body.horaHasta ||
                    ''
                )
                    .trim();


            // ====================================================
            // VALIDAR DATOS
            // ====================================================

            if (
                !fecha ||
                !hora
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'La fecha y la hora de inicio son obligatorias.'

                });

            }


            if (
                !/^\d{4}-\d{2}-\d{2}$/
                    .test(
                        fecha
                    )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'La fecha seleccionada no es válida.'

                });

            }


            const patronHora =
                /^([01]\d|2[0-3]):([0-5]\d)$/;


            if (
                !patronHora.test(
                    hora
                )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'La hora de inicio no es válida.'

                });

            }


            if (
                horaHasta &&
                !patronHora.test(
                    horaHasta
                )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'La hora final no es válida.'

                });

            }


            // ====================================================
            // DOMINGOS
            // ====================================================

            const fechaLocal =
                new Date(
                    `${fecha}T12:00:00`
                );


            if (
                fechaLocal.getDay() === 0
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'Los domingos son días no laborables y ya están bloqueados.'

                });

            }


            // ====================================================
            // COMPROBAR DÍA COMPLETO BLOQUEADO
            // ====================================================

            if (
                await esDiaBloqueado(
                    req.usuario.id,
                    fecha
                )
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'Ese día ya está bloqueado completamente.'

                });

            }


            // ====================================================
            // CONVERSIÓN DE HORAS
            // ====================================================

            function horaAMinutos(
                valor
            ) {

                const [
                    h,
                    m
                ] =
                    valor
                        .split(':')
                        .map(Number);


                return (
                    h * 60 + m
                );

            }


            function minutosAHora(
                total
            ) {

                const h =
                    Math.floor(
                        total / 60
                    );


                const m =
                    total % 60;


                return (
                    `${String(
                        h
                    ).padStart(
                        2,
                        '0'
                    )}:` +
                    `${String(
                        m
                    ).padStart(
                        2,
                        '0'
                    )}`
                );

            }


            const inicio =
                horaAMinutos(
                    hora
                );


            const fin =
                horaHasta

                    ? horaAMinutos(
                        horaHasta
                    )

                    : inicio;


            // ====================================================
            // VALIDAR RANGO
            // ====================================================

            if (
                fin < inicio
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'La hora final debe ser igual o posterior a la hora de inicio.'

                });

            }


            if (
                horaHasta &&
                (
                    fin -
                    inicio
                ) % 60 !== 0
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'El rango debe avanzar por bloques de una hora. Ejemplo: 13:00 a 15:00.'

                });

            }


            // ====================================================
            // GENERAR TODAS LAS HORAS DEL RANGO
            // ====================================================

            const horas =
                [];


            for (
                let minuto =
                    inicio;

                minuto <= fin;

                minuto += 60
            ) {

                horas.push(
                    minutosAHora(
                        minuto
                    )
                );

            }


            if (
                horas.length > 24
            ) {

                return res.status(400).json({

                    success:
                        false,

                    message:
                        'El rango seleccionado es demasiado amplio.'

                });

            }


            // ====================================================
            // TRANSACCIÓN
            // ====================================================

            conexion =
                await pool
                    .getConnection();


            await conexion
                .beginTransaction();


            // ====================================================
            // VER SI HAY CITAS O BLOQUEOS
            // ====================================================

            const [
                existentes
            ] =
                await conexion.query(

                    `SELECT
                        id,
                        hora,
                        servicio,
                        estado,
                        cliente
                     FROM agendamientos
                     WHERE barberoId = ?
                     AND fecha = ?
                     AND hora IN (?)
                     FOR UPDATE`,

                    [
                        req.usuario.id,
                        fecha,
                        horas
                    ]

                );


            // ====================================================
            // NO BLOQUEAR ENCIMA DE UNA CITA REAL
            // ====================================================

            const conflictos =
                existentes.filter(
                    registro =>

                        registro.servicio !==
                            'BLOQUEADO'

                        &&

                        registro.estado !==
                            'Bloqueado'
                );


            if (
                conflictos.length > 0
            ) {

                const horasOcupadas =
                    conflictos

                        .map(
                            registro =>

                                String(
                                    registro.hora
                                )
                                    .slice(
                                        0,
                                        5
                                    )
                        )

                        .join(
                            ', '
                        );


                await conexion
                    .rollback();


                conexion
                    .release();


                conexion =
                    null;


                return res.status(409).json({

                    success:
                        false,

                    message:
                        `No se puede crear el bloqueo porque ya existe una cita en: ${horasOcupadas}.`

                });

            }


            // ====================================================
            // HORAS QUE YA ESTABAN BLOQUEADAS
            // ====================================================

            const yaBloqueadas =
                new Set(

                    existentes

                        .filter(
                            registro =>

                                registro.servicio ===
                                    'BLOQUEADO'

                                ||

                                registro.estado ===
                                    'Bloqueado'
                        )

                        .map(
                            registro =>

                                String(
                                    registro.hora
                                )
                                    .slice(
                                        0,
                                        5
                                    )
                        )

                );


            // ====================================================
            // SOLO INSERTAR LAS NUEVAS
            // ====================================================

            const horasNuevas =
                horas.filter(
                    horaBloqueo =>

                        !yaBloqueadas
                            .has(
                                horaBloqueo
                            )
                );


            for (
                const horaBloqueo
                of horasNuevas
            ) {

                await conexion.query(

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
                        horaBloqueo,
                        'Descanso / Inasistencia',
                        '-',
                        '-',
                        'Bloqueado'
                    ]

                );

            }


            await conexion
                .commit();


            conexion
                .release();


            conexion =
                null;


            // ====================================================
            // RESPUESTA
            // ====================================================

            if (
                horasNuevas.length ===
                0
            ) {

                return res.json({

                    success:
                        true,

                    message:
                        horas.length === 1

                            ? 'Esa hora ya estaba bloqueada.'

                            : 'Todo ese rango ya estaba bloqueado.'

                });

            }


            return res.json({

                success:
                    true,

                message:
                    horas.length === 1

                        ? 'Horario bloqueado correctamente.'

                        : `Rango bloqueado correctamente: ${hora} a ${horaHasta}.`

            });


        } catch (error) {

            if (
                conexion
            ) {

                try {

                    await conexion
                        .rollback();

                } catch (_) {}


                conexion
                    .release();

            }


            console.error(
                'Error al bloquear horario:',
                error
            );


            return res.status(500).json({

                success:
                    false,

                message:
                    'No se pudo bloquear el horario.'

            });

        }

    }
);

// ============================================================
// DESBLOQUEAR HORARIO DEL BARBERO
// UNA HORA O UN RANGO
// ============================================================

app.post(
    '/api/barbero/desbloquear',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        try {

            const fecha =
                String(
                    req.body.fecha || ''
                ).trim();


            const hora =
                String(
                    req.body.hora || ''
                ).trim();


            const horaHasta =
                String(
                    req.body.horaHasta || ''
                ).trim();


            // ====================================================
            // VALIDAR DATOS
            // ====================================================

            if (
                !fecha ||
                !hora
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La fecha y la hora son obligatorias.'
                });

            }


            if (
                !/^\d{4}-\d{2}-\d{2}$/.test(
                    fecha
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La fecha seleccionada no es válida.'
                });

            }


            const patronHora =
                /^([01]\d|2[0-3]):([0-5]\d)$/;


            if (
                !patronHora.test(
                    hora
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La hora inicial no es válida.'
                });

            }


            if (
                horaHasta &&
                !patronHora.test(
                    horaHasta
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La hora final no es válida.'
                });

            }


            // ====================================================
            // CONVERTIR HORAS
            // ====================================================

            function horaAMinutos(
                valor
            ) {

                const [
                    h,
                    m
                ] =
                    valor
                        .split(':')
                        .map(Number);


                return (
                    h * 60 +
                    m
                );

            }


            function minutosAHora(
                total
            ) {

                const h =
                    Math.floor(
                        total / 60
                    );


                const m =
                    total % 60;


                return (
                    `${String(h).padStart(2, '0')}:` +
                    `${String(m).padStart(2, '0')}`
                );

            }


            const inicio =
                horaAMinutos(
                    hora
                );


            const fin =
                horaHasta

                    ? horaAMinutos(
                        horaHasta
                    )

                    : inicio;


            if (
                fin < inicio
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La hora final debe ser igual o posterior a la hora inicial.'
                });

            }


            if (
                horaHasta &&
                (
                    fin -
                    inicio
                ) % 60 !== 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El rango debe avanzar en bloques de una hora.'
                });

            }


            // ====================================================
            // CREAR LISTA DE HORAS
            // ====================================================

            const horas =
                [];


            for (
                let minuto = inicio;
                minuto <= fin;
                minuto += 60
            ) {

                horas.push(
                    minutosAHora(
                        minuto
                    )
                );

            }


            // ====================================================
            // BORRAR ÚNICAMENTE BLOQUEOS
            // ====================================================

            const [
                resultado
            ] =
                await pool.query(

                    `DELETE FROM agendamientos
                     WHERE barberoId = ?
                     AND fecha = ?
                     AND hora IN (?)
                     AND
                     (
                         servicio = 'BLOQUEADO'
                         OR estado = 'Bloqueado'
                     )`,

                    [
                        req.usuario.id,
                        fecha,
                        horas
                    ]

                );


            if (
                resultado.affectedRows === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        horas.length === 1
                            ? 'Esa hora no está bloqueada.'
                            : 'No hay horas bloqueadas dentro de ese rango.'
                });

            }


            return res.json({

                success: true,

                desbloqueadas:
                    resultado.affectedRows,

                message:
                    resultado.affectedRows === 1

                        ? 'Horario desbloqueado correctamente.'

                        : `${resultado.affectedRows} horarios fueron desbloqueados correctamente.`

            });


        } catch (error) {

            console.error(
                'Error al desbloquear horario:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo desbloquear el horario.'
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
// MODIFICAR CITA DESDE PANEL DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/modificar-cita',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        let conexion;


        try {

            const idCita =
                Number(
                    req.body.idCita
                );


            const nuevaFecha =
                String(
                    req.body.nuevaFecha || ''
                ).trim();


            const nuevaHora =
                String(
                    req.body.nuevaHora || ''
                ).trim();


            const emailNuevo =
                String(
                    req.body.email ?? ''
                ).trim();


            if (
                !Number.isInteger(idCita) ||
                idCita <= 0 ||
                !nuevaFecha ||
                !nuevaHora
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Faltan datos para modificar la cita.'
                });

            }


            if (
                !/^\d{4}-\d{2}-\d{2}$/.test(
                    nuevaFecha
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La nueva fecha no es válida.'
                });

            }


            if (
                !/^\d{2}:\d{2}$/.test(
                    nuevaHora
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'La nueva hora no es válida.'
                });

            }


            if (
                emailNuevo &&
                !emailValidoBasico(
                    emailNuevo
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El correo ingresado no es válido.'
                });

            }


            const fechaLocal =
                new Date(
                    `${nuevaFecha}T12:00:00`
                );


            if (
                fechaLocal.getDay() === 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Los domingos no son días laborables.'
                });

            }


            if (
                await esDiaBloqueado(
                    req.usuario.id,
                    nuevaFecha
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Ese día está bloqueado.'
                });

            }


            const [citas] =
                await pool.query(

                    `SELECT *
                     FROM agendamientos
                     WHERE id = ?
                     AND barberoId = ?
                     LIMIT 1`,

                    [
                        idCita,
                        req.usuario.id
                    ]

                );


            if (
                citas.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        'La cita no existe o no pertenece a tu agenda.'
                });

            }


            const cita =
    citas[0];


// Una cita finalizada forma parte del historial
// y ya no debe poder modificarse.

if (
    String(
        cita.estado || ''
    )
        .trim()
        .toLowerCase() ===
    'finalizada'
) {

    return res.status(409).json({
        success: false,
        message:
            'Este servicio ya fue finalizado y no puede modificarse.'
    });

}


const fechaAnterior =
                fechaISODesdeBD(
                    cita.fecha
                );


            if (
                esBloqueoContinuo(
                    cita.servicio
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Esta hora pertenece a un servicio largo. Modifica la cita desde la hora de inicio.'
                });

            }


            const servicio =
                servicioBase(
                    cita.servicio
                );


            const esHoraExtra =
                String(
                    cita.estado || ''
                )
                    .trim()
                    .toLowerCase() ===
                'hora extra';


            const esServicioLargo =
                esServicioLargoParaBarbero(
                    req.usuario.id,
                    servicio
                );


            let nuevasHoras =
                [
                    nuevaHora
                ];


            if (
                esServicioLargo
            ) {

                nuevasHoras =
                    obtenerHorasContinuas(
                        nuevaHora,
                        4
                    );


                if (!nuevasHoras) {

                    return res.status(400).json({
                        success: false,
                        message:
                            'Este servicio requiere 4 horas continuas.'
                    });

                }

            }


            /*
             * Una cita normal solamente puede
             * moverse a horarios normales.
             *
             * Una HORA EXTRA sí puede moverse
             * fuera del horario habitual.
             */

            if (
                !esHoraExtra
            ) {

                const [barberos] =
                    await pool.query(

                        `SELECT horarios
                         FROM barberos
                         WHERE id = ?
                         AND activo = 1
                         LIMIT 1`,

                        [
                            req.usuario.id
                        ]

                    );


                const horariosConfigurados =
                    String(
                        barberos[0]?.horarios ||
                        ''
                    )
                        .split(',')
                        .map(
                            h => h.trim()
                        )
                        .filter(Boolean);


                const disponibles =
                    nuevasHoras.every(
                        h =>
                            horariosConfigurados
                                .includes(h)
                    );


                if (!disponibles) {

                    return res.status(400).json({
                        success: false,
                        message:
                            esServicioLargo
                                ? 'La nueva hora no permite completar las 4 horas dentro de tu jornada.'
                                : 'La nueva hora no pertenece a tus horarios normales.'
                    });

                }

            }


            const horasAnteriores =
                esServicioLargo

                    ? (
                        obtenerHorasContinuas(
                            cita.hora,
                            4
                        ) ||
                        [cita.hora]
                    )

                    : [
                        cita.hora
                    ];


            conexion =
                await pool.getConnection();


            await conexion.beginTransaction();


            /*
             * Obtenemos los IDs que pertenecen
             * a esta misma cita.
             */

            const idsPropios =
                [
                    Number(
                        cita.id
                    )
                ];


            if (
                esServicioLargo
            ) {

                const [bloquesViejos] =
                    await conexion.query(

                        `SELECT id
                         FROM agendamientos
                         WHERE barberoId = ?
                         AND fecha = ?
                         AND hora IN (?)
                         AND cliente = ?
                         AND (
                             id = ?
                             OR servicio = ?
                         )`,

                        [
                            req.usuario.id,
                            fechaAnterior,
                            horasAnteriores,
                            cita.cliente,
                            cita.id,
                            `${servicio} (Bloqueo Continuo)`
                        ]

                    );


                bloquesViejos.forEach(
                    bloque => {

                        const id =
                            Number(
                                bloque.id
                            );


                        if (
                            !idsPropios.includes(
                                id
                            )
                        ) {

                            idsPropios.push(
                                id
                            );

                        }

                    }
                );

            }


            /*
             * Comprobar que la nueva hora
             * no esté ocupada.
             */

            let consulta =
                `SELECT id
                 FROM agendamientos
                 WHERE barberoId = ?
                 AND fecha = ?
                 AND hora IN (?)`;


            const parametros =
                [
                    req.usuario.id,
                    nuevaFecha,
                    nuevasHoras
                ];


            consulta +=
                ' AND id NOT IN (?)';


            parametros.push(
                idsPropios
            );


            const [ocupados] =
                await conexion.query(
                    consulta,
                    parametros
                );


            if (
                ocupados.length > 0
            ) {

                await conexion.rollback();

                conexion.release();

                conexion =
                    null;


                return res.status(409).json({
                    success: false,
                    message:
                        esServicioLargo
                            ? 'No hay 4 horas continuas disponibles.'
                            : 'La nueva hora ya está ocupada.'
                });

            }


            /*
             * Borrar antiguos bloques continuos.
             */

            const continuaciones =
                idsPropios.filter(
                    id =>
                        Number(id) !==
                        Number(cita.id)
                );


            if (
                continuaciones.length > 0
            ) {

                await conexion.query(

                    `DELETE FROM agendamientos
                     WHERE id IN (?)`,

                    [
                        continuaciones
                    ]

                );

            }


            /*
             * Modificar la cita principal.
             */

            await conexion.query(

                `UPDATE agendamientos
                 SET fecha = ?,
                     hora = ?,
                     email = ?
                 WHERE id = ?
                 AND barberoId = ?`,

                [
                    nuevaFecha,
                    nuevaHora,
                    emailNuevo,
                    cita.id,
                    req.usuario.id
                ]

            );


            /*
             * Volver a crear los bloques de
             * un servicio de 4 horas.
             */

            if (
                esServicioLargo
            ) {

                for (
                    let i = 1;
                    i < nuevasHoras.length;
                    i++
                ) {

                    if (
                        esHoraExtra
                    ) {

                        await conexion.query(

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
                                `${servicio} (Bloqueo Continuo)`,
                                nuevaFecha,
                                nuevasHoras[i],
                                cita.cliente,
                                cita.telefono || '',
                                emailNuevo,
                                'Hora extra'
                            ]

                        );

                    }

                    else {

                        await conexion.query(

                            `INSERT INTO agendamientos
                            (
                                barberoId,
                                servicio,
                                fecha,
                                hora,
                                cliente,
                                telefono,
                                email
                            )
                            VALUES (?, ?, ?, ?, ?, ?, ?)`,

                            [
                                req.usuario.id,
                                `${servicio} (Bloqueo Continuo)`,
                                nuevaFecha,
                                nuevasHoras[i],
                                cita.cliente,
                                cita.telefono || '',
                                emailNuevo
                            ]

                        );

                    }

                }

            }


            await conexion.commit();

            conexion.release();

            conexion =
                null;


            const perfiles =
                await obtenerMapaPerfiles();


            const notificado =
                await enviarCorreoCambioCita({

                    email:
                        emailNuevo,

                    cliente:
                        cita.cliente,

                    barbero:
                        perfiles[
                            req.usuario.id
                        ] ||
                        'Tu Barbero',

                    servicio,

                    fechaAnterior,

                    horaAnterior:
                        cita.hora,

                    nuevaFecha,

                    nuevaHora

                });


            return res.json({

                success: true,

                notificado,

                message:
                    notificado

                        ? 'Cita modificada correctamente y cliente notificado por correo.'

                        : 'Cita modificada correctamente. El cliente no tenía un email registrado.'

            });


        } catch (error) {

            if (conexion) {

                try {

                    await conexion.rollback();

                } catch (_) {}


                conexion.release();

            }


            console.error(
                'Error modificando cita desde panel:',
                error
            );


            if (
                error.code ===
                'ER_DUP_ENTRY'
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        'La nueva hora acaba de ser tomada. Actualiza la agenda.'
                });

            }


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo modificar la cita.'
            });

        }

    }
);

// ============================================================
// CORREO DE VALORACIÓN
// ============================================================

async function enviarCorreoValoracion({
    email,
    cliente,
    barbero,
    servicio,
    token
}) {

    if (
        !email ||
        !emailValidoBasico(email)
    ) {

        return false;

    }


    try {

        const url =
            `${obtenerUrlPublica()}/valorar.html?t=${encodeURIComponent(token)}`;


        const { data, error } =
            await resend.emails.send({

                from:
                    EMAIL_REMITENTE,

                to:
                    [email],

                subject:
                    `¿Cómo estuvo tu experiencia con ${barbero}? ⭐`,

                html: `
                    <div
                        style="
                            margin:0;
                            padding:36px 18px;
                            background:#080808;
                            font-family:Arial,sans-serif;
                            color:#ffffff;
                        "
                    >

                        <div
                            style="
                                max-width:560px;
                                margin:auto;
                                overflow:hidden;
                                background:#111111;
                                border:1px solid #292929;
                                border-radius:18px;
                            "
                        >

                            <div
                                style="
                                    height:4px;
                                    background:#d30000;
                                "
                            ></div>


                            <div
                                style="
                                    padding:36px 34px;
                                "
                            >

                                <div
                                    style="
                                        color:#d30000;
                                        font-size:12px;
                                        font-weight:800;
                                        letter-spacing:3px;
                                        margin-bottom:14px;
                                    "
                                >
                                    PARCE BARBER
                                </div>


                                <h1
                                    style="
                                        margin:0 0 12px;
                                        color:#ffffff;
                                        font-size:28px;
                                        line-height:1.15;
                                    "
                                >
                                    Tu corte terminó.
                                </h1>


                                <p
                                    style="
                                        color:#a9a9a9;
                                        line-height:1.7;
                                        font-size:15px;
                                        margin-bottom:28px;
                                    "
                                >
                                    Hola
                                    <strong style="color:#ffffff;">
                                        ${cliente}
                                    </strong>.
                                    Queremos saber cómo fue tu experiencia
                                    con
                                    <strong style="color:#ffffff;">
                                        ${barbero}
                                    </strong>.
                                </p>


                                <div
                                    style="
                                        background:#171717;
                                        border:1px solid #262626;
                                        border-radius:13px;
                                        padding:18px 20px;
                                        margin-bottom:28px;
                                    "
                                >

                                    <div
                                        style="
                                            font-size:11px;
                                            letter-spacing:1.5px;
                                            color:#777777;
                                            font-weight:700;
                                            margin-bottom:6px;
                                        "
                                    >
                                        SERVICIO
                                    </div>

                                    <div
                                        style="
                                            font-size:16px;
                                            color:#ffffff;
                                            font-weight:700;
                                        "
                                    >
                                        ${servicio}
                                    </div>

                                </div>


                                <div
                                    style="
                                        text-align:center;
                                        margin:10px 0 30px;
                                    "
                                >

                                    <div
                                        style="
                                            color:#e4b552;
                                            letter-spacing:5px;
                                            font-size:27px;
                                            margin-bottom:15px;
                                        "
                                    >
                                        ★★★★★
                                    </div>


                                    <a
                                        href="${url}"
                                        style="
                                            display:inline-block;
                                            background:#d30000;
                                            color:#ffffff;
                                            text-decoration:none;
                                            font-size:13px;
                                            font-weight:800;
                                            letter-spacing:1px;
                                            padding:15px 28px;
                                            border-radius:9px;
                                        "
                                    >
                                        VALORAR MI EXPERIENCIA
                                    </a>

                                </div>


                                <p
                                    style="
                                        color:#666666;
                                        font-size:12px;
                                        line-height:1.6;
                                        text-align:center;
                                        margin:0;
                                    "
                                >
                                    La puntuación ayuda a mejorar el servicio.
                                    El comentario es opcional y será recibido
                                    por tu barbero.
                                </p>

                            </div>

                        </div>

                    </div>
                `

            });


        if (error) {

            console.error(
                '❌ Error enviando correo de valoración:',
                error
            );

            return false;

        }


        console.log(
            '⭐ Correo de valoración enviado:',
            data?.id
        );


        return true;


    } catch (error) {

        console.error(
            '❌ Error inesperado enviando valoración:',
            error
        );

        return false;

    }

}

// ============================================================
// OBTENER VALORACIÓN MEDIANTE TOKEN
// ============================================================

app.get(
    '/api/valoracion/:token',
    async (req, res) => {

        try {

            const token =
                String(
                    req.params.token || ''
                ).trim();


            if (
                !/^[a-f0-9]{64}$/i.test(
                    token
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El enlace de valoración no es válido.'
                });

            }


            const [rows] =
                await pool.query(

                    `SELECT
                        v.id,
                        v.cliente,
                        v.servicio,
                        v.puntuacion,
                        v.comentario,
                        v.valorado_en,

                        b.id AS barberoId,
                        b.nombre AS barbero,

                        a.fecha,
                        a.hora,
                        a.estado

                     FROM valoraciones v

                     INNER JOIN barberos b
                        ON b.id = v.barbero_id

                     INNER JOIN agendamientos a
                        ON a.id = v.agendamiento_id

                     WHERE v.token = ?

                     LIMIT 1`,

                    [
                        token
                    ]

                );


            if (
                rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        'Esta valoración no existe o el enlace ya no es válido.'
                });

            }


            const valoracion =
                rows[0];


            const yaValorada =
                valoracion.puntuacion !== null;


            return res.json({

                success: true,

                valoracion: {

                    cliente:
                        valoracion.cliente,

                    servicio:
                        valoracion.servicio,

                    barberoId:
                        valoracion.barberoId,

                    barbero:
                        valoracion.barbero,

                    fecha:
                        fechaISODesdeBD(
                            valoracion.fecha
                        ),

                    hora:
                        valoracion.hora,

                    yaValorada,

                    puntuacion:
                        yaValorada
                            ? Number(
                                valoracion.puntuacion
                            )
                            : null

                }

            });


        } catch (error) {

            console.error(
                'Error cargando valoración:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No pudimos cargar esta valoración.'
            });

        }

    }
);


// ============================================================
// GUARDAR VALORACIÓN
// ============================================================

app.post(
    '/api/valoracion/:token',
    async (req, res) => {

        try {

            const token =
                String(
                    req.params.token || ''
                ).trim();


            const puntuacion =
                Number(
                    req.body.puntuacion
                );


            const comentario =
                String(
                    req.body.comentario || ''
                ).trim();


            if (
                !/^[a-f0-9]{64}$/i.test(
                    token
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El enlace de valoración no es válido.'
                });

            }


            // Solo permitimos:
            // 0.5, 1, 1.5, 2 ... hasta 5.

            if (
                !Number.isFinite(
                    puntuacion
                )
                ||
                puntuacion < 0.5
                ||
                puntuacion > 5
                ||
                !Number.isInteger(
                    puntuacion * 2
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Selecciona una valoración entre 0.5 y 5 estrellas.'
                });

            }


            if (
                comentario.length > 1200
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'El comentario es demasiado largo.'
                });

            }


            const [rows] =
                await pool.query(

                    `SELECT
                        v.id,
                        v.puntuacion,
                        a.estado

                     FROM valoraciones v

                     INNER JOIN agendamientos a
                        ON a.id = v.agendamiento_id

                     WHERE v.token = ?

                     LIMIT 1`,

                    [
                        token
                    ]

                );


            if (
                rows.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        'Esta valoración no existe.'
                });

            }


            const valoracion =
                rows[0];


            if (
                String(
                    valoracion.estado || ''
                )
                    .trim()
                    .toLowerCase() !==
                'finalizada'
            ) {

                return res.status(409).json({
                    success: false,
                    message:
                        'Este servicio todavía no puede ser valorado.'
                });

            }


            if (
                valoracion.puntuacion !== null
            ) {

                return res.status(409).json({
                    success: false,
                    yaValorada: true,
                    message:
                        'Esta experiencia ya fue valorada anteriormente.'
                });

            }


            const [resultado] =
                await pool.query(

                    `UPDATE valoraciones

                     SET
                        puntuacion = ?,
                        comentario = ?,
                        valorado_en = CURRENT_TIMESTAMP

                     WHERE id = ?
                     AND puntuacion IS NULL`,

                    [
                        puntuacion,

                        comentario ||
                            null,

                        valoracion.id
                    ]

                );


            if (
                resultado.affectedRows === 0
            ) {

                return res.status(409).json({
                    success: false,
                    yaValorada: true,
                    message:
                        'Esta experiencia ya fue valorada.'
                });

            }


            return res.json({

                success: true,

                message:
                    'Gracias por compartir tu experiencia con Parce Barber.'

            });


        } catch (error) {

            console.error(
                'Error guardando valoración:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No pudimos guardar tu valoración.'
            });

        }

    }
);

// ============================================================
// FINALIZAR SERVICIO — PANEL DEL BARBERO
// ============================================================

app.post(
    '/api/barbero/finalizar-cita',
    requiereSesion,
    requiereBarberoActivo,
    async (req, res) => {

        let conexion;


        try {

            const idCita =
                Number(
                    req.body.idCita
                );


            if (
                !Number.isInteger(idCita) ||
                idCita <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Debes indicar una cita válida.'
                });

            }


            // =================================================
            // BUSCAR LA CITA
            // Solo puede finalizar citas propias.
            // =================================================

            const [citas] =
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
                     WHERE id = ?
                     AND barberoId = ?
                     LIMIT 1`,

                    [
                        idCita,
                        req.usuario.id
                    ]

                );


            if (
                citas.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        'La cita no existe o no pertenece a tu agenda.'
                });

            }


            const cita =
                citas[0];


            // =================================================
            // NO FINALIZAR BLOQUEOS
            // =================================================

            if (
                String(
                    cita.servicio || ''
                ).trim().toUpperCase() ===
                    'BLOQUEADO'
                ||
                esBloqueoContinuo(
                    cita.servicio
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Este horario no corresponde a una cita que pueda finalizarse.'
                });

            }


            // =================================================
            // SI YA ESTÁ FINALIZADA, NO HACEMOS NADA DE NUEVO
            // =================================================

            if (
                String(
                    cita.estado || ''
                )
                    .trim()
                    .toLowerCase() ===
                'finalizada'
            ) {

                return res.json({
                    success: true,
                    yaFinalizada: true,
                    message:
                        'Este servicio ya estaba finalizado.'
                });

            }


            const token =
                crearTokenValoracion();


            const servicio =
                servicioBase(
                    cita.servicio
                );


            conexion =
                await pool.getConnection();


            await conexion.beginTransaction();


            // =================================================
            // MARCAR CITA COMO FINALIZADA
            // =================================================

            await conexion.query(

                `UPDATE agendamientos
                 SET estado = 'Finalizada'
                 WHERE id = ?
                 AND barberoId = ?`,

                [
                    cita.id,
                    req.usuario.id
                ]

            );


            // =================================================
            // PREPARAR SU VALORACIÓN
            //
            // INSERT IGNORE evita crear dos valoraciones
            // para la misma cita.
            // =================================================

            await conexion.query(

    `INSERT IGNORE INTO valoraciones
    (
        agendamiento_id,
        barbero_id,
        cliente,
        servicio,
        token
    )
    VALUES (?, ?, ?, ?, ?)`,

    [
        cita.id,
        req.usuario.id,
        cita.cliente ||
            'Cliente',
        servicio ||
            'Servicio',
        token
    ]

);


// Leemos el token definitivo almacenado.
// Esto evita cualquier problema si la valoración
// ya había sido preparada anteriormente.

const [valoracionesCita] =
    await conexion.query(

        `SELECT token
         FROM valoraciones
         WHERE agendamiento_id = ?
         LIMIT 1`,

        [
            cita.id
        ]

    );


const tokenValoracion =
    valoracionesCita[0]?.token ||
    token;


await conexion.commit();


            conexion.release();

            conexion =
                null;


            const email =
                String(
                    cita.email || ''
                ).trim();


            const tieneCorreo =
                Boolean(email) &&
                emailValidoBasico(
                    email
                );

            let correoValoracionEnviado =
    false;


if (tieneCorreo) {

    const perfiles =
        await obtenerMapaPerfiles();


    const nombreBarbero =
        perfiles[
            req.usuario.id
        ] ||
        'Tu barbero';


    correoValoracionEnviado =
        await enviarCorreoValoracion({

            email,

            cliente:
                cita.cliente ||
                'Cliente',

            barbero:
                nombreBarbero,

            servicio:
                servicio ||
                'Servicio',

            token:
                tokenValoracion

        });

}


            return res.json({

    success: true,

    tieneCorreo,

    correoValoracionEnviado,

    message:
        tieneCorreo

            ? correoValoracionEnviado

                ? 'Servicio finalizado. Enviamos al cliente su invitación para valorar la experiencia.'

                : 'Servicio finalizado, pero no pudimos enviar el correo de valoración.'

            : 'Servicio finalizado. Esta cita no tiene correo registrado.'

});


        } catch (error) {

            if (conexion) {

                try {

                    await conexion.rollback();

                } catch (_) {}


                conexion.release();

            }


            console.error(
                'Error finalizando servicio:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo finalizar el servicio.'
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

        let conexion;


        try {

            const idCita =
                Number(
                    req.body.idCita
                );


            if (
                !Number.isInteger(idCita) ||
                idCita <= 0
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Debes indicar una cita válida.'
                });

            }


            const [citas] =
                await pool.query(

                    `SELECT *
                     FROM agendamientos
                     WHERE id = ?
                     AND barberoId = ?
                     LIMIT 1`,

                    [
                        idCita,
                        req.usuario.id
                    ]

                );


            if (
                citas.length === 0
            ) {

                return res.status(404).json({
                    success: false,
                    message:
                        'La cita no existe o no pertenece a tu agenda.'
                });

            }


            const cita =
    citas[0];


// Las citas finalizadas quedan registradas
// en el historial y no pueden eliminarse.

if (
    String(
        cita.estado || ''
    )
        .trim()
        .toLowerCase() ===
    'finalizada'
) {

    return res.status(409).json({
        success: false,
        message:
            'Este servicio ya fue finalizado y no puede cancelarse.'
    });

}


const fechaCita =
                fechaISODesdeBD(
                    cita.fecha
                );


            if (
                esBloqueoContinuo(
                    cita.servicio
                )
            ) {

                return res.status(400).json({
                    success: false,
                    message:
                        'Cancela esta reserva desde la hora de inicio del servicio.'
                });

            }


            const servicio =
                servicioBase(
                    cita.servicio
                );


            const esServicioLargo =
                esServicioLargoParaBarbero(
                    req.usuario.id,
                    servicio
                );


            const horasCita =
                esServicioLargo

                    ? (
                        obtenerHorasContinuas(
                            cita.hora,
                            4
                        ) ||
                        [cita.hora]
                    )

                    : [
                        cita.hora
                    ];


            conexion =
                await pool.getConnection();


            await conexion.beginTransaction();


            const idsEliminar =
                [
                    Number(
                        cita.id
                    )
                ];


            if (
                esServicioLargo
            ) {

                const [bloques] =
                    await conexion.query(

                        `SELECT id
                         FROM agendamientos
                         WHERE barberoId = ?
                         AND fecha = ?
                         AND hora IN (?)
                         AND cliente = ?
                         AND (
                             id = ?
                             OR servicio = ?
                         )`,

                        [
                            req.usuario.id,
                            fechaCita,
                            horasCita,
                            cita.cliente,
                            cita.id,
                            `${servicio} (Bloqueo Continuo)`
                        ]

                    );


                bloques.forEach(
                    bloque => {

                        const id =
                            Number(
                                bloque.id
                            );


                        if (
                            !idsEliminar.includes(
                                id
                            )
                        ) {

                            idsEliminar.push(
                                id
                            );

                        }

                    }
                );

            }


            await conexion.query(

                `DELETE FROM agendamientos
                 WHERE id IN (?)`,

                [
                    idsEliminar
                ]

            );


            await conexion.commit();

            conexion.release();

            conexion =
                null;


            const perfiles =
                await obtenerMapaPerfiles();


            const notificado =
                await enviarCorreoCancelacionCita({

                    email:
                        cita.email,

                    cliente:
                        cita.cliente,

                    barbero:
                        perfiles[
                            cita.barberoId
                        ] ||
                        'Tu Barbero',

                    servicio,

                    fecha:
                        fechaCita,

                    hora:
                        cita.hora

                });


            return res.json({

                success: true,

                notificado,

                message:
                    notificado

                        ? 'Cita cancelada correctamente y cliente notificado por correo.'

                        : 'Cita cancelada correctamente. El cliente no tenía un email registrado.'

            });


        } catch (error) {

            if (conexion) {

                try {

                    await conexion.rollback();

                } catch (_) {}


                conexion.release();

            }


            console.error(
                'Error cancelando cita del barbero:',
                error
            );


            return res.status(500).json({
                success: false,
                message:
                    'No se pudo cancelar la cita.'
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

    // ========================================================
// ALMUERZO AUTOMÁTICO
// ========================================================

const horaAlmuerzo =
    obtenerHoraAlmuerzo(
        barberoId
    );


if (
    horaAlmuerzo
    &&
    horasLista.includes(
        horaAlmuerzo
    )
    &&
    !ocupadas.includes(
        horaAlmuerzo
    )
) {

    ocupadas.push(
        horaAlmuerzo
    );

}
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


        // Aseguramos que la tabla de sugerencias exista.
        await asegurarTablaSugerencias();

        // Aseguramos que la tabla de valoraciones exista.
await asegurarTablaValoraciones();


        console.log(
            `✅ Servidor ONLINE en http://localhost:${PORT}`
        );


        console.log(
            '💾 Base de Datos MySQL CONECTADA correctamente.'
        );


        console.log(
            '💬 Tabla de sugerencias lista.'
        );

        console.log(
    '⭐ Tabla de valoraciones lista.'
);


    } catch (error) {

        console.error(
            '❌ Error preparando la base de datos:',
            error
        );

    }

});