require('dotenv').config();

const mysql = require('mysql2/promise');
const bcrypt = require('bcryptjs');

const pool = mysql.createPool({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

async function migrarContrasenas() {
    try {
        await pool.query(
            'ALTER TABLE barberos MODIFY COLUMN contrasena VARCHAR(255) NOT NULL'
        );

        const [barberos] = await pool.query(
            'SELECT id, usuario, contrasena FROM barberos'
        );

        let actualizados = 0;

        for (const barbero of barberos) {
            if (!barbero.contrasena || barbero.contrasena.startsWith('$2')) {
                continue;
            }

            const hash = await bcrypt.hash(barbero.contrasena, 12);

            await pool.query(
                'UPDATE barberos SET contrasena = ? WHERE id = ?',
                [hash, barbero.id]
            );

            actualizados++;
        }

        console.log(`Contraseñas protegidas: ${actualizados}`);
    } finally {
        await pool.end();
    }
}

migrarContrasenas().catch((error) => {
    console.error('No se pudieron proteger las contraseñas:', error);
    process.exitCode = 1;
});