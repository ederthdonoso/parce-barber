# 💈 Parce Barber

Sistema web de gestión y agendamiento de citas para una barbería.

Parce Barber permite a los clientes consultar los servicios disponibles, seleccionar un barbero, elegir una fecha y hora y gestionar sus citas.

Además, cuenta con paneles privados para los barberos y para el jefe de la barbería.

---

## 🚀 Funcionalidades

### 👤 Clientes

- Visualización de la barbería y sus servicios.
- Selección de barbero.
- Consulta de disponibilidad.
- Agendamiento de horas.
- Consulta de próximas citas mediante correo electrónico.
- Modificación de una cita.
- Cancelación de citas.
- Sistema de cortes para clientes frecuentes.
- Notificaciones por correo electrónico.

### 💈 Barberos

Cada barbero dispone de un acceso privado mediante usuario y contraseña.

Desde su panel puede:

- Consultar sus citas.
- Revisar información de sus clientes.
- Gestionar sus horas.
- Bloquear horarios.
- Cancelar citas cuando sea necesario.
- Acceder al panel correspondiente según sus permisos.

Los barberos desactivados no pueden iniciar sesión.

### 👑 Jefe de barbería

El jefe dispone de un panel administrativo protegido.

Puede:

- Gestionar barberos.
- Crear nuevos barberos.
- Editar información de los barberos.
- Desactivar barberos.
- Gestionar citas.
- Modificar citas.
- Cancelar citas.
- Consultar información general de la agenda.

Los permisos administrativos están protegidos mediante autenticación y control de roles.

---

## 🔐 Seguridad

El proyecto incorpora diferentes medidas de seguridad:

- Autenticación mediante JWT.
- Cookies `HttpOnly`.
- Cookies `Secure` en producción.
- Configuración `SameSite`.
- Contraseñas almacenadas mediante `bcrypt`.
- Control de acceso mediante roles.
- Protección de rutas administrativas.
- Validación de barberos activos.
- Sesiones con tiempo de expiración.
- Protección contra múltiples intentos de inicio de sesión.
- Headers de seguridad mediante Helmet.
- Restricciones de integridad en MySQL para evitar reservas duplicadas.
- Variables sensibles almacenadas mediante variables de entorno.

### Variables de entorno

Las credenciales y secretos **no deben almacenarse en GitHub**.

El proyecto utiliza variables como:

```env
NODE_ENV=production

DB_HOST=
DB_USER=
DB_PASSWORD=
DB_NAME=

EMAIL_USUARIO=
EMAIL_PASSWORD=

JWT_SECRET=