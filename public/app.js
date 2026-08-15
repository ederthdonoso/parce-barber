document.addEventListener('DOMContentLoaded', () => {
    const btnQuick = document.getElementById('btn-quick');

    if (btnQuick) {
        btnQuick.addEventListener('click', async () => {
            const cliente = document.getElementById('q-nombre').value.trim();
            const telefono = document.getElementById('q-telefono').value.trim();
            const email = document.getElementById('q-email').value.trim();

            if (!cliente || !telefono || !email) {
                alert('Por favor, rellena todos los campos obligatorios para asignarte tu hora.');
                return;
            }

            btnQuick.innerText = 'BUSCANDO TU HORA MÁS CERCANA...';
            btnQuick.disabled = true;

            try {
                const response = await fetch('/api/agendado-rapido', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json'
                    },
                    body: JSON.stringify({
                        cliente,
                        telefono,
                        email
                    })
                });

                const data = await response.json();

                if (data.success) {
                    document.getElementById('modal-details').innerHTML =
                        '<strong>Barbero Asignado:</strong> ' +
                        data.asignado.barbero +
                        '<br>' +
                        '<strong>Fecha:</strong> ' +
                        data.asignado.fecha +
                        '<br>' +
                        '<strong>Hora:</strong> ' +
                        data.asignado.hora +
                        ' hrs';

                    document.getElementById('quick-modal').style.display = 'flex';
                } else {
                    alert(
                        data.message ||
                        'No encontramos una hora disponible.'
                    );
                }

            } catch (err) {
                console.error('Error al agendar:', err);

                alert(
                    'No pudimos conectar con el servidor. Inténtalo nuevamente.'
                );

            } finally {
                btnQuick.innerText = 'Agendado Rápido';
                btnQuick.disabled = false;
            }
        });
    }
});

