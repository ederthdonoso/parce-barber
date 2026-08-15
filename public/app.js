document.addEventListener('DOMContentLoaded', () => {
    const btnQuick = document.getElementById('btn-quick');
    
    if (btnQuick) {
        btnQuick.addEventListener('click', async () => {
            const cliente = document.getElementById('q-nombre').value;
            const telefono = document.getElementById('q-telefono').value;
            const email = document.getElementById('q-email').value;

            if(!cliente || !telefono || !email) {
                alert("Por favor, rellena todos los campos callejeros obligatorios para asignarte tu hora.");
                return;
            }

            btnQuick.innerText = "BUSCANDO TU HORA MÁS CERCANA...";
            
            try {
                const response = await fetch('/api/agenda-rapida', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ cliente, telefono, email })
                });
                
                const data = await response.json();
                
                if(data.success) {
                    document.getElementById('modal-details').innerHTML = `
                        <strong>Barbero Asignado:</strong> ${data.cita.barberoName}<br>
                        <strong>Fecha:</strong> ${data.cita.fecha}<br>
                        <strong>Hora Dorada:</strong> ${data.cita.hora} hrs<br>
                        <small style="color:#aaa;">Cortes acumulados con el Jefe: ${data.totalCortes}/30</small>
                    `;
                    document.getElementById('quick-modal').style.display = 'flex';
                } else {
                    alert(data.message);
                }
            } catch (err) {
                console.error("Error al agendar:", err);
            } finally {
                btnQuick.innerText = "Agendado Rápido";
            }
        });
    }
});