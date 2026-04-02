const { spawn } = require('child_process');
const axios = require('axios');

// 🔧 Change interface if needed
const INTERFACE = '4';

// 🚀 Start tshark
const tshark = spawn('tshark', [
    '-i', INTERFACE,
    '-l', // 🔥 real-time line buffering
    '-T', 'fields',
    '-e', 'ip.src',
    '-e', 'ip.dst',
    '-e', '_ws.col.Protocol',
    '-e', 'dns.qry.name',
    '-e', 'http.host'
]);

// 🧠 Process packets
tshark.stdout.on('data', (data) => {
    const lines = data.toString().split('\n');

    lines.forEach(async (line) => {
        if (!line) return;

        const parts = line.split('\t');

        // 🧹 Clean data
        const source_ip = parts[0]?.trim();
        const destination_ip = parts[1]?.trim();
        const protocolRaw = parts[2]?.trim();
        const dns = parts[3]?.trim();
        const http = parts[4]?.trim();

        // ❌ Skip invalid
        if (
            !source_ip ||
            !destination_ip ||
            !protocolRaw ||
            source_ip === '' ||
            destination_ip === '' ||
            protocolRaw === ''
        ) {
            return;
        }

        // 🔥 Normalize protocol
        const protocol = protocolRaw.toUpperCase();

        // 🌐 Extract website (clean)
        let website = null;

        if (dns && dns !== '') {
            website = dns;
        } else if (http && http !== '') {
            website = http;
        }

        console.log(
            `Captured: ${source_ip} → ${destination_ip} → ${protocol} → ${website || '-'}`
        );

        // 🚀 Send to backend
        axios.post('http://localhost:3000/packets', {
            source_ip,
            destination_ip,
            protocol,
            website
        }).catch(err => {
            console.error("API Error:", err.response?.data || err.message);
        });
    });
});

// ❌ Tshark errors
tshark.stderr.on('data', (err) => {
    console.error("Tshark Error:", err.toString());
});

// 🔚 Exit handling
tshark.on('close', (code) => {
    console.log(`Tshark exited with code ${code}`);
});