const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const app = express();
const PORT = 3000;
const SECRET_KEY = "nusa_putra_secret";

app.use(express.json());

// =======================
// DATABASE PALSU (MEMORY)
// =======================
let users = [];
let activities = [];
let registrations = [];

// =======================
// MIDDLEWARE
// =======================

// Logger
app.use((req, res, next) => {
    console.log(`[${new Date().toISOString()}] ${req.method} ${req.url}`);
    next();
});

// Auth Middleware
const authMiddleware = (req, res, next) => {
    const token = req.headers['authorization']?.split(' ')[1];
    if (!token) return res.status(401).json({ message: "Token diperlukan" });

    jwt.verify(token, SECRET_KEY, (err, user) => {
        if (err) return res.status(403).json({ message: "Token tidak valid" });
        req.user = user;
        next();
    });
};

// Role Middleware
const roleMiddleware = (role) => (req, res, next) => {
    if (req.user.role !== role)
        return res.status(403).json({ message: `Akses ditolak: Khusus ${role}` });
    next();
};

// Validasi kegiatan
const activityValidation = (req, res, next) => {
    const { name, date, location } = req.body;
    if (!name || !date || !location) {
        return res.status(400).json({
            message: "Nama, tanggal, dan lokasi wajib diisi"
        });
    }
    next();
};

// =======================
// ENDPOINT
// =======================

// 1. Register
app.post('/register', async (req, res) => {
    const { username, password, role } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = {
        id: users.length + 1,
        username,
        password: hashedPassword,
        role
    };

    users.push(newUser);
    res.status(201).json({ message: "User berhasil didaftarkan" });
});

// 2. Login
app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    const user = users.find(u => u.username === username);

    if (user && await bcrypt.compare(password, user.password)) {
        const token = jwt.sign(
            { id: user.id, username: user.username, role: user.role },
            SECRET_KEY
        );
        res.json({ token });
    } else {
        res.status(401).json({ message: "Kredensial salah" });
    }
});

// 3. Get Activities (semua user)
app.get('/activities', authMiddleware, (req, res) => {
    res.json(activities);
});

// 4. Create Activity (Admin)
app.post('/activities',
    authMiddleware,
    roleMiddleware('Admin'),
    activityValidation,
    (req, res) => {

        const { name, date, location } = req.body;

        const newActivity = {
            id: activities.length + 1,
            name,
            date,
            location
        };

        activities.push(newActivity);
        res.status(201).json({ message: "Kegiatan berhasil dibuat" });
    }
);

// 5. Update Activity (Admin)
app.put('/activities/:id',
    authMiddleware,
    roleMiddleware('Admin'),
    activityValidation,
    (req, res) => {

        const { id } = req.params;
        const activity = activities.find(a => a.id == id);

        if (!activity)
            return res.status(404).json({ message: "Kegiatan tidak ditemukan" });

        activity.name = req.body.name;
        activity.date = req.body.date;
        activity.location = req.body.location;

        res.json({ message: "Kegiatan berhasil diperbarui" });
    }
);

// 6. Join Activity (Mahasiswa)
app.post('/activities/:id/join',
    authMiddleware,
    roleMiddleware('Mahasiswa'),
    (req, res) => {

        registrations.push({
            user_id: req.user.id,
            activity_id: Number(req.params.id)
        });

        res.json({ message: "Berhasil mendaftar kegiatan" });
    }
);

// =======================
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
});
