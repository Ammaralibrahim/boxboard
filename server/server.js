const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const app = express();
const PORT = process.env.PORT || 5000;

// MongoDB bağlantısı ve model tanımı
mongoose.connect('mongodb+srv://ammar:alibrahim@cluster0.51i7rk6.mongodb.net/boxboard', { useNewUrlParser: true, useUnifiedTopology: true })
    .then(() => console.log('MongoDB connected'))
    .catch(err => console.error('MongoDB connection error:', err));

// Kullanıcı ve Kutu modellerini tanımla
const UserSchema = new mongoose.Schema({
    name: String,
    email: { type: String, unique: true },
    password: String,
});
const User = mongoose.model('User', UserSchema);

const BoxSchema = new mongoose.Schema({
    rented: Boolean,
    renter: {
      name: String,
      surname: String,
      email: String,
      phone: String,
      content: String,
    },
});
const Box = mongoose.model('Box', BoxSchema);

// CORS Middleware
app.use(cors({
    origin: 'http://localhost:3000', // İstemci tarafınızın URL'sini buraya ekleyin
    methods: ['GET', 'POST'],
    allowedHeaders: ['Content-Type', 'Authorization'],
  }));
  

// Diğer middleware'ler
app.use(express.json());

// JWT doğrulama middleware
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (token == null) return res.sendStatus(401);

    jwt.verify(token, 'aaazmh1980', (err, user) => {
        if (err) return res.sendStatus(403);
        req.user = user;
        next();
    });
};

// API rotaları
app.get('/api/auth', authenticateToken, async (req, res) => {
    const user = await User.findOne({ email: req.user.email });
    if (!user) return res.status(404).json({ error: 'User not found' });

    res.json({ name: user.name, email: user.email });
});

// Kullanıcı kaydı
app.post('/api/register', async (req, res) => {
    try {
        const hashedPassword = await bcrypt.hash(req.body.password, 10);
        const user = new User({
            name: req.body.name,
            email: req.body.email,
            password: hashedPassword,
        });
        await user.save();
        res.status(201).json({ message: 'User created' });
    } catch (err) {
        console.error('Error registering user:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Kullanıcı girişi ve token oluşturma
app.post('/api/login', async (req, res) => {
    const user = await User.findOne({ email: req.body.email });
    if (!user) return res.status(400).json({ error: 'Cannot find user' });

    if (await bcrypt.compare(req.body.password, user.password)) {
        const token = jwt.sign({ email: user.email }, 'aaazmh1980', { expiresIn: '8h' });
        res.json({ token });
    } else {
        res.status(403).json({ error: 'Invalid credentials' });
    }
});

// Kutuları getirme
app.get('/api/boxes', async (req, res) => {
    try {
        const boxes = await Box.find();
        res.json(boxes);
    } catch (err) {
        console.error('Error fetching boxes:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Box kiralama
app.post("/api/boxes/:id/rent", async (req, res) => {
    const { id } = req.params;
    const { name, surname, email, phone, content } = req.body;
  
    try {
      const box = await Box.findById(id);
      if (!box) return res.status(404).send("Box not found");
  
      if (box.rented) return res.status(400).send("Box already rented");
  
      box.rented = true;
      box.renter = { name, surname, email, phone, content };
  
      await box.save();
      res.status(200).send("Box successfully rented");
    } catch (error) {
      res.status(500).send("Server error");
    }
  });
  

// Kullanıcı profilini ve kiralanan kutuları ile ilgili tüm verileri getirme
app.get('/api/user/profile', authenticateToken, async (req, res) => {
    try {
        // Kullanıcıyı bul
        const user = await User.findOne({ email: req.user.email });
        if (!user) return res.status(404).json({ error: 'User not found' });

        // Kullanıcıya ait profil bilgilerini al
        const userProfile = {
            name: user.name,
            email: user.email,
            // Diğer kullanıcı bilgilerini burada ekleyebilirsiniz
        };

        // Kiralanan kutuları bul
        const rentedBoxes = await Box.find({ 'renter.email': user.email });

        // Kiralanan kutularla ilgili detayları al
        const detailedBoxes = rentedBoxes.map(box => ({
            id: box._id,
            rented: box.rented,
            renter: box.renter,
            // Burada box ile ilgili diğer detayları ekleyebilirsiniz
        }));

        // Kullanıcı bilgilerini ve kiralanan kutuları döndür
        res.json({
            userProfile: userProfile,
            rentedBoxes: detailedBoxes
        });
    } catch (err) {
        console.error('Error fetching user profile:', err);
        res.status(500).json({ error: 'Internal server error' });
    }
});

// Sunucu başlatma
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
