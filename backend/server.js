const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = 'supersecretkey';

// MongoDB connection
const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost:27017/icafal';
mongoose.connect(MONGO_URI, { useNewUrlParser: true, useUnifiedTopology: true })
  .then(() => console.log('MongoDB connected'))
  .catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  username: { type: String, unique: true, required: true },
  passwordHash: { type: String, required: true },
  role: { type: String, enum: ['user', 'admin'], required: true }
});
const User = mongoose.model('User', userSchema);

// Report Schema
const reportSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true },
  username: String,
  area: String,
  jornada: String,
  supervisor: String,
  team: [Object],
  actividades: [Object],
  dateSubmitted: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', reportSchema);

// Middleware to authenticate user via JWT
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  if (!authHeader) return res.status(401).json({ message: 'No token provided' });
  const token = authHeader.split(' ')[1];
  if (!token) return res.status(401).json({ message: 'No token provided' });

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ message: 'Invalid or expired token' });
    req.user = user;
    next();
  });
}

// Middleware to check if Admin
function isAdmin(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ message: 'Admin access required' });
  next();
}

// Register new user (solo admin puede registrar y asignar rol)
app.post('/auth/register', authenticateToken, isAdmin, async (req, res) => {
  const { username, password, role } = req.body;
  if (!username || !password || !role) return res.status(400).json({ message: 'Username, password y role requeridos' });

  if (!['user', 'admin'].includes(role)) {
    return res.status(400).json({ message: 'Rol inválido. Debe ser "user" o "admin".' });
  }

  try {
    const existingUser = await User.findOne({ username });
    if (existingUser) return res.status(400).json({ message: 'Username already taken' });
    const passwordHash = await bcrypt.hash(password, 8);
    const newUser = new User({ username, passwordHash, role });
    await newUser.save();
    res.status(201).json({ message: 'User registered successfully' });
  } catch (err) {
    res.status(500).json({ message: 'Error registering user', error: err.message });
  }
});

// Login user
app.post('/auth/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Invalid username or password' });
    const isValid = await bcrypt.compare(password, user.passwordHash);
    if (!isValid) return res.status(400).json({ message: 'Invalid username or password' });
    const token = jwt.sign({ id: user._id, username: user.username, role: user.role }, JWT_SECRET, { expiresIn: '8h' });
    res.json({ token, username: user.username, role: user.role });
  } catch (err) {
    res.status(500).json({ message: 'Error logging in', error: err.message });
  }
});

// Create a daily report - updated to accept area, jornada, supervisor, team, actividades
app.post('/reports', authenticateToken, async (req, res) => {
  const { area, jornada, supervisor, team, actividades } = req.body;
  if (!area || !jornada || !supervisor || !Array.isArray(team) || team.length === 0) {
    return res.status(400).json({ message: 'Área, jornada, supervisor y equipo son requeridos' });
  }
  for (const member of team) {
    if (
      typeof member !== 'object' ||
      Object.values(member).every(val => !val)
    ) {
      return res.status(400).json({ message: 'Cada integrante del equipo debe tener al menos un campo' });
    }
  }
  if (!Array.isArray(actividades) || actividades.length === 0) {
    return res.status(400).json({ message: 'Debe ingresar al menos una actividad realizada por el equipo' });
  }
  for (const act of actividades) {
    if (
      !act.descripcion || typeof act.descripcion !== 'string' ||
      !act.horaInicio || typeof act.horaInicio !== 'string' ||
      !act.horaFin || typeof act.horaFin !== 'string'
    ) {
      return res.status(400).json({ message: 'Cada actividad debe tener descripción, hora de inicio y hora de fin' });
    }
  }
  try {
    const newReport = new Report({
      userId: req.user.id,
      username: req.user.username,
      area,
      jornada,
      supervisor,
      team,
      actividades
    });
    await newReport.save();
    res.status(201).json({ message: 'Report created successfully', report: newReport });
  } catch (err) {
    res.status(500).json({ message: 'Error creating report', error: err.message });
  }
});

// Get all reports (admin only)
app.get('/reports', authenticateToken, isAdmin, async (req, res) => {
  try {
    const allReports = await Report.find();
    res.json(allReports);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching reports', error: err.message });
  }
});

// Get own reports (user)
app.get('/myreports', authenticateToken, async (req, res) => {
  try {
    const userReports = await Report.find({ userId: req.user.id });
    res.json(userReports);
  } catch (err) {
    res.status(500).json({ message: 'Error fetching user reports', error: err.message });
  }
});

// Eliminar informe por ID (admin puede eliminar cualquiera, usuario solo los suyos)
app.delete('/reports/:id', authenticateToken, async (req, res) => {
  const reportId = req.params.id;
  if (!mongoose.Types.ObjectId.isValid(reportId)) return res.status(400).json({ message: 'ID inválido' });
  try {
    const report = await Report.findById(reportId);
    if (!report) return res.status(404).json({ message: 'Informe no encontrado' });
    if (req.user.role !== 'admin' && String(report.userId) !== req.user.id) {
      return res.status(403).json({ message: 'No tienes permiso para eliminar este informe' });
    }
    await Report.findByIdAndDelete(reportId);
    res.json({ message: 'Informe eliminado correctamente' });
  } catch (err) {
    res.status(500).json({ message: 'Error deleting report', error: err.message });
  }
});

const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});

