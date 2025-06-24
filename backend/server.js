const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const mongoose = require('mongoose');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors());

const JWT_SECRET = process.env.JWT_SECRET || 'supersecretkey';

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
  actividades: [Object], // Mantenemos para compatibilidad
  avances: [Object],
  interferencias: [Object],
  detenciones: [Object],
  comentarios: [Object],
  dateSubmitted: { type: Date, default: Date.now }
});
const Report = mongoose.model('Report', reportSchema);

// --- Catálogos: Modelos ---
const activitySchema = new mongoose.Schema({ nombre: { type: String, required: true, unique: true } });
const Activity = mongoose.model('Activity', activitySchema);

const tramoSchema = new mongoose.Schema({ nombre: { type: String, required: true, unique: true } });
const Tramo = mongoose.model('Tramo', tramoSchema);

const workerSchema = new mongoose.Schema({
  nombre: { type: String, required: true },
  rut: { type: String, required: true, unique: true },
  cargo: { type: String, required: true }
});
const Worker = mongoose.model('Worker', workerSchema);

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
  // Validar y guardar correctamente todos los campos
  const { area, jornada, supervisor, team, actividades, avances, interferencias, detenciones, comentarios } = req.body;
  
  if (!area || !jornada || !supervisor) {
    return res.status(400).json({ message: 'Área, jornada y supervisor son requeridos' });
  }
  if (!Array.isArray(team) || team.length === 0) {
    return res.status(400).json({ message: 'El equipo es requerido y no puede estar vacío' });
  }
  
  for (const member of team) {
    if (
      typeof member !== 'object' ||
      Object.values(member).every(val => !val)
    ) {
      return res.status(400).json({ message: 'Cada integrante del equipo debe tener al menos un campo' });
    }
    // Asegurar que tipoAsist se guarde aunque sea vacío
    if (!('tipoAsist' in member)) member.tipoAsist = '';
  }
  
  // Procesar actividades (mantenemos para compatibilidad)
  let safeActividades = [];
  if (Array.isArray(actividades)) {
    safeActividades = actividades.map(act => ({
      descripcion: act.descripcion || '',
      horaInicio: act.horaInicio || '',
      horaFin: act.horaFin || '',
      detalle: act.detalle || ''
    }));
  }

  // Procesar nuevos campos con validación mejorada
  let safeAvances = [];
  if (Array.isArray(avances)) {
    safeAvances = avances.filter(av => av && av.descripcion && av.descripcion.trim())
      .map(av => ({ descripcion: av.descripcion.trim() }));
  }

  let safeInterferencias = [];
  if (Array.isArray(interferencias)) {
    safeInterferencias = interferencias.filter(inter => inter && inter.descripcion && inter.descripcion.trim())
      .map(inter => ({ descripcion: inter.descripcion.trim() }));
  }

  let safeDetenciones = [];
  if (Array.isArray(detenciones)) {
    safeDetenciones = detenciones.filter(det => det && det.descripcion && det.descripcion.trim())
      .map(det => ({ descripcion: det.descripcion.trim() }));
  }

  let safeComentarios = [];
  if (Array.isArray(comentarios)) {
    safeComentarios = comentarios.filter(com => com && com.descripcion && com.descripcion.trim())
      .map(com => ({ descripcion: com.descripcion.trim() }));
  }

  try {
    const reportData = {
      userId: req.user.id,
      username: req.user.username,
      area,
      jornada,
      supervisor,
      team,
      actividades: safeActividades,
      avances: safeAvances,
      interferencias: safeInterferencias,
      detenciones: safeDetenciones,
      comentarios: safeComentarios
    };
    
    const newReport = new Report(reportData);
    const savedReport = await newReport.save();
    
    res.status(201).json({ message: 'Report created successfully', report: savedReport });
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

// --- Catálogos: Rutas ---
// ACTIVITIES
app.get('/catalog/activities', authenticateToken, async (req, res) => {
  const list = await Activity.find();
  res.json(list);
});
app.post('/catalog/activities', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre } = req.body;
    if (!nombre) return res.status(400).json({ message: 'Nombre requerido' });
    const act = new Activity({ nombre });
    await act.save();
    res.status(201).json(act);
  } catch (e) { res.status(400).json({ message: e.message }); }
});
app.put('/catalog/activities/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre } = req.body;
    const act = await Activity.findByIdAndUpdate(req.params.id, { nombre }, { new: true });
    if (!act) return res.status(404).json({ message: 'No encontrado' });
    res.json(act);
  } catch (e) { res.status(400).json({ message: e.message }); }
});
app.delete('/catalog/activities/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Activity.findByIdAndDelete(req.params.id);
    res.json({ message: 'Eliminado' });
  } catch (e) { res.status(400).json({ message: e.message }); }
});

// TRAMOS
app.get('/catalog/tramos', authenticateToken, async (req, res) => {
  const list = await Tramo.find();
  res.json(list);
});
app.post('/catalog/tramos', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre } = req.body;
    if (!nombre) return res.status(400).json({ message: 'Nombre requerido' });
    const tramo = new Tramo({ nombre });
    await tramo.save();
    res.status(201).json(tramo);
  } catch (e) { res.status(400).json({ message: e.message }); }
});
app.put('/catalog/tramos/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre } = req.body;
    const tramo = await Tramo.findByIdAndUpdate(req.params.id, { nombre }, { new: true });
    if (!tramo) return res.status(404).json({ message: 'No encontrado' });
    res.json(tramo);
  } catch (e) { res.status(400).json({ message: e.message }); }
});
app.delete('/catalog/tramos/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Tramo.findByIdAndDelete(req.params.id);
    res.json({ message: 'Eliminado' });
  } catch (e) { res.status(400).json({ message: e.message }); }
});

// WORKERS
app.get('/catalog/workers', authenticateToken, async (req, res) => {
  const list = await Worker.find();
  res.json(list);
});
// Solo admin puede crear trabajadores
app.post('/catalog/workers', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre, rut, cargo } = req.body;
    if (!nombre || !rut || !cargo) return res.status(400).json({ message: 'Todos los campos son requeridos' });
    const worker = new Worker({ nombre, rut, cargo });
    await worker.save();
    res.status(201).json(worker);
  } catch (e) { res.status(400).json({ message: e.message }); }
});
app.put('/catalog/workers/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    const { nombre, rut, cargo } = req.body;
    const worker = await Worker.findByIdAndUpdate(req.params.id, { nombre, rut, cargo }, { new: true });
    if (!worker) return res.status(404).json({ message: 'No encontrado' });
    res.json(worker);
  } catch (e) { res.status(400).json({ message: e.message }); }
});
app.delete('/catalog/workers/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Worker.findByIdAndDelete(req.params.id);
    res.json({ message: 'Eliminado' });
  } catch (e) { res.status(400).json({ message: e.message }); }
});

app.delete('/catalog/workers/:id', authenticateToken, isAdmin, async (req, res) => {
  try {
    await Worker.findByIdAndDelete(req.params.id);
    res.json({ message: 'Eliminado' });
  } catch (e) { res.status(400).json({ message: e.message }); }
});

const PORT = process.env.PORT || 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});

