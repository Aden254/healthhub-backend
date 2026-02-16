const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const http = require('http');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();

const app = express();
const server = http.createServer(app);
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Socket.io for WebRTC signaling
let io;
try {
  const { Server } = require('socket.io');
  io = new Server(server, {
    cors: { origin: '*', methods: ['GET', 'POST'] }
  });
  console.log('Socket.io loaded for WebRTC signaling');
} catch (e) {
  console.log('Socket.io not installed - WebRTC signaling disabled');
  console.log('Run: npm install socket.io uuid');
}

// Middleware
app.use(cors({
  origin: ['http://localhost:5173', 'https://localhost:5173', 'http://172.20.238.43:5173', 'https://172.20.238.43:5173'],
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE'],
  credentials: true
}));
app.use(express.json());

// Database connection
const db = mysql.createPool({
  host: process.env.DB_HOST || 'localhost',
  user: process.env.DB_USER || 'root',
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME || 'healthhub_db',
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0
});

// Promisified query helper (used by ConsultLink endpoints)
const query = (sql, params) => {
  return new Promise((resolve, reject) => {
    db.query(sql, params, (err, results) => {
      if (err) reject(err);
      else resolve(results);
    });
  });
};

// Test database connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('Database connection failed:', err);
    return;
  }
  console.log('Connected to MySQL database');
  connection.release();
});

// ==================== AUTHENTICATION MIDDLEWARE ====================

const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(401).json({ error: 'Access token required' });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) {
      return res.status(403).json({ error: 'Invalid or expired token' });
    }
    req.user = user;
    next();
  });
};

const authorizeRole = (...allowedRoles) => {
  return (req, res, next) => {
    if (!req.user || !allowedRoles.includes(req.user.role)) {
      return res.status(403).json({ 
        error: 'Access denied',
        message: `This action requires one of: ${allowedRoles.join(', ')}`
      });
    }
    next();
  };
};

// ==================== AUTHENTICATION ROUTES ====================

// Health check (public)
app.get('/', (req, res) => {
  res.json({ 
    status: 'HealthHub API is running!',
    version: '3.0.0',
    features: ['Authentication', 'CRUD Operations', 'Role-Based Access', 'ConsultLink Telehealth'],
    demoAccounts: {
      doctor: 'doc01 / password123',
      nurse: 'nurse01 / password123',
      admin: 'admin / password123'
    }
  });
});

// Login
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Username and password required' });
  }

  const loginQuery = `
    SELECT 
      u.userId, u.username, u.role, u.MedicalPersonnelId,
      mp.Fname, mp.Lname, mp.Specialty, mp.DoctorId
    FROM Users u
    LEFT JOIN MedicalPersonnel mp ON u.MedicalPersonnelId = mp.MedicalPersonnelId
    WHERE u.username = ? AND u.password = ? AND u.isActive = 1
  `;

  db.query(loginQuery, [username, password], (err, results) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Login failed' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = results[0];

    db.query('UPDATE Users SET lastLogin = NOW() WHERE userId = ?', [user.userId]);

    const token = jwt.sign(
      { 
        userId: user.userId, 
        username: user.username, 
        role: user.role,
        medicalPersonnelId: user.MedicalPersonnelId
      },
      JWT_SECRET,
      { expiresIn: '8h' }
    );

    res.json({
      token,
      user: {
        userId: user.userId,
        username: user.username,
        role: user.role,
        name: user.Fname && user.Lname ? `${user.Fname} ${user.Lname}` : 'Admin',
        specialty: user.Specialty,
        medicalPersonnelId: user.MedicalPersonnelId
      }
    });
  });
});

// Get current user info
app.get('/api/auth/me', authenticateToken, (req, res) => {
  const meQuery = `
    SELECT 
      u.userId, u.username, u.role, u.MedicalPersonnelId,
      mp.Fname, mp.Lname, mp.Specialty, mp.DoctorId
    FROM Users u
    LEFT JOIN MedicalPersonnel mp ON u.MedicalPersonnelId = mp.MedicalPersonnelId
    WHERE u.userId = ?
  `;

  db.query(meQuery, [req.user.userId], (err, results) => {
    if (err) {
      return res.status(500).json({ error: 'Failed to fetch user info' });
    }

    if (results.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    const user = results[0];
    res.json({
      userId: user.userId,
      username: user.username,
      role: user.role,
      name: user.Fname && user.Lname ? `${user.Fname} ${user.Lname}` : 'Admin',
      specialty: user.Specialty,
      medicalPersonnelId: user.MedicalPersonnelId
    });
  });
});

// ==================== DASHBOARD STATS ====================

app.get('/api/stats', authenticateToken, (req, res) => {
  const queries = {
    totalPatients: 'SELECT COUNT(*) as count FROM Patient',
    activePatients: 'SELECT COUNT(*) as count FROM Patient WHERE Discharge = 0',
    totalDoctors: 'SELECT COUNT(*) as count FROM MedicalPersonnel WHERE DoctorId IS NOT NULL',
    totalNurses: 'SELECT COUNT(*) as count FROM MedicalPersonnel WHERE DoctorId IS NULL',
    totalPrescriptions: 'SELECT COUNT(*) as count FROM Prescriptions WHERE Status = "Active"',
    activeSessions: "SELECT COUNT(*) as count FROM consultation_sessions WHERE status IN ('pending', 'active')"
  };

  const stats = {};
  let completed = 0;

  Object.entries(queries).forEach(([key, q]) => {
    db.query(q, (err, results) => {
      if (err) {
        console.error(`Error fetching ${key}:`, err);
        stats[key] = 0;
      } else {
        stats[key] = results[0].count;
      }
      
      completed++;
      if (completed === Object.keys(queries).length) {
        res.json(stats);
      }
    });
  });
});

// ==================== PATIENTS CRUD ====================

app.get('/api/patients', authenticateToken, (req, res) => {
  const patientsQuery = `
    SELECT p.*, mp.Fname as DoctorFname, mp.Lname as DoctorLname, mp.Specialty
    FROM Patient p
    LEFT JOIN MedicalPersonnel mp ON p.AssignedDoctorId = mp.MedicalPersonnelId
    ORDER BY p.patientId
  `;
  
  db.query(patientsQuery, (err, results) => {
    if (err) {
      console.error('Error fetching patients:', err);
      return res.status(500).json({ error: 'Failed to fetch patients' });
    }
    res.json(results);
  });
});

app.get('/api/patients/:id', authenticateToken, (req, res) => {
  const patientQuery = `
    SELECT p.*, mp.Fname as DoctorFname, mp.Lname as DoctorLname, mp.Specialty
    FROM Patient p
    LEFT JOIN MedicalPersonnel mp ON p.AssignedDoctorId = mp.MedicalPersonnelId
    WHERE p.patientId = ?
  `;
  
  db.query(patientQuery, [req.params.id], (err, results) => {
    if (err) {
      console.error('Error fetching patient:', err);
      return res.status(500).json({ error: 'Failed to fetch patient' });
    }
    if (results.length === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }
    res.json(results[0]);
  });
});

app.post('/api/patients', authenticateToken, authorizeRole('Nurse', 'Doctor', 'Admin'), (req, res) => {
  const { 
    patientId, Fname, Lname, Birthdate, Phone, Address,
    ECname, ECcontact, Diet, MedicalHistory, Diagnosis 
  } = req.body;

  if (!patientId || !Fname || !Lname || !Birthdate) {
    return res.status(400).json({ error: 'Missing required fields: patientId, Fname, Lname, Birthdate' });
  }

  const findDoctorQuery = `
    SELECT MedicalPersonnelId FROM MedicalPersonnel 
    WHERE DoctorId IS NOT NULL AND Status = 'Active'
    ORDER BY PatientLoad ASC LIMIT 1
  `;

  db.query(findDoctorQuery, (err, doctors) => {
    if (err || doctors.length === 0) {
      return res.status(500).json({ error: 'No available doctors' });
    }

    const assignedDoctorId = doctors[0].MedicalPersonnelId;

    const insertQuery = `
      INSERT INTO Patient (patientId, Fname, Lname, Birthdate, Phone, Address, ECname, ECcontact, Diet, \`Medical History\`, Diagnosis, AssignedDoctorId)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;

    db.query(insertQuery, [patientId, Fname, Lname, Birthdate, Phone, Address, ECname, ECcontact, Diet, MedicalHistory, Diagnosis, assignedDoctorId], (err) => {
      if (err) {
        if (err.code === 'ER_DUP_ENTRY') {
          return res.status(409).json({ error: 'Patient ID already exists' });
        }
        return res.status(500).json({ error: 'Failed to add patient' });
      }

      db.query(
        'INSERT INTO AuditLog (TableName, RecordId, Action, ChangedBy, NewValue, ChangeDate) VALUES (?, ?, ?, ?, ?, NOW())',
        ['Patient', patientId, 'INSERT', req.user.username, `Patient added by ${req.user.username}, assigned to ${assignedDoctorId}`]
      );

      res.status(201).json({ 
        message: 'Patient added successfully', 
        patientId: patientId,
        assignedDoctor: assignedDoctorId
      });
    });
  });
});

app.put('/api/patients/:id', authenticateToken, authorizeRole('Doctor', 'Admin'), (req, res) => {
  const patientId = req.params.id;
  const updates = req.body;
  
  const allowedFields = ['Fname', 'Lname', 'Phone', 'Address', 'ECname', 'ECcontact', 'Diet', 'Medical History', 'Diagnosis'];
  const updateFields = [];
  const updateValues = [];

  Object.keys(updates).forEach(key => {
    if (allowedFields.includes(key)) {
      updateFields.push(`\`${key}\` = ?`);
      updateValues.push(updates[key]);
    }
  });

  if (updateFields.length === 0) {
    return res.status(400).json({ error: 'No valid fields to update' });
  }

  updateValues.push(patientId);

  const updateQuery = `UPDATE Patient SET ${updateFields.join(', ')} WHERE patientId = ?`;

  db.query(updateQuery, updateValues, (err, result) => {
    if (err) {
      console.error('Error updating patient:', err);
      return res.status(500).json({ error: 'Failed to update patient' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    db.query(
      'INSERT INTO AuditLog (TableName, RecordId, Action, ChangedBy, NewValue, ChangeDate) VALUES (?, ?, ?, ?, ?, NOW())',
      ['Patient', patientId, 'UPDATE', req.user.username, `Patient updated by ${req.user.username}`]
    );
    res.json({ message: 'Patient updated successfully' });
  });
});

app.patch('/api/patients/:id/discharge', authenticateToken, authorizeRole('Doctor', 'Admin'), (req, res) => {
  const patientId = req.params.id;

  db.query('CALL DischargePatient(?, CURDATE())', [patientId], (err) => {
    if (err) {
      console.error('Error discharging patient:', err);
      return res.status(500).json({ error: 'Failed to discharge patient' });
    }

    res.json({ 
      message: 'Patient discharged successfully',
      dischargedBy: req.user.username,
      dischargeDate: new Date().toISOString().split('T')[0]
    });
  });
});

// ==================== MEDICAL PERSONNEL ====================

app.get('/api/medical-personnel', authenticateToken, (req, res) => {
  const personnelQuery = `
    SELECT mp.*, COUNT(DISTINCT p.patientId) as patient_count
    FROM MedicalPersonnel mp
    LEFT JOIN Patient p ON mp.MedicalPersonnelId = p.AssignedDoctorId
    GROUP BY mp.MedicalPersonnelId
    ORDER BY mp.Specialty, mp.Lname
  `;
  
  db.query(personnelQuery, (err, results) => {
    if (err) {
      console.error('Error fetching medical personnel:', err);
      return res.status(500).json({ error: 'Failed to fetch medical personnel' });
    }
    res.json(results);
  });
});

app.get('/api/doctors', authenticateToken, (req, res) => {
  const doctorsQuery = `
    SELECT mp.*, COUNT(DISTINCT p.patientId) as patient_count
    FROM MedicalPersonnel mp
    LEFT JOIN Patient p ON mp.MedicalPersonnelId = p.AssignedDoctorId
    WHERE mp.DoctorId IS NOT NULL
    GROUP BY mp.MedicalPersonnelId
    ORDER BY mp.Lname
  `;
  
  db.query(doctorsQuery, (err, results) => {
    if (err) {
      console.error('Error fetching doctors:', err);
      return res.status(500).json({ error: 'Failed to fetch doctors' });
    }
    res.json(results);
  });
});

// ==================== PRESCRIPTIONS ====================

app.get('/api/prescriptions', authenticateToken, (req, res) => {
  const rxQuery = `
    SELECT pr.*, p.Fname as PatientFname, p.Lname as PatientLname,
           d.DrugsName, d.Dosage, d.Generics,
           mp.Fname as DoctorFname, mp.Lname as DoctorLname
    FROM Prescriptions pr
    JOIN Patient p ON pr.PatientID = p.patientId
    JOIN Drugs d ON pr.DrugID = d.DrugsId
    JOIN MedicalPersonnel mp ON pr.DoctorID = mp.MedicalPersonnelId
    ORDER BY pr.Date DESC
  `;
  
  db.query(rxQuery, (err, results) => {
    if (err) {
      console.error('Error fetching prescriptions:', err);
      return res.status(500).json({ error: 'Failed to fetch prescriptions' });
    }
    res.json(results);
  });
});

app.get('/api/prescriptions/refills-due', authenticateToken, (req, res) => {
  const refillQuery = `
    SELECT pr.*, p.Fname as PatientFname, p.Lname as PatientLname,
           d.DrugsName, d.Dosage,
           mp.Fname as DoctorFname, mp.Lname as DoctorLname,
           DATEDIFF(pr.RefillDate, CURDATE()) as days_until_refill
    FROM Prescriptions pr
    JOIN Patient p ON pr.PatientID = p.patientId
    JOIN Drugs d ON pr.DrugID = d.DrugsId
    JOIN MedicalPersonnel mp ON pr.DoctorID = mp.MedicalPersonnelId
    WHERE pr.RefillDate BETWEEN CURDATE() AND DATE_ADD(CURDATE(), INTERVAL 7 DAY)
    ORDER BY pr.RefillDate
  `;
  
  db.query(refillQuery, (err, results) => {
    if (err) {
      console.error('Error fetching refills:', err);
      return res.status(500).json({ error: 'Failed to fetch refills' });
    }
    res.json(results);
  });
});

// ==================== TESTS ====================

app.get('/api/tests', authenticateToken, (req, res) => {
  db.query('SELECT * FROM Tests ORDER BY TestName', (err, results) => {
    if (err) {
      console.error('Error fetching tests:', err);
      return res.status(500).json({ error: 'Failed to fetch tests' });
    }
    res.json(results);
  });
});

app.get('/api/tests/scheduled', authenticateToken, (req, res) => {
  const scheduledQuery = `
    SELECT t.*, p.Fname as PatientFname, p.Lname as PatientLname,
           ts.TestName, ts.\`Testing Department\`
    FROM \`Tested for\` t
    JOIN Patient p ON t.Patient = p.patientId
    JOIN Tests ts ON t.TestId = ts.TestsId
    WHERE t.Status = 'Scheduled'
    ORDER BY t.Date
  `;
  
  db.query(scheduledQuery, (err, results) => {
    if (err) {
      console.error('Error fetching scheduled tests:', err);
      return res.status(500).json({ error: 'Failed to fetch scheduled tests' });
    }
    res.json(results);
  });
});

// ==================== REPORTS ====================

app.get('/api/reports', authenticateToken, (req, res) => {
  const reportsQuery = `
    SELECT w.*, p.Fname as PatientFname, p.Lname as PatientLname,
           mp.Fname as DoctorFname, mp.Lname as DoctorLname,
           r.reportType
    FROM Writes w
    JOIN Patient p ON w.Patient = p.patientId
    JOIN MedicalPersonnel mp ON w.MedicalPersonnel = mp.MedicalPersonnelId
    JOIN Report r ON w.Reportid = r.reportId
    ORDER BY w.Date DESC
  `;
  
  db.query(reportsQuery, (err, results) => {
    if (err) {
      console.error('Error fetching reports:', err);
      return res.status(500).json({ error: 'Failed to fetch reports' });
    }
    res.json(results);
  });
});

// ==================== SEARCH ====================

app.get('/api/search/patients', authenticateToken, (req, res) => {
  const searchTerm = req.query.q || '';
  const searchQuery = `
    SELECT p.*, mp.Fname as DoctorFname, mp.Lname as DoctorLname
    FROM Patient p
    LEFT JOIN MedicalPersonnel mp ON p.AssignedDoctorId = mp.MedicalPersonnelId
    WHERE p.Fname LIKE ? OR p.Lname LIKE ? OR p.patientId LIKE ?
    ORDER BY p.Lname
    LIMIT 20
  `;
  
  const searchPattern = `%${searchTerm}%`;
  db.query(searchQuery, [searchPattern, searchPattern, searchPattern], (err, results) => {
    if (err) {
      console.error('Error searching patients:', err);
      return res.status(500).json({ error: 'Search failed' });
    }
    res.json(results);
  });
});

// ==================== CONSULTLINK: TELEHEALTH ENDPOINTS ====================

// Create a consultation session (Doctors only)
app.post('/api/consultations/create', authenticateToken, authorizeRole('Doctor', 'Admin'), async (req, res) => {
  try {
    const { patientName, patientEmail, patientRecordId, expiresInHours = 24 } = req.body;

    if (!patientName) {
      return res.status(400).json({ error: 'Patient name is required' });
    }

    const sessionId = uuidv4();
    const sessionToken = uuidv4();
    const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5173';
    const sessionLink = `${frontendUrl}/join/${sessionId}?token=${sessionToken}`;
    const expiresAt = new Date(Date.now() + expiresInHours * 60 * 60 * 1000);

   await query(
      `INSERT INTO consultation_sessions 
       (session_id, doctor_user_id, doctor_personnel_id, patient_record_id, patient_name, patient_email, session_link, session_token, expires_at, status)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, DATE_ADD(NOW(), INTERVAL ? HOUR), 'pending')`,
      [sessionId, req.user.userId, req.user.medicalPersonnelId || null, patientRecordId || null, patientName, patientEmail || null, sessionLink, sessionToken, expiresInHours]
    );

    // Audit log
    await query(
      `INSERT INTO consultation_audit_log (session_id, event_type, user_type, user_id, event_details)
       VALUES (?, 'created', 'doctor', ?, ?)`,
      [sessionId, req.user.userId, JSON.stringify({ patientName, patientEmail, expiresInHours })]
    );

    const [created] = await query(`SELECT expires_at FROM consultation_sessions WHERE session_id = ?`, [sessionId]);

    res.status(201).json({
      success: true,
      sessionId,
      sessionLink,
      sessionToken,
      expiresAt: created.expires_at
    });
  } catch (error) {
    console.error('Session creation error:', error);
    res.status(500).json({ error: 'Failed to create session', details: error.message });
  }
});

// Get all sessions for the logged-in doctor
app.get('/api/consultations', authenticateToken, async (req, res) => {
  try {
    const results = await query(
      `SELECT cs.*, 
              mp.Fname as DoctorFname, mp.Lname as DoctorLname,
              p.Fname as PatientFname, p.Lname as PatientLname
       FROM consultation_sessions cs
       LEFT JOIN MedicalPersonnel mp ON cs.doctor_personnel_id = mp.MedicalPersonnelId
       LEFT JOIN Patient p ON cs.patient_record_id = p.patientId
       WHERE cs.doctor_user_id = ?
       ORDER BY cs.created_at DESC
       LIMIT 50`,
      [req.user.userId]
    );
    res.json(results);
  } catch (error) {
    console.error('Error fetching sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Get all sessions (Admin view)
app.get('/api/consultations/all', authenticateToken, authorizeRole('Admin'), async (req, res) => {
  try {
    const results = await query(
      `SELECT cs.*, 
              mp.Fname as DoctorFname, mp.Lname as DoctorLname
       FROM consultation_sessions cs
       LEFT JOIN MedicalPersonnel mp ON cs.doctor_personnel_id = mp.MedicalPersonnelId
       ORDER BY cs.created_at DESC
       LIMIT 100`
    );
    res.json(results);
  } catch (error) {
    console.error('Error fetching all sessions:', error);
    res.status(500).json({ error: 'Failed to fetch sessions' });
  }
});

// Validate a session (PUBLIC - used by patient join page, no auth)
app.get('/api/consultations/join/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { token: sessionToken } = req.query;

    if (!sessionToken) {
      return res.status(400).json({ error: 'Session token required' });
    }

    const results = await query(
      `SELECT cs.session_id, cs.patient_name, cs.status, cs.expires_at,
              mp.Fname as DoctorFname, mp.Lname as DoctorLname, mp.Specialty
       FROM consultation_sessions cs
       LEFT JOIN MedicalPersonnel mp ON cs.doctor_personnel_id = mp.MedicalPersonnelId
       WHERE cs.session_id = ? AND cs.session_token = ?`,
      [sessionId, sessionToken]
    );

    if (results.length === 0) {
      return res.status(404).json({ error: 'Session not found or invalid token' });
    }

    const session = results[0];

   const [{ expired }] = await query(`SELECT NOW() > ? AS expired`, [session.expires_at]);
    if (expired) {
      await query(`UPDATE consultation_sessions SET status = 'expired' WHERE session_id = ?`, [sessionId]);
      return res.status(410).json({ error: 'Session has expired' });
    }

    if (session.status === 'completed' || session.status === 'cancelled') {
      return res.status(410).json({ error: `Session is ${session.status}` });
    }

    res.json({
      valid: true,
      sessionId: session.session_id,
      patientName: session.patient_name,
      doctorName: `Dr. ${session.DoctorFname} ${session.DoctorLname}`,
      specialty: session.Specialty,
      status: session.status
    });
  } catch (error) {
    console.error('Session validation error:', error);
    res.status(500).json({ error: 'Failed to validate session' });
  }
});

// End a consultation session
app.patch('/api/consultations/:sessionId/end', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { notes } = req.body;

    const result = await query(
      `UPDATE consultation_sessions 
       SET status = 'completed', ended_at = NOW(), notes = ?,
           duration_seconds = TIMESTAMPDIFF(SECOND, started_at, NOW())
       WHERE session_id = ? AND doctor_user_id = ?`,
      [notes || null, sessionId, req.user.userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    await query(
      `INSERT INTO consultation_audit_log (session_id, event_type, user_type, user_id, event_details)
       VALUES (?, 'ended', 'doctor', ?, ?)`,
      [sessionId, req.user.userId, JSON.stringify({ notes })]
    );

    res.json({ success: true, message: 'Session ended' });
  } catch (error) {
    console.error('Error ending session:', error);
    res.status(500).json({ error: 'Failed to end session' });
  }
});

// Cancel a session
app.patch('/api/consultations/:sessionId/cancel', authenticateToken, async (req, res) => {
  try {
    const { sessionId } = req.params;

    const result = await query(
      `UPDATE consultation_sessions SET status = 'cancelled' WHERE session_id = ? AND doctor_user_id = ?`,
      [sessionId, req.user.userId]
    );

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Session not found' });
    }

    res.json({ success: true, message: 'Session cancelled' });
  } catch (error) {
    console.error('Error cancelling session:', error);
    res.status(500).json({ error: 'Failed to cancel session' });
  }
});

// ==================== WEBRTC SIGNALING (Socket.io) ====================

if (io) {
  const activeSessions = new Map();

  io.on('connection', (socket) => {
    console.log('WebRTC client connected:', socket.id);

    socket.on('join-session', ({ sessionId, userType, userName }) => {
      socket.join(sessionId);
      socket.sessionId = sessionId;
      socket.userType = userType;
      socket.userName = userName;

      if (!activeSessions.has(sessionId)) {
        activeSessions.set(sessionId, new Set());
      }
      activeSessions.get(sessionId).add({ id: socket.id, userType, userName });

      socket.to(sessionId).emit('peer-joined', { userType, userName, socketId: socket.id });
      console.log(`${userType} "${userName}" joined session ${sessionId}`);

      if (userType === 'doctor') {
        query(`UPDATE consultation_sessions SET status = 'active', started_at = IFNULL(started_at, NOW()) WHERE session_id = ?`, [sessionId])
          .catch(err => console.error('Error updating session status:', err));
      }

      query(
        `INSERT INTO consultation_audit_log (session_id, event_type, user_type, event_details) VALUES (?, 'joined', ?, ?)`,
        [sessionId, userType, JSON.stringify({ userName, socketId: socket.id })]
      ).catch(err => console.error('Audit log error:', err));
    });

    socket.on('offer', ({ sessionId, offer }) => {
      socket.to(sessionId).emit('offer', { offer });
    });

    socket.on('answer', ({ sessionId, answer }) => {
      socket.to(sessionId).emit('answer', { answer });
    });

    socket.on('ice-candidate', ({ sessionId, candidate }) => {
      socket.to(sessionId).emit('ice-candidate', { candidate });
    });

    socket.on('disconnect', () => {
      console.log('WebRTC client disconnected:', socket.id);

      if (socket.sessionId && activeSessions.has(socket.sessionId)) {
        const participants = activeSessions.get(socket.sessionId);
        for (const p of participants) {
          if (p.id === socket.id) {
            participants.delete(p);
            break;
          }
        }

        socket.to(socket.sessionId).emit('peer-left', { 
          userType: socket.userType, 
          userName: socket.userName 
        });

        if (participants.size === 0) {
          activeSessions.delete(socket.sessionId);
        }
      }

      if (socket.sessionId) {
        query(
          `INSERT INTO consultation_audit_log (session_id, event_type, user_type, event_details) VALUES (?, 'left', ?, ?)`,
          [socket.sessionId, socket.userType || 'unknown', JSON.stringify({ socketId: socket.id })]
        ).catch(err => console.error('Audit log error:', err));
      }
    });
  });
}

// ==================== START SERVER ====================

server.listen(PORT, () => {
  console.log(`\n  HealthHub + ConsultLink Server v3.0`);
  console.log(`  ------------------------------------`);
  console.log(`  Server:    http://localhost:${PORT}`);
  console.log(`  Auth:      Enabled (JWT)`);
  console.log(`  WebRTC:    ${io ? 'Enabled (Socket.io)' : 'Disabled (install socket.io)'}`);
  console.log(`  Database:  healthhub`);
  console.log(`  Demo:      doc01/password123, nurse01/password123`);
  console.log(`  ------------------------------------\n`);
});