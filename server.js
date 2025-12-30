const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const jwt = require('jsonwebtoken');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors());
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

// Test database connection
db.getConnection((err, connection) => {
  if (err) {
    console.error('❌ Database connection failed:', err);
    return;
  }
  console.log('✅ Connected to MySQL database');
  connection.release();
});

// ==================== AUTHENTICATION MIDDLEWARE ====================

// Verify JWT token
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1]; // Bearer TOKEN

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

// Check if user has required role
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
    version: '2.0.0',
    features: ['Authentication', 'CRUD Operations', 'Role-Based Access'],
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

  const query = `
    SELECT 
      u.userId, u.username, u.role, u.MedicalPersonnelId,
      mp.Fname, mp.Lname, mp.Specialty, mp.DoctorId
    FROM Users u
    LEFT JOIN MedicalPersonnel mp ON u.MedicalPersonnelId = mp.MedicalPersonnelId
    WHERE u.username = ? AND u.password = ? AND u.isActive = 1
  `;

  db.query(query, [username, password], (err, results) => {
    if (err) {
      console.error('Login error:', err);
      return res.status(500).json({ error: 'Login failed' });
    }

    if (results.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = results[0];

    // Update last login
    db.query('UPDATE Users SET lastLogin = NOW() WHERE userId = ?', [user.userId]);

    // Create JWT token
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
  const query = `
    SELECT 
      u.userId, u.username, u.role, u.MedicalPersonnelId,
      mp.Fname, mp.Lname, mp.Specialty, mp.DoctorId
    FROM Users u
    LEFT JOIN MedicalPersonnel mp ON u.MedicalPersonnelId = mp.MedicalPersonnelId
    WHERE u.userId = ?
  `;

  db.query(query, [req.user.userId], (err, results) => {
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

// ==================== DASHBOARD STATS (Protected) ====================

app.get('/api/stats', authenticateToken, (req, res) => {
  const queries = {
    totalPatients: 'SELECT COUNT(*) as count FROM Patient',
    activePatients: 'SELECT COUNT(*) as count FROM Patient WHERE Discharge = 0',
    totalDoctors: 'SELECT COUNT(*) as count FROM MedicalPersonnel WHERE DoctorId IS NOT NULL',
    totalNurses: 'SELECT COUNT(*) as count FROM MedicalPersonnel WHERE DoctorId IS NULL',
    totalPrescriptions: 'SELECT COUNT(*) as count FROM Prescriptions WHERE Status = "Active"'
  };

  const stats = {};
  let completed = 0;

  Object.entries(queries).forEach(([key, query]) => {
    db.query(query, (err, results) => {
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

// Get all patients (Protected)
app.get('/api/patients', authenticateToken, (req, res) => {
  const query = `
    SELECT p.*, mp.Fname as DoctorFname, mp.Lname as DoctorLname, mp.Specialty
    FROM Patient p
    LEFT JOIN MedicalPersonnel mp ON p.AssignedDoctorId = mp.MedicalPersonnelId
    ORDER BY p.patientId
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching patients:', err);
      return res.status(500).json({ error: 'Failed to fetch patients' });
    }
    res.json(results);
  });
});

// Get single patient (Protected)
app.get('/api/patients/:id', authenticateToken, (req, res) => {
  const query = `
    SELECT p.*, mp.Fname as DoctorFname, mp.Lname as DoctorLname, mp.Specialty
    FROM Patient p
    LEFT JOIN MedicalPersonnel mp ON p.AssignedDoctorId = mp.MedicalPersonnelId
    WHERE p.patientId = ?
  `;
  
  db.query(query, [req.params.id], (err, results) => {
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

// Add new patient (Nurse+)
app.post('/api/patients', authenticateToken, authorizeRole('Nurse', 'Doctor', 'Admin'), (req, res) => {
  const { 
    patientId, Fname, Lname, Birthdate, Phone, Address,
    ECname, ECcontact, Diet, MedicalHistory, Diagnosis 
  } = req.body;

  if (!patientId || !Fname || !Lname || !Birthdate) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  // STEP 1: Call stored procedure to get recommended doctor
  db.query('CALL AllocatePatientToDoctor(?, @assigned_doctor)', [patientId], (err) => {
    if (err) {
      console.error('Error allocating doctor:', err);
      return res.status(500).json({ error: 'Failed to allocate doctor' });
    }

    // STEP 2: Get the assigned doctor ID
    db.query('SELECT @assigned_doctor as doctorId', (err, result) => {
      if (err) {
        console.error('Error getting doctor ID:', err);
        return res.status(500).json({ error: 'Failed to get doctor assignment' });
      }

      const assignedDoctorId = result[0].doctorId;

      // STEP 3: Insert patient with assigned doctor
      const query = `
        INSERT INTO Patient 
        (patientId, Fname, Lname, Birthdate, Phone, Address, ECname, ECcontact, 
         Diet, \`Medical History\`, Diagnosis, Discharge, AdmissionDate, AssignedDoctorId)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, CURDATE(), ?)
      `;

      db.query(query, [
        patientId, Fname, Lname, Birthdate, Phone || null, Address || null,
        ECname || null, ECcontact || null, Diet || null, MedicalHistory || null,
        Diagnosis || null, assignedDoctorId
      ], (err, result) => {
        if (err) {
          console.error('Error adding patient:', err);
          if (err.code === 'ER_DUP_ENTRY') {
            return res.status(409).json({ error: 'Patient ID already exists' });
          }
          return res.status(500).json({ error: 'Failed to add patient' });
        }

        // Log action
        db.query(
  'INSERT INTO AuditLog (TableName, RecordId, Action, ChangedBy, NewValue, ChangedDate) VALUES (?, ?, ?, ?, ?, NOW())',
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
});

// Update patient (Doctor+)
app.put('/api/patients/:id', authenticateToken, authorizeRole('Doctor', 'Admin'), (req, res) => {
  const patientId = req.params.id;
  const updates = req.body;
  
  // Build dynamic update query
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

  const query = `UPDATE Patient SET ${updateFields.join(', ')} WHERE patientId = ?`;

  db.query(query, updateValues, (err, result) => {
    if (err) {
      console.error('Error updating patient:', err);
      return res.status(500).json({ error: 'Failed to update patient' });
    }

    if (result.affectedRows === 0) {
      return res.status(404).json({ error: 'Patient not found' });
    }

    // Log action
    // Log action
db.query(
  'INSERT INTO AuditLog (TableName, RecordId, Action, ChangedBy, NewValue, ChangedDate) VALUES (?, ?, ?, ?, ?, NOW())',
  ['Patient', patientId, 'UPDATE', req.user.username, `Patient updated by ${req.user.username}`]
);
    res.json({ message: 'Patient updated successfully' });
  });
});

// Discharge patient (Doctor only)
app.patch('/api/patients/:id/discharge', authenticateToken, authorizeRole('Doctor', 'Admin'), (req, res) => {
  const patientId = req.params.id;

  // Call the stored procedure
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

// ==================== REMAINING ENDPOINTS (Same as before, now protected) ====================

// Medical Personnel
app.get('/api/medical-personnel', authenticateToken, (req, res) => {
  const query = `
    SELECT mp.*, COUNT(DISTINCT p.patientId) as patient_count
    FROM MedicalPersonnel mp
    LEFT JOIN Patient p ON mp.MedicalPersonnelId = p.AssignedDoctorId
    GROUP BY mp.MedicalPersonnelId
    ORDER BY mp.Specialty, mp.Lname
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching medical personnel:', err);
      return res.status(500).json({ error: 'Failed to fetch medical personnel' });
    }
    res.json(results);
  });
});

// Doctors
app.get('/api/doctors', authenticateToken, (req, res) => {
  const query = `
    SELECT mp.*, COUNT(DISTINCT p.patientId) as patient_count
    FROM MedicalPersonnel mp
    LEFT JOIN Patient p ON mp.MedicalPersonnelId = p.AssignedDoctorId
    WHERE mp.DoctorId IS NOT NULL
    GROUP BY mp.MedicalPersonnelId
    ORDER BY mp.Lname
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching doctors:', err);
      return res.status(500).json({ error: 'Failed to fetch doctors' });
    }
    res.json(results);
  });
});

// Prescriptions
app.get('/api/prescriptions', authenticateToken, (req, res) => {
  const query = `
    SELECT pr.*, p.Fname as PatientFname, p.Lname as PatientLname,
           d.DrugsName, d.Dosage, d.Generics,
           mp.Fname as DoctorFname, mp.Lname as DoctorLname
    FROM Prescriptions pr
    JOIN Patient p ON pr.PatientID = p.patientId
    JOIN Drugs d ON pr.DrugID = d.DrugsId
    JOIN MedicalPersonnel mp ON pr.DoctorID = mp.MedicalPersonnelId
    ORDER BY pr.Date DESC
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching prescriptions:', err);
      return res.status(500).json({ error: 'Failed to fetch prescriptions' });
    }
    res.json(results);
  });
});

app.get('/api/prescriptions/refills-due', authenticateToken, (req, res) => {
  const query = `
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
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching refills:', err);
      return res.status(500).json({ error: 'Failed to fetch refills' });
    }
    res.json(results);
  });
});

// Tests
app.get('/api/tests', authenticateToken, (req, res) => {
  const query = 'SELECT * FROM Tests ORDER BY TestName';
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching tests:', err);
      return res.status(500).json({ error: 'Failed to fetch tests' });
    }
    res.json(results);
  });
});

app.get('/api/tests/scheduled', authenticateToken, (req, res) => {
  const query = `
    SELECT t.*, p.Fname as PatientFname, p.Lname as PatientLname,
           ts.TestName, ts.\`Testing Department\`
    FROM \`Tested for\` t
    JOIN Patient p ON t.Patient = p.patientId
    JOIN Tests ts ON t.TestId = ts.TestsId
    WHERE t.Status = 'Scheduled'
    ORDER BY t.Date
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching scheduled tests:', err);
      return res.status(500).json({ error: 'Failed to fetch scheduled tests' });
    }
    res.json(results);
  });
});

// Reports
app.get('/api/reports', authenticateToken, (req, res) => {
  const query = `
    SELECT w.*, p.Fname as PatientFname, p.Lname as PatientLname,
           mp.Fname as DoctorFname, mp.Lname as DoctorLname,
           r.reportType
    FROM Writes w
    JOIN Patient p ON w.Patient = p.patientId
    JOIN MedicalPersonnel mp ON w.MedicalPersonnel = mp.MedicalPersonnelId
    JOIN Report r ON w.Reportid = r.reportId
    ORDER BY w.Date DESC
  `;
  
  db.query(query, (err, results) => {
    if (err) {
      console.error('Error fetching reports:', err);
      return res.status(500).json({ error: 'Failed to fetch reports' });
    }
    res.json(results);
  });
});

// Search
app.get('/api/search/patients', authenticateToken, (req, res) => {
  const searchTerm = req.query.q || '';
  const query = `
    SELECT p.*, mp.Fname as DoctorFname, mp.Lname as DoctorLname
    FROM Patient p
    LEFT JOIN MedicalPersonnel mp ON p.AssignedDoctorId = mp.MedicalPersonnelId
    WHERE p.Fname LIKE ? OR p.Lname LIKE ? OR p.patientId LIKE ?
    ORDER BY p.Lname
    LIMIT 20
  `;
  
  const searchPattern = `%${searchTerm}%`;
  db.query(query, [searchPattern, searchPattern, searchPattern], (err, results) => {
    if (err) {
      console.error('Error searching patients:', err);
      return res.status(500).json({ error: 'Search failed' });
    }
    res.json(results);
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`📍 Local: http://localhost:${PORT}`);
  console.log(`🔐 Authentication: Enabled`);
  console.log(`👤 Demo accounts: doc01/password123, nurse01/password123`);
});
