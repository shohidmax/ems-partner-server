
const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const os = require('os');
const archiver = require('archiver');
const { randomUUID } = require('crypto');
const http = require('http');
const { Server } = require('socket.io');
const { MongoClient, ObjectId } = require('mongodb');
const helmet = require('helmet');
const compression = require('compression');
const nodemailer = require('nodemailer');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit'); 
require('dotenv').config();

// --- গ্লোবাল ভেরিয়েবল ---
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const BATCH_INTERVAL_MS = 10000; // ১০ সেকেন্ড পর পর ব্যাচ সেভ হবে
const FILTER_INTERVAL_MS = 10 * 60 * 1000;
const OFFLINE_THRESHOLD_MS = 10 * 60 * 1000;
const CHECK_OFFLINE_INTERVAL_MS = 1 * 60 * 1000;

let espDataBuffer = []; 
const backupJobs = new Map();

// --- অ্যাপ এবং সার্ভার সেটআপ ---
const app = express();

// [গুরুত্বপূর্ণ] প্রক্সি এরর ফিক্স (Render/Heroku/Nginx এর জন্য)
app.set('trust proxy', 1); 

const port = process.env.PORT || 3002;
const http_server = http.createServer(app);
const io = new Server(http_server, {
  cors: { origin: "*", methods: ["GET", "POST"] }
});

// --- ১. সিকিউরিটি: রেট লিমিটার ---
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 120, // প্রতি মিনিটে ১২০টি রিকোয়েস্ট পর্যন্ত এলাউড
  message: { success: false, message: 'Too many requests, slow down.' },
  standardHeaders: true,
  legacyHeaders: false,
});

// --- Nodemailer Transport ---
let mailTransporter;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  mailTransporter = nodemailer.createTransport({
    host: process.env.EMAIL_HOST || 'smtp.gmail.com',
    port: parseInt(process.env.EMAIL_PORT || '587', 10),
    secure: process.env.EMAIL_SECURE === 'true',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });
} 

// --- Middleware ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) return res.status(401).send({ success: false, message: 'Authorization header missing' });
  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).send({ success: false, message: 'Invalid format' });
  try {
    const payload = jwt.verify(parts[1], JWT_SECRET);
    req.user = payload; 
    return next();
  } catch (err) {
    return res.status(401).send({ success: false, message: 'Invalid or expired token' });
  }
}

app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// IoT রুটে রেট লিমিটার
app.use('/api/esp32p', apiLimiter); 
app.use('/api/esp32pp', apiLimiter);

// --- MongoDB কানেকশন ---
const uri = process.env.MONGODB_URI;
if (!uri) throw new Error('MONGODB_URI missing in .env');
const client = new MongoClient(uri);

// --- হেল্পার ফাংশন ---

/**
 * [গুরুত্বপূর্ণ] ডাটা বাফার ফ্লাশ এবং নতুন ফরম্যাট হ্যান্ডলিং
 */
async function flushDataBuffer(collection, devicesCollection) {
  if (espDataBuffer.length === 0) return;

  const dataToInsert = [...espDataBuffer];
  espDataBuffer = []; 

  try {
    await collection.insertMany(dataToInsert, { ordered: false });
    
    // রিয়েল-টাইম আপডেটের জন্য সকেটে পাঠানো
    io.emit('new-data', dataToInsert);

    // ডিভাইস স্ট্যাটাস আপডেট (Last Seen & Latest Data Snapshot)
    const lastSeenUpdates = new Map();
    for (const data of dataToInsert) {
      if (data.uid) {
        const newTime = data.timestamp || new Date(); 
        const existing = lastSeenUpdates.get(data.uid);
        
        if (!existing || newTime >= existing.time) {
          lastSeenUpdates.set(data.uid, { 
            time: newTime, 
            data: { 
               // নতুন নেস্টেড ডাটা স্ট্রাকচার সেভ করা হচ্ছে
               pssensor: data.pssensor || {},
               environment: data.environment || {},
               rain: data.rain || {},
               // ফ্লাট ভ্যালু (লিগ্যাসি সাপোর্টের জন্য)
               temperature: (data.environment?.temp !== undefined) ? data.environment.temp : data.temperature,
               water_level: (data.pssensor?.depth_ft !== undefined) ? data.pssensor.depth_ft : data.water_level,
               rainfall: (data.rain?.mm !== undefined) ? data.rain.mm : data.rainfall
            } 
          });
        }
      }
    }

    if (lastSeenUpdates.size > 0) {
      const bulkOps = [];
      const updatedDeviceUIDs = [];

      lastSeenUpdates.forEach((update, uid) => {
        updatedDeviceUIDs.push(uid);
        bulkOps.push({
          updateOne: {
            filter: { uid: uid },
            update: {
              $set: {
                lastSeen: update.time,
                status: 'online',
                data: update.data // ডিভাইসের লেটেস্ট সেন্সর ভ্যালু আপডেট
              },
              $setOnInsert: {
                uid: uid,
                addedAt: new Date(),
                location: null,
                name: null,
                division: null,
                latitude: null,
                longitude: null
              }
            },
            upsert: true
          }
        });
      });

      await devicesCollection.bulkWrite(bulkOps, { ordered: false });
      io.emit('device-status-updated', updatedDeviceUIDs);
    }

  } catch (error) {
    espDataBuffer = [...dataToInsert, ...espDataBuffer];
  }
}

async function syncAllDevices(EspCollection, devicesCollection) {
  try {
    const uids = await EspCollection.distinct('uid');
    if (!uids || uids.length === 0) return;
    const bulkOps = uids.map(uid => ({
      updateOne: {
        filter: { uid: uid },
        update: { 
          $setOnInsert: { uid: uid, addedAt: new Date(), status: 'unknown', data: {} } 
        },
        upsert: true
      }
    }));
    if (bulkOps.length > 0) await devicesCollection.bulkWrite(bulkOps, { ordered: false });
  } catch (error) { console.error('[Sync] Error:', error.message); }
}

async function checkOfflineDevices(devicesCollection) {
  try {
    const thresholdTime = new Date(Date.now() - OFFLINE_THRESHOLD_MS);
    const devicesToUpdate = await devicesCollection.find(
      { status: 'online', lastSeen: { $lt: thresholdTime } },
      { projection: { uid: 1 } }
    ).toArray();

    if (devicesToUpdate.length === 0) return;
    const uidsToUpdate = devicesToUpdate.map(d => d.uid);
    
    await devicesCollection.updateMany(
      { uid: { $in: uidsToUpdate } },
      { $set: { status: 'offline' } }
    );
    io.emit('device-status-updated', uidsToUpdate);
  } catch (error) { console.error('[Offline] Error:', error.message); }
}

function cleanupOldBackupJobs() {
  const NOW = Date.now();
  const MAX_AGE_MS = 60 * 60 * 1000;
  backupJobs.forEach((job, jobId) => {
    const jobTime = job.finishedAt ? job.finishedAt.getTime() : 0;
    if ((job.status === 'done' || job.status === 'error') && (NOW - jobTime > MAX_AGE_MS)) {
        if (job.tmpDir) {
          try { fs.rmSync(job.tmpDir, { recursive: true, force: true }); } catch(e){}
        }
        backupJobs.delete(jobId);
    }
  });
}

// --- মেইন রান ফাংশন ---
async function run() {
  try {
    await client.connect();
    console.log('DB connected');

    const db = client.db('Esp32data');
    const EspCollection = db.collection('espdata2'); 
    const devicesCollection = db.collection('devices');
    const usersCollection = db.collection('users');

    // ইনডেক্সিং (দ্রুত ফিল্টারিংয়ের জন্য)
    try {
        await EspCollection.createIndex({ uid: 1, timestamp: -1 }); 
        await devicesCollection.createIndex({ uid: 1 }, { unique: true });
        await usersCollection.createIndex({ email: 1 }, { unique: true });
    } catch (idxErr) { console.warn('Index warning:', idxErr.message); }

    // টাইমার
    setInterval(() => flushDataBuffer(EspCollection, devicesCollection), BATCH_INTERVAL_MS);
    setInterval(() => syncAllDevices(EspCollection, devicesCollection), FILTER_INTERVAL_MS);
    setInterval(() => checkOfflineDevices(devicesCollection), CHECK_OFFLINE_INTERVAL_MS);
    setInterval(cleanupOldBackupJobs, 15 * 60 * 1000);

    syncAllDevices(EspCollection, devicesCollection);

    // অ্যাডমিন চেক হেল্পার
    async function ensureAdmin(req, res) {
      const userId = req.user && req.user.userId;
      if (!userId) return res.status(401).send({ success: false, message: 'Unauthorized' });
      const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
      const isAdminEnv = process.env.ADMIN_EMAIL && user && user.email === process.env.ADMIN_EMAIL;
      if (user && (user.isAdmin === true || isAdminEnv)) return { ok: true, user };
      return res.status(403).send({ success: false, message: 'Admin access required' });
    }

    // -------------------------
    // --- Routes (API) ---
    // -------------------------

    // 1. Data Ingestion (ESP32)
    app.post('/api/esp32p', async (req, res) => {
      try {
        const data = req.body;
        // রিসিভ টাইম (Bangladesh Time)
        const bdTime = new Date(Date.now() + (6 * 60 * 60 * 1000));
        data.receivedAt = bdTime;

        // টাইমস্ট্যাম্প লজিক: যদি ডিভাইস টাইম পাঠায়, সেট ব্যবহার হবে, না হলে সার্ভার টাইম
        if (data.timestamp && typeof data.timestamp === 'string') {
           // ISO ফরম্যাটে কনভার্ট করার চেষ্টা
           const isoString = data.timestamp.replace(' ', 'T') + "+06:00"; 
           const d = new Date(isoString);
           data.timestamp = isNaN(d.getTime()) ? bdTime : d;
        } else {
           data.timestamp = bdTime;
        }

        espDataBuffer.push(data);
        res.status(200).send({ message: 'Queued.' });
      } catch (error) {
        res.status(400).send({ message: 'Invalid Data' });
      }
    });

    app.post('/api/esp32pp', async (req, res) => { // UTC Version
        try {
          const data = req.body;
          data.timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
          data.receivedAt = new Date();
          espDataBuffer.push(data);
          res.status(200).send({ message: 'Queued.' });
        } catch (error) { res.status(400).send({ message: 'Invalid Data' }); }
    });

    // 2. Data Retrieval (Latest N)
    app.get('/api/device/data', async (req, res) => {
      try {
        const { uid, limit } = req.query;
        const lim = Math.min(1000, Math.max(1, parseInt(limit, 10) || 300));
        const q = uid ? { uid: String(uid) } : {};

        const docs = await EspCollection.find(q)
          .sort({ timestamp: -1 })
          .limit(lim)
          .project({ uid: 1, pssensor: 1, environment: 1, rain: 1, timestamp: 1, dateTime: 1, temperature: 1, water_level: 1, rainfall: 1, _id: 0 }) 
          .toArray();

        return res.send(docs);
      } catch (error) {
        return res.status(500).send({ success: false, message: 'Server error' });
      }
    });

    // 3. Data Retrieval (Date Range Filter)
    app.post('/api/device/data-by-range', async (req, res) => {
        try {
          const { uid, start, end, limit } = req.body || {};
          if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });
  
          const startDate = start ? new Date(start) : new Date(0);
          const endDate = end ? new Date(end) : new Date();
          const lim = Math.min(20000, Math.max(1, parseInt(limit, 10) || 10000));
  
          const docs = await EspCollection.find({ uid: String(uid), timestamp: { $gte: startDate, $lte: endDate } })
            .sort({ timestamp: 1 })
            .limit(lim)
            .project({ uid: 1, pssensor: 1, environment: 1, rain: 1, timestamp: 1, dateTime: 1, temperature: 1, water_level: 1, rainfall: 1, _id: 0 })
            .toArray();
  
          return res.send(docs);
        } catch (error) {
          return res.status(500).send({ success: false, message: 'Server error' });
        }
    });

    // 4. Device Management (Admin/User)
    app.put('/api/device/:uid', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        const { uid } = req.params;
        const { location, name, division, latitude, longitude } = req.body; 

        const updateFields = {};
        if (location !== undefined) updateFields.location = location;
        if (name !== undefined) updateFields.name = name;
        if (division !== undefined) updateFields.division = division;
        if (latitude !== undefined) updateFields.latitude = latitude;
        if (longitude !== undefined) updateFields.longitude = longitude;

        if (Object.keys(updateFields).length === 0) return res.status(400).send({ message: 'No fields' });

        const result = await devicesCollection.updateOne({ uid }, { $set: updateFields });
        res.send({ success: true, message: result.matchedCount ? 'Updated' : 'Not found' });
    });

    app.get('/api/user/devices', authenticateJWT, async (req, res) => {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
        if (!user || !user.devices) return res.send([]);
        
        const devices = await devicesCollection.find({ uid: { $in: user.devices } }).toArray();
        const result = user.devices.map(uid => {
            const d = devices.find(x => x.uid === uid);
            return {
                uid,
                name: d?.name,
                location: d?.location,
                division: d?.division,
                status: d?.status || 'offline',
                lastSeen: d?.lastSeen,
                data: d?.data || {} 
            };
        });
        res.send(result);
    });

    app.post('/api/user/device/add', authenticateJWT, async (req, res) => {
        const { uid } = req.body;
        if (!uid) return res.status(400).send({ message: 'UID needed' });
        await usersCollection.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $addToSet: { devices: String(uid).trim() } }
        );
        res.send({ success: true, message: 'Device Added' });
    });

    // 5. User & Admin Management
    app.post('/api/user/register', async (req, res) => {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).send({ message: 'Missing fields' });
        try {
            const exists = await usersCollection.findOne({ email: email.toLowerCase() });
            if (exists) return res.status(400).send({ message: 'Email taken' });
            await usersCollection.insertOne({
                name, email: email.toLowerCase(), 
                passwordHash: await bcrypt.hash(password, 10), 
                devices: [], createdAt: new Date()
            });
            res.send({ success: true, message: 'Registered' });
        } catch (e) { res.status(500).send({ message: 'Error' }); }
    });

    app.post('/api/user/login', async (req, res) => {
        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email: String(email).toLowerCase() });
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).send({ message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.send({ success: true, token });
    });

    app.get('/api/user/profile', authenticateJWT, async (req, res) => {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) }, { projection: { passwordHash: 0 } });
        if(!user) return res.status(404).send('Not found');
        const isAdminEnv = process.env.ADMIN_EMAIL && user.email === process.env.ADMIN_EMAIL;
        user.isAdmin = (user.isAdmin === true || isAdminEnv);
        res.send(user);
    });

    app.post('/api/user/profile/update', authenticateJWT, async (req, res) => {
        try {
            const { name, address, mobile } = req.body;
            const updateFields = {};
            if (name) updateFields.name = name;
            if (address) updateFields.address = address;
            if (mobile) updateFields.mobile = mobile;
    
            if (Object.keys(updateFields).length === 0) {
                return res.status(400).send({ message: "No fields to update." });
            }
            
            await usersCollection.updateOne({ _id: new ObjectId(req.user.userId) }, { $set: updateFields });
            res.send({ success: true, message: "Profile updated." });
        } catch (e) {
            res.status(500).send({ error: e.message });
        }
    });

    app.post('/api/user/password/change', authenticateJWT, async (req, res) => {
        try {
            const { oldPassword, newPassword } = req.body;
            if (!oldPassword || !newPassword) return res.status(400).send({ message: "Old and new passwords are required." });
    
            const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
            if (!user) return res.status(404).send({ message: "User not found." });
    
            const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
            if (!isMatch) return res.status(401).send({ message: "Invalid old password." });
            
            const newPasswordHash = await bcrypt.hash(newPassword, 10);
            await usersCollection.updateOne({ _id: user._id }, { $set: { passwordHash: newPasswordHash } });
    
            res.send({ success: true, message: 'Password changed successfully.' });
        } catch (e) {
            res.status(500).send({ error: e.message });
        }
    });

    // Admin: List Users
    app.get('/api/admin/users', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        const users = await usersCollection.find({}, { projection: { passwordHash: 0 } }).toArray();
        res.send(users);
    });

    // Admin: List all devices with owners
    app.get('/api/admin/devices', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        try {
            const devices = await devicesCollection.find({}).toArray();
            const allDeviceUIDs = devices.map(d => d.uid);
    
            const users = await usersCollection.find(
                { devices: { $in: allDeviceUIDs } },
                { projection: { _id: 1, name: 1, email: 1, devices: 1 } }
            ).toArray();
    
            const userMap = new Map();
            users.forEach(user => {
                user.devices.forEach(uid => {
                    if (!userMap.has(uid)) userMap.set(uid, []);
                    userMap.get(uid).push({ _id: user._id, name: user.name, email: user.email });
                });
            });
    
            const result = devices.map(device => ({
                ...device,
                owners: userMap.get(device.uid) || []
            }));
    
            res.send(result);
        } catch (error) {
            res.status(500).send({ success: false, message: 'Internal server error' });
        }
    });

    // Admin: Stats
    app.get('/api/admin/stats', authenticateJWT, async (req, res) => {
      const check = await ensureAdmin(req, res);
      if (!check?.ok) return;
      try {
        const stats = {
            totalDevices: await devicesCollection.countDocuments(),
            onlineDevices: await devicesCollection.countDocuments({ status: 'online' }),
            totalUsers: await usersCollection.countDocuments()
        };
        res.send(stats);
      } catch(e) {
        res.status(500).send({ message: 'Error fetching stats'});
      }
    });

    // Admin: Reports
    app.get('/api/admin/report', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        const { period = 'monthly', year = new Date().getFullYear().toString() } = req.query;
        let group, sort;
        const matchYear = parseInt(year, 10);

        switch (period) {
            case 'daily':
                group = {
                    _id: { $dateToString: { format: '%Y-%m-%d', date: '$timestamp', timeZone: 'Asia/Dhaka' } },
                    avgTemp: { $avg: '$environment.temp' },
                    avgRain: { $sum: '$rain.mm' },
                    count: { $sum: 1 }
                };
                sort = { '_id': 1 };
                break;
            case 'yearly':
                group = {
                    _id: { $year: { date: '$timestamp', timeZone: 'Asia/Dhaka' } },
                    avgTemp: { $avg: '$environment.temp' },
                    avgRain: { $sum: '$rain.mm' },
                    count: { $sum: 1 }
                };
                sort = { '_id': 1 };
                break;
            case 'monthly':
            default:
                group = {
                    _id: { $dateToString: { format: '%Y-%m', date: '$timestamp', timeZone: 'Asia/Dhaka' } },
                    avgTemp: { $avg: '$environment.temp' },
                    avgRain: { $sum: '$rain.mm' },
                    count: { $sum: 1 }
                };
                sort = { '_id': 1 };
        }

        try {
            const data = await EspCollection.aggregate([
                { $match: { 
                    timestamp: { 
                        $gte: new Date(matchYear, 0, 1), 
                        $lt: new Date(matchYear + 1, 0, 1)
                    },
                    'environment.temp': { $ne: 85 } // Ignore error value
                } },
                { $group: group },
                { $sort: sort },
                { $project: {
                    _id: 0,
                    date: period === 'daily' ? '$_id' : undefined,
                    month: period === 'monthly' ? '$_id' : undefined,
                    year: period === 'yearly' ? '$_id' : undefined,
                    avgTemp: 1,
                    avgRain: 1,
                    count: 1
                }}
            ]).toArray();
            res.json(data);
        } catch (e) {
            res.status(500).send({ error: e.message });
        }
    });

    // Admin: Promote/Demote
    app.post('/api/admin/user/make-admin', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        await usersCollection.updateOne({ email: req.body.email }, { $set: { isAdmin: true } });
        res.send({ success: true, message: 'User promoted to Admin' });
    });

    app.post('/api/admin/user/remove-admin', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        if (req.body.email === process.env.ADMIN_EMAIL) return res.status(403).send({ message: 'Cannot remove super admin' });
        await usersCollection.updateOne({ email: req.body.email }, { $set: { isAdmin: false } });
        res.send({ success: true, message: 'Admin privileges removed' });
    });

    // Admin: Forgot Password Logic
    app.post('/api/user/password/forgot', async (req, res) => {
        if (!mailTransporter) return res.status(500).send({ message: 'Email not configured' });
        const user = await usersCollection.findOne({ email: req.body.email.toLowerCase() });
        if (user) {
            const newPass = crypto.randomBytes(6).toString('hex');
            await usersCollection.updateOne({ _id: user._id }, { $set: { passwordHash: await bcrypt.hash(newPass, 10) } });
            mailTransporter.sendMail({
                to: user.email,
                subject: 'Password Reset',
                text: `New Password: ${newPass}`
            }).catch(console.error);
        }
        res.send({ success: true, message: 'If email exists, pass sent.' });
    });

    // 6. Backup System (Same as before)
    app.post('/api/backup/start', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        const { uid } = req.body;
        const q = uid ? { uid: String(uid) } : {};
        const jobId = randomUUID();
        const tmpDir = path.join(os.tmpdir(), `esp-backup-${jobId}`);
        fs.mkdirSync(tmpDir, { recursive: true });
        
        const job = { status: 'pending', progress: 0, tmpDir, zipPath: path.join(tmpDir, 'espdata.zip') };
        backupJobs.set(jobId, job);

        res.send({ jobId });

        (async () => {
            try {
                job.status = 'exporting';
                const total = await EspCollection.countDocuments(q);
                const out = fs.createWriteStream(path.join(tmpDir, 'espdata.json'), { encoding: 'utf8' });
                out.write('[');
                let first = true, written = 0;
                for await (const doc of EspCollection.find(q).sort({ timestamp: 1 })) {
                    if (!first) out.write(',');
                    // Clean Output
                    const clean = { 
                        uid: doc.uid, timestamp: doc.timestamp, dateTime: doc.dateTime,
                        pssensor: doc.pssensor, environment: doc.environment, rain: doc.rain
                    };
                    out.write(JSON.stringify(clean));
                    first = false; written++;
                    if (total > 0) job.progress = Math.floor((written / total) * 90);
                }
                out.write(']'); out.end();
                await new Promise(r => out.on('finish', r));

                job.status = 'zipping';
                const output = fs.createWriteStream(job.zipPath);
                const archive = archiver('zip', { zlib: { level: 9 } });
                archive.pipe(output);
                archive.file(path.join(tmpDir, 'espdata.json'), { name: 'espdata.json' });
                await archive.finalize();
                await new Promise(r => output.on('close', r));

                job.status = 'done'; job.progress = 100; job.finishedAt = new Date();
                 const downloadPath = `/api/backup/download/${jobId}`;
                 job.downloadUrl = downloadPath; 

            } catch (err) { job.status = 'error'; job.error = err.message; job.finishedAt = new Date(); }
        })();
    });

    app.get('/api/backup/status/:jobId', authenticateJWT, (req, res) => {
        const job = backupJobs.get(req.params.jobId);
        if(!job) return res.status(404).send({message: 'Not found'});
        
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');

        const sendEvent = (data) => res.write(`data: ${JSON.stringify(data)}\n\n`);

        sendEvent({ status: job.status, progress: job.progress, error: job.error });

        if (job.status === 'done' || job.status === 'error') {
            if (job.status === 'done') {
                sendEvent({ status: 'done', progress: 100, download: job.downloadUrl });
            }
            return res.end();
        }

        const iv = setInterval(() => {
            const currentJob = backupJobs.get(req.params.jobId);
            if (!currentJob) {
                clearInterval(iv);
                return res.end();
            }
            
            sendEvent({ status: currentJob.status, progress: currentJob.progress, error: currentJob.error });
            
            if (currentJob.status === 'done' || currentJob.status === 'error') {
                 if (currentJob.status === 'done') {
                    sendEvent({ status: 'done', progress: 100, download: currentJob.downloadUrl });
                }
                clearInterval(iv);
                res.end();
            }
        }, 1000);

        req.on('close', () => clearInterval(iv));
    });

    app.get('/api/backup/download/:jobId', authenticateJWT, (req, res) => {
        const check = ensureAdmin(req, res);
        if(!check) return;

        const job = backupJobs.get(req.params.jobId);
        if (!job || job.status !== 'done') return res.status(400).send('Not ready or invalid job ID');
        res.download(job.zipPath, 'espdata.zip');
    });

  } catch (err) { console.error('Startup Error:', err); }
}

run().catch(console.dir);

app.get("/", (req, res) => res.send(`<h1 style="text-align: center; color: green;">Max it Server (v2.0) Running at ${port}</h1>`));

http_server.listen(port, () => {
  console.log(`Max it Production server running at: ${port}`);
});


    