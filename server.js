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
const rateLimit = require('express-rate-limit'); // নিরাপত্তা: রেট লিমিটিং যুক্ত করা হয়েছে
require('dotenv').config();

// --- গ্লোবাল ভেরিয়েবল ---
const JWT_SECRET = process.env.JWT_SECRET || 'please_change_this_secret';
const BATCH_INTERVAL_MS = 10000;
const FILTER_INTERVAL_MS = 10 * 60 * 1000;
const OFFLINE_THRESHOLD_MS = 10 * 60 * 1000;
const CHECK_OFFLINE_INTERVAL_MS = 1 * 60 * 1000;

let espDataBuffer = [];
const backupJobs = new Map();

// --- অ্যাপ এবং সার্ভার সেটআপ ---
const app = express();
const port = process.env.PORT || 3002;
const http_server = http.createServer(app);
const io = new Server(http_server, {
  cors: {
    origin: "*", // প্রয়োজনে নির্দিষ্ট ডোমেইন সেট করতে পারেন
    methods: ["GET", "POST"]
  }
});

// --- ১. সিকিউরিটি: রেট লিমিটার (অতিরিক্ত রিকোয়েস্ট বন্ধ করতে) ---
// প্রতি ১ মিনিটে একটি আইপি থেকে সর্বোচ্চ ৬০টি রিকোয়েস্ট
const apiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, 
  max: 60, 
  message: { success: false, message: 'Too many requests, please try again later.' },
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
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS,
    },
  });
  
  mailTransporter.verify((error, success) => {
    if (error) {
      console.warn('[Nodemailer Error] ইমেইল কনফিগারেশন সঠিক নয়:', error.message);
    } else {
      console.log('[Nodemailer Success] ইমেইল সার্ভার প্রস্তুত।');
    }
  });
} else {
  console.warn('[Nodemailer Info] EMAIL_USER বা EMAIL_PASS সেট করা নেই।');
}

// --- Middleware ---
function authenticateJWT(req, res, next) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (!authHeader) return res.status(401).send({ success: false, message: 'Authorization header missing' });

  const parts = authHeader.split(' ');
  if (parts.length !== 2 || parts[0] !== 'Bearer') return res.status(401).send({ success: false, message: 'Invalid authorization format' });

  const token = parts[1];
  try {
    const payload = jwt.verify(token, JWT_SECRET);
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

// IoT রুটে রেট লিমিটার প্রয়োগ
app.use('/api/esp32p', apiLimiter); 
app.use('/api/esp32pp', apiLimiter);

// --- MongoDB কানেকশন ---
const uri = process.env.MONGODB_URI;
if (!uri) throw new Error('MONGODB_URI is not defined in .env file');
const client = new MongoClient(uri);

// --- হেল্পার ফাংশন ---

/**
 * [গুরুত্বপূর্ণ ফিক্স] ডাটা বাফার ফ্লাশ
 * ডাটাবেস ফেইল করলে ডাটা হারাবে না, বাফারে ফেরত যাবে।
 */
async function flushDataBuffer(collection, devicesCollection) {
  if (espDataBuffer.length === 0) return;

  const dataToInsert = [...espDataBuffer];
  espDataBuffer = []; // বাফার খালি করা

  console.log(`[Batch Insert] Processing ${dataToInsert.length} documents...`);

  try {
    // ১. ডাটা ইনসার্ট
    await collection.insertMany(dataToInsert, { ordered: false });
    
    io.emit('new-data', dataToInsert);

    // ২. ডিভাইস স্ট্যাটাস আপডেট (Last Seen)
    const lastSeenUpdates = new Map();
    for (const data of dataToInsert) {
      if (data.uid) {
        // টাইমস্ট্যাম্প ঠিক করা
        const newTime = data.timestamp || data.receivedAt || new Date(); 
        const existing = lastSeenUpdates.get(data.uid);
        
        if (!existing || newTime >= existing.time) {
          lastSeenUpdates.set(data.uid, { 
            time: newTime, 
            data: { // লেটেস্ট সেন্সর ডাটা সংরক্ষণ
               pssensor: data.pssensor,
               environment: data.environment,
               rain: data.rain,
               // ব্যাকওয়ার্ড কম্প্যাটিবিলিটির জন্য আগের ফিল্ডগুলো রাখা হলো
               temperature: data.temperature || (data.environment && data.environment.temp),
               water_level: data.water_level,
               rainfall: data.rainfall
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
                data: update.data
              },
              $setOnInsert: {
                uid: uid,
                addedAt: new Date(),
                location: null,
                name: null,
                division: null
              }
            },
            upsert: true
          }
        });
      });

      await devicesCollection.bulkWrite(bulkOps, { ordered: false });
      io.emit('device-status-updated', updatedDeviceUIDs);
    }
    console.log(`[Batch Insert] Success.`);

  } catch (error) {
    console.error("[Batch Insert] Failed! Restoring data:", error.message);
    // [FIX] ফেইল করলে ডাটা বাফারে ফেরত পাঠানো হচ্ছে
    espDataBuffer = [...dataToInsert, ...espDataBuffer];
  }
}

async function syncAllDevices(EspCollection, devicesCollection) {
  try {
    // এই অপারেশনটি ভারী, তাই ইনডেক্স থাকা জরুরি
    const uids = await EspCollection.distinct('uid');
    if (!uids || uids.length === 0) return;

    const bulkOps = uids.map(uid => ({
      updateOne: {
        filter: { uid: uid },
        update: { 
          $setOnInsert: { 
            uid: uid, 
            addedAt: new Date(),
            status: 'unknown',
            lastSeen: null,
            data: {}
          } 
        },
        upsert: true
      }
    }));

    if (bulkOps.length > 0) {
      await devicesCollection.bulkWrite(bulkOps, { ordered: false });
    }
  } catch (error) {
    console.error('[Device Sync Job] Error:', error.message);
  }
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

    console.log(`[Offline Check] ${uidsToUpdate.length} devices marked offline.`);
    io.emit('device-status-updated', uidsToUpdate);
  } catch (error) {
    console.error('[Offline Check] Error:', error.message);
  }
}

function cleanupOldBackupJobs() {
  const NOW = Date.now();
  const MAX_AGE_MS = 60 * 60 * 1000;

  backupJobs.forEach((job, jobId) => {
    const jobTime = job.finishedAt ? job.finishedAt.getTime() : 0;
    if ((job.status === 'done' || job.status === 'error') && (NOW - jobTime > MAX_AGE_MS)) {
        if (job.tmpDir) {
          try {
            fs.rmSync(job.tmpDir, { recursive: true, force: true });
          } catch(e) {
            console.warn(`[Cleanup] Failed to delete ${job.tmpDir}`, e.message);
          }
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

    // --- [নতুন] পারফরম্যান্সের জন্য ইনডেক্স তৈরি ---
    try {
        await EspCollection.createIndex({ uid: 1, timestamp: -1 }); 
        await devicesCollection.createIndex({ uid: 1 }, { unique: true });
        await usersCollection.createIndex({ email: 1 }, { unique: true });
    } catch (idxErr) {
        console.warn('Index creation warning:', idxErr.message);
    }

    // টাইমার সেটআপ
    setInterval(() => flushDataBuffer(EspCollection, devicesCollection), BATCH_INTERVAL_MS);
    setInterval(() => syncAllDevices(EspCollection, devicesCollection), FILTER_INTERVAL_MS);
    setInterval(() => checkOfflineDevices(devicesCollection), CHECK_OFFLINE_INTERVAL_MS);
    setInterval(cleanupOldBackupJobs, 15 * 60 * 1000);

    console.log('Running initial device list sync job on startup...');
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
    // --- Routes ---
    // -------------------------

    // ESP32 Data (UTC)
    app.post('/api/esp32pp', async (req, res) => {
      try {
        const data = req.body;
        data.timestamp = data.timestamp ? new Date(data.timestamp) : new Date();
        data.receivedAt = new Date();
        espDataBuffer.push(data);
        res.status(200).send({ message: 'Data accepted and queued.' });
      } catch (error) {
        res.status(400).send({ message: 'Invalid data format' });
      }
    });

    // ESP32 Data (With BD Time Logic)
    app.post('/api/esp32p', async (req, res) => {
      try {
        const data = req.body;
        // বাংলাদেশ টাইম লজিক
        const bdTime = new Date(Date.now() + (6 * 60 * 60 * 1000));
        data.receivedAt = bdTime;

        if (data.timestamp && typeof data.timestamp === 'string') {
          const isoString = data.timestamp.replace(' ', 'T') + "+06:00";
          data.timestamp = new Date(isoString);
        } else {
          data.timestamp = bdTime;
        }

        espDataBuffer.push(data);
        res.status(200).send({ message: 'Data accepted and queued.' });
      } catch (error) {
        console.error("Error in /api/esp32p:", error.message);
        res.status(400).send({ message: 'Invalid data format' });
      }
    });

    // পাবলিক ডাটা রুট
    app.get('/api/esp32', async (req, res) => {
      const cursor = EspCollection.find({});
      const Data = await cursor.toArray();
      res.send(Data);
    });

    // GET /api/device/data
    app.get('/api/device/data', async (req, res) => {
      try {
        const { uid, limit } = req.query || {};
        const lim = Math.min(1000, Math.max(1, parseInt(limit, 10) || 300));
        const q = uid ? { uid: String(uid) } : {};

        const docs = await EspCollection.find(q)
          .sort({ timestamp: -1 })
          .limit(lim)
          .project({ uid: 1, pssensor: 1, environment: 1, rain: 1, timestamp: 1, _id: 0 }) // নতুন স্ট্রাকচার অনুযায়ী প্রজেকশন
          .toArray();

        return res.send(docs);
      } catch (error) {
        return res.status(500).send({ success: false, message: 'Internal server error' });
      }
    });

    // POST /api/device/data-by-range
    app.post('/api/device/data-by-range', async (req, res) => {
        try {
          const { uid, start, end, limit } = req.body || {};
          if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });
  
          function parseDate(s, fallback) {
            if (!s) return fallback;
            const normalized = String(s).trim().replace(' ', 'T');
            const d = new Date(normalized);
            return isNaN(d.getTime()) ? null : d;
          }
          
          const startDate = parseDate(start, new Date(0));
          const endDate = parseDate(end, new Date());
          if (!startDate || !endDate) return res.status(400).send({ success: false, message: 'Invalid dates' });
          
          const lim = Math.min(20000, Math.max(1, parseInt(limit, 10) || 10000));
  
          const docs = await EspCollection.find({ uid: String(uid), timestamp: { $gte: startDate, $lte: endDate } })
            .sort({ timestamp: 1 })
            .limit(lim)
            .project({ uid: 1, pssensor: 1, environment: 1, rain: 1, timestamp: 1, _id: 0 })
            .toArray();
  
          return res.send(docs);
        } catch (error) {
          return res.status(500).send({ success: false, message: 'Internal server error' });
        }
    });

    // --- ব্যাকআপ রুটস ---
    app.post('/api/backup/start', async (req, res) => {
        const { uid } = req.body || {};
        const q = uid ? { uid: String(uid) } : {};
        const jobId = randomUUID();
        const tmpDir = path.join(os.tmpdir(), `esp-backup-${jobId}`);
        fs.mkdirSync(tmpDir, { recursive: true });
        
        const jsonPath = path.join(tmpDir, 'espdata.json');
        const zipPath = path.join(tmpDir, 'espdata.zip');
        const job = { status: 'pending', progress: 0, tmpDir, jsonPath, zipPath };
        backupJobs.set(jobId, job);

        (async () => {
            try {
                job.status = 'exporting';
                const total = await EspCollection.countDocuments(q);
                const out = fs.createWriteStream(jsonPath, { encoding: 'utf8' });
                out.write('[');
                let first = true;
                let written = 0;
                
                for await (const doc of EspCollection.find(q).sort({ timestamp: 1 })) {
                    if (!first) out.write(',\n');
                    const copy = { ...doc };
                    if (copy._id) copy._id = copy._id.toString();
                    out.write(JSON.stringify(copy));
                    first = false;
                    written++;
                    if (total > 0) job.progress = Math.floor((written / total) * 90);
                }
                out.write(']');
                out.end();
                await new Promise(r => out.on('finish', r));

                job.status = 'zipping';
                const output = fs.createWriteStream(zipPath);
                const archive = archiver('zip', { zlib: { level: 9 } });
                archive.pipe(output);
                archive.file(jsonPath, { name: 'espdata.json' });
                await archive.finalize();
                await new Promise(r => output.on('close', r));

                job.status = 'done';
                job.progress = 100;
                job.finishedAt = new Date();
            } catch (err) {
                console.error('Backup Error:', err);
                job.status = 'error';
                job.error = err.message;
            }
        })();

        res.send({ jobId });
    });

    app.get('/api/backup/status/:jobId', (req, res) => {
        const job = backupJobs.get(req.params.jobId);
        if (!job) return res.status(404).send({message: 'Job not found'});
        
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        const iv = setInterval(() => {
            const j = backupJobs.get(req.params.jobId);
            if (!j) { clearInterval(iv); return res.end(); }
            res.write(`data: ${JSON.stringify({ status: j.status, progress: j.progress, error: j.error })}\n\n`);
            if (j.status === 'done' || j.status === 'error') {
                clearInterval(iv);
                res.end();
            }
        }, 1000);
        req.on('close', () => clearInterval(iv));
    });

    app.get('/api/backup/download/:jobId', (req, res) => {
        const job = backupJobs.get(req.params.jobId);
        if (!job || job.status !== 'done') return res.status(400).send('Not ready');
        res.download(job.zipPath, 'espdata.zip', () => {
            try { fs.rmSync(job.tmpDir, { recursive: true, force: true }); } catch(e){}
            backupJobs.delete(req.params.jobId);
        });
    });

    // --- ইউজার অথেন্টিকেশন রুটস ---
    app.post('/api/user/register', async (req, res) => {
        const { name, email, password } = req.body || {};
        if (!name || !email || !password) return res.status(400).send({ success: false, message: 'Missing fields' });
        
        const normalizedEmail = String(email).trim().toLowerCase();
        try {
            const exists = await usersCollection.findOne({ email: normalizedEmail });
            if (exists) return res.status(400).send({ success: false, message: 'Email taken' });

            const passwordHash = await bcrypt.hash(String(password), 10);
            await usersCollection.insertOne({
                name: String(name).trim(), email: normalizedEmail, passwordHash, devices: [], createdAt: new Date(), address: null, mobile: null
            });
            res.send({ success: true, message: 'Registered' });
        } catch (e) {
            res.status(500).send({ success: false, message: 'Error' });
        }
    });

    app.post('/api/user/login', async (req, res) => {
        const { email, password } = req.body || {};
        if (!email || !password) return res.status(400).send({ success: false });
        
        const user = await usersCollection.findOne({ email: String(email).toLowerCase() });
        if (!user || !(await bcrypt.compare(String(password), user.passwordHash))) {
            return res.status(401).send({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id.toString(), email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.send({ success: true, token });
    });

    app.post('/api/user/password/forgot', async (req, res) => {
        if (!mailTransporter) return res.status(500).send({ success: false, message: 'Email config missing' });
        const { email } = req.body;
        const user = await usersCollection.findOne({ email: String(email).toLowerCase() });
        if (user) {
            const newPass = crypto.randomBytes(6).toString('hex');
            await usersCollection.updateOne({ _id: user._id }, { $set: { passwordHash: await bcrypt.hash(newPass, 10) } });
            mailTransporter.sendMail({
                to: user.email,
                subject: 'Password Reset',
                text: `New Password: ${newPass}`
            }).catch(console.error);
        }
        res.send({ success: true, message: 'If account exists, email sent.' });
    });

    // --- প্রোটেক্টেড রুটস (ইউজার) ---
    app.get('/api/device/list', authenticateJWT, async (req, res) => {
        const list = await devicesCollection.find({}, { projection: { _id: 0 } }).toArray();
        res.send(list);
    });

    app.post('/api/user/device/add', authenticateJWT, async (req, res) => {
        const { uid } = req.body;
        if (!uid) return res.status(400).send({ message: 'UID needed' });
        await usersCollection.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $addToSet: { devices: String(uid).trim() } }
        );
        res.send({ success: true, message: 'Device added' });
    });

    app.delete('/api/user/device/remove', authenticateJWT, async (req, res) => {
        const { uid } = req.body;
        await usersCollection.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $pull: { devices: String(uid).trim() } }
        );
        res.send({ success: true, message: 'Device removed' });
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
                status: d?.status || 'offline',
                lastSeen: d?.lastSeen,
                data: d?.data || {}
            };
        });
        res.send(result);
    });

    app.get('/api/user/device/:uid/data', authenticateJWT, async (req, res) => {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
        if (!user.devices.includes(req.params.uid)) return res.status(403).send({ message: 'Forbidden' });
        
        const { limit } = req.query;
        const lim = Math.min(5000, Math.max(1, parseInt(limit, 10) || 500));
        // শেষ ২৪ ঘন্টার ডাটা ডিফল্ট
        const endDate = new Date();
        const startDate = new Date(endDate.getTime() - (24 * 60 * 60 * 1000));

        const docs = await EspCollection.find({ uid: req.params.uid, timestamp: { $gte: startDate, $lte: endDate } })
            .sort({ timestamp: -1 })
            .limit(lim)
            .project({ pssensor: 1, environment: 1, rain: 1, timestamp: 1, _id: 0 })
            .toArray();
        res.send(docs.reverse());
    });

    app.get('/api/user/profile', authenticateJWT, async (req, res) => {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) }, { projection: { passwordHash: 0 } });
        if (!user) return res.status(404).send('User not found');
        const isAdminEnv = process.env.ADMIN_EMAIL && user.email === process.env.ADMIN_EMAIL;
        user.isAdmin = (user.isAdmin === true || isAdminEnv);
        res.send(user);
    });

    app.post('/api/user/profile/update', authenticateJWT, async (req, res) => {
        const { name, address, mobile } = req.body;
        const update = {};
        if (name) update.name = name;
        if (address) update.address = address;
        if (mobile) update.mobile = mobile;
        
        await usersCollection.updateOne({ _id: new ObjectId(req.user.userId) }, { $set: update });
        res.send({ success: true });
    });

    app.post('/api/user/password/change', authenticateJWT, async (req, res) => {
        const { oldPassword, newPassword } = req.body;
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
        if (!await bcrypt.compare(oldPassword, user.passwordHash)) return res.status(401).send({ message: 'Invalid old password' });
        
        await usersCollection.updateOne({ _id: user._id }, { $set: { passwordHash: await bcrypt.hash(newPassword, 10) } });
        res.send({ success: true, message: 'Password changed' });
    });

    // --- অ্যাডমিন রুটস ---
    app.post('/api/filter/device', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        await syncAllDevices(EspCollection, devicesCollection);
        res.send({ success: true });
    });

    // [গুরুত্বপূর্ণ] Division সহ আপডেট লজিক (আপনার দেওয়া কোড অনুযায়ী)
    app.put('/api/device/:uid', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        const { uid } = req.params;
        const { location, name, latitude, longitude, division } = req.body; // Division যুক্ত

        const updateFields = {};
        if (location !== undefined) updateFields.location = location;
        if (name !== undefined) updateFields.name = name;
        if (latitude !== undefined) updateFields.latitude = latitude;
        if (longitude !== undefined) updateFields.longitude = longitude;
        if (division !== undefined) updateFields.division = division;

        if (Object.keys(updateFields).length === 0) return res.status(400).send({ message: 'No fields' });

        const result = await devicesCollection.updateOne({ uid }, { $set: updateFields });
        res.send({ success: true, message: result.matchedCount ? 'Updated' : 'Not found' });
    });

    app.get('/api/admin/stats', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        const [totalDev, onlineDev, totalData] = await Promise.all([
            devicesCollection.countDocuments(),
            devicesCollection.countDocuments({ status: 'online' }),
            EspCollection.countDocuments()
        ]);
        
        res.send({ totalDevices: totalDev, onlineDevices: onlineDev, offlineDevices: totalDev - onlineDev, totalDataPoints: totalData });
    });

    app.get('/api/admin/users', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        const users = await usersCollection.find({}, { projection: { passwordHash: 0 } }).toArray();
        res.send(users);
    });

    app.post('/api/admin/user/make-admin', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        await usersCollection.updateOne({ email: req.body.email }, { $set: { isAdmin: true } });
        res.send({ success: true });
    });

    app.post('/api/admin/user/remove-admin', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        if (req.body.email === process.env.ADMIN_EMAIL) return res.status(403).send({ message: 'Cannot remove super admin' });
        
        await usersCollection.updateOne({ email: req.body.email }, { $set: { isAdmin: false } });
        res.send({ success: true });
    });

  } catch (err) {
    console.error('Startup Error:', err);
  }
}

run().catch(console.dir);

// রুট মেসেজ
app.get("/", (req, res) => {
  res.send(`<h1 style="text-align: center; color: green;">Max it Server (Optimized) is Running at ${port}</h1>`);
});

// সার্ভার চালু
http_server.listen(port, () => {
  console.log(`Max it Production server running at: ${port}`);
  console.log(`Current server time: ${new Date().toLocaleString('en-US', { timeZone: 'Asia/Dhaka' })} (Asia/Dhaka)`);
});