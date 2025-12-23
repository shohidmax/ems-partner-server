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
const rateLimit = require('express-rate-limit'); // নতুন: রেট লিমিটিং
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
    origin: "*", // প্রয়োজনে নির্দিষ্ট ডোমেইন দিন
    methods: ["GET", "POST"]
  }
});

// --- ১. সিকিউরিটি: রেট লিমিটার সেটআপ (নতুন) ---
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
      console.warn('[Nodemailer Error]  :', error.message);
    } else {
      console.log('[Nodemailer Success]  : Email server is ready to take messages');
    }
  });
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

// IoT রুটে রেট লিমিটার বসানো হলো
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

  // বাফার থেকে ডাটা আলাদা করা এবং মেইন বাফার খালি করা
  const dataToInsert = [...espDataBuffer];
  espDataBuffer = []; 

  console.log(`[Batch Insert] Processing ${dataToInsert.length} documents...`);

  try {
    // ১. ডাটা ইনসার্ট করার চেষ্টা
    await collection.insertMany(dataToInsert, { ordered: false });
    
    // ডাটা সফলভাবে সেভ হলে ক্লায়েন্টদের জানানো
    io.emit('new-data', dataToInsert);

    // ২. ডিভাইস স্ট্যাটাস আপডেট (Last Seen)
    const lastSeenUpdates = new Map();
    for (const data of dataToInsert) {
      if (data.uid) {
        const newTime = data.timestamp || new Date(); 
        const existing = lastSeenUpdates.get(data.uid);
        
        if (!existing || newTime >= existing.time) {
          lastSeenUpdates.set(data.uid, { 
            time: newTime, 
            data: { 
              temperature: data.temperature,
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
                name: null
              }
            },
            upsert: true
          }
        });
      });

      await devicesCollection.bulkWrite(bulkOps, { ordered: false });
      io.emit('device-status-updated', updatedDeviceUIDs);
    }
    
    console.log(`[Batch Insert] Success: ${dataToInsert.length} docs saved.`);

  } catch (error) {
    console.error("[Batch Insert] Failed! Restoring data to buffer:", error.message);
    
    // [FIX] ফেইল করলে ডাটা বাফারের শুরুতে ফেরত পাঠানো হচ্ছে
    espDataBuffer = [...dataToInsert, ...espDataBuffer];
  }
}

async function syncAllDevices(EspCollection, devicesCollection) {
  // এটি একটি ভারী কাজ, তাই শুধুমাত্র প্রয়োজন হলেই চালাবেন
  try {
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
            // Node 14.14+ এর জন্য recursive delete
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
    console.log('MongoDB Connected Successfully');

    const db = client.db('Esp32data');
    const EspCollection = db.collection('espdata2'); 
    const devicesCollection = db.collection('devices');
    const usersCollection = db.collection('users');

    // --- [নতুন] পারফরম্যান্সের জন্য ইনডেক্স তৈরি ---
    // এটি নিশ্চিত করবে যে কোয়েরিগুলো দ্রুত হয়
    console.log('Ensuring indexes...');
    try {
        await EspCollection.createIndex({ uid: 1, timestamp: -1 }); // ডাটা গ্রাফের জন্য
        await devicesCollection.createIndex({ uid: 1 }, { unique: true }); // ডিভাইস লিস্টের জন্য
        await usersCollection.createIndex({ email: 1 }, { unique: true }); // লগইনের জন্য
    } catch (idxErr) {
        console.warn('Index creation warning:', idxErr.message);
    }

    // টাইমার সেটআপ
    setInterval(() => flushDataBuffer(EspCollection, devicesCollection), BATCH_INTERVAL_MS);
    setInterval(() => syncAllDevices(EspCollection, devicesCollection), FILTER_INTERVAL_MS);
    setInterval(() => checkOfflineDevices(devicesCollection), CHECK_OFFLINE_INTERVAL_MS);
    setInterval(cleanupOldBackupJobs, 15 * 60 * 1000);

    // স্টার্টআপে একবার সিঙ্ক
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
        res.status(200).send({ message: 'Data queued.' });
      } catch (error) {
        res.status(400).send({ message: 'Invalid data' });
      }
    });

    // ESP32 Data (With BD Time Logic)
    app.post('/api/esp32p', async (req, res) => {
      try {
        const data = req.body;
        
        // সার্ভার রিসিভ টাইম (Bangladesh Standard Time হিসেবে ম্যানুয়াল অ্যাডজাস্টমেন্ট)
        // দ্রষ্টব্য: এটি 'Fake UTC' তৈরি করে, তবে আপনার আগের লজিক ঠিক রাখার জন্য রাখা হলো।
        const bdTime = new Date(Date.now() + (6 * 60 * 60 * 1000));
        data.receivedAt = bdTime; 

        if (data.timestamp && typeof data.timestamp === 'string') {
          const isoString = data.timestamp.replace(' ', 'T') + "+06:00";
          data.timestamp = new Date(isoString);
        } else {
          data.timestamp = bdTime;
        }

        espDataBuffer.push(data);
        res.status(200).send({ message: 'Data queued.' });
      } catch (error) {
        console.error("Error in /api/esp32p:", error.message);
        res.status(400).send({ message: 'Invalid data' });
      }
    });

    // পাবলিক ডাটা রুট (অপ্টিমাইজড)
    app.get('/api/device/data', async (req, res) => {
      try {
        const { uid, limit } = req.query || {};
        if (!uid) return res.status(400).send({ message: 'UID required' });
        
        const lim = Math.min(1000, Math.max(1, parseInt(limit, 10) || 300));
        
        const docs = await EspCollection.find({ uid: String(uid) })
          .sort({ timestamp: -1 })
          .limit(lim)
          .project({ uid: 1, temperature: 1, water_level: 1, rainfall: 1, timestamp: 1, _id: 0 })
          .toArray();

        return res.send(docs);
      } catch (error) {
        return res.status(500).send({ message: 'Server Error' });
      }
    });

    // ডাটা রেঞ্জ রুট
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
            .project({ uid: 1, temperature: 1, water_level: 1, rainfall: 1, timestamp: 1, _id: 0 })
            .toArray();
  
          return res.send(docs);
        } catch (error) {
          return res.status(500).send({ success: false, message: 'Internal server error' });
        }
    });

    // --- ব্যাকআপ রুটস (একই আছে) ---
    app.post('/api/backup/start', async (req, res) => {
        const { uid } = req.body || {};
        const q = uid ? { uid: String(uid) } : {};
        const jobId = randomUUID();
        
        // ফোল্ডার তৈরি
        const tmpDir = path.join(os.tmpdir(), `esp-backup-${jobId}`);
        try { fs.mkdirSync(tmpDir, { recursive: true }); } catch(e){}

        const jsonPath = path.join(tmpDir, 'espdata.json');
        const zipPath = path.join(tmpDir, 'espdata.zip');
        const job = { status: 'pending', progress: 0, tmpDir, jsonPath, zipPath, error: null };
        backupJobs.set(jobId, job);

        // ব্যাকগ্রাউন্ড প্রসেস
        (async () => {
            try {
                job.status = 'exporting';
                const out = fs.createWriteStream(jsonPath, { encoding: 'utf8' });
                out.write('[');
                let first = true;
                let written = 0;
                const total = await EspCollection.countDocuments(q); // মোট সংখ্যা জানা থাকলে প্রগ্রেস ভালো দেখাবে

                const cursor = EspCollection.find(q).sort({ timestamp: 1 });
                for await (const doc of cursor) {
                    if (!first) out.write(',');
                    // মেমরি লিক এড়াতে এবং ফরম্যাট ঠিক রাখতে
                    const cleanDoc = {
                        uid: doc.uid,
                        temperature: doc.temperature,
                        water_level: doc.water_level,
                        rainfall: doc.rainfall,
                        timestamp: doc.timestamp,
                        receivedAt: doc.receivedAt
                    };
                    out.write(JSON.stringify(cleanDoc));
                    first = false;
                    written++;
                    if (total > 0) job.progress = Math.floor((written / total) * 90); // ৯০% পর্যন্ত এক্সপোর্ট
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
                job.finishedAt = new Date();
            }
        })();

        res.send({ jobId });
    });

    app.get('/api/backup/status/:jobId', (req, res) => {
        const job = backupJobs.get(req.params.jobId);
        if (!job) return res.status(404).send('Not found');
        
        res.setHeader('Content-Type', 'text/event-stream');
        res.setHeader('Cache-Control', 'no-cache');
        res.setHeader('Connection', 'keep-alive');
        
        const iv = setInterval(() => {
            const j = backupJobs.get(req.params.jobId);
            if (!j) { clearInterval(iv); return res.end(); }
            
            res.write(`data: ${JSON.stringify({ status: j.status, progress: j.progress })}\n\n`);
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
        res.download(job.zipPath);
    });

    // --- ইউজার অথেন্টিকেশন রুটস ---
    app.post('/api/user/register', async (req, res) => {
        const { name, email, password } = req.body || {};
        if (!name || !email || !password) return res.status(400).send({ success: false, message: 'Missing fields' });
        
        const normalizedEmail = String(email).trim().toLowerCase();
        try {
            const exists = await usersCollection.findOne({ email: normalizedEmail });
            if (exists) return res.status(400).send({ success: false, message: 'Email taken' });

            const passwordHash = await bcrypt.hash(password, 10);
            await usersCollection.insertOne({
                name, email: normalizedEmail, passwordHash, devices: [], createdAt: new Date()
            });
            res.send({ success: true, message: 'Registered' });
        } catch (e) {
            res.status(500).send({ success: false, message: 'Error' });
        }
    });

    app.post('/api/user/login', async (req, res) => {
        const { email, password } = req.body || {};
        const user = await usersCollection.findOne({ email: String(email).toLowerCase() });
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).send({ success: false, message: 'Invalid credentials' });
        }
        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.send({ success: true, token });
    });

    // Forgot Password
    app.post('/api/user/password/forgot', async (req, res) => {
        if (!mailTransporter) return res.status(500).send({ success: false, message: 'Email config missing' });
        const { email } = req.body;
        const user = await usersCollection.findOne({ email: String(email).toLowerCase() });
        if (user) {
            const newPass = crypto.randomBytes(4).toString('hex');
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

    app.get('/api/user/devices', authenticateJWT, async (req, res) => {
        const user = await usersCollection.findOne({ _id: new ObjectId(req.user.userId) });
        if (!user || !user.devices) return res.send([]);
        
        const devices = await devicesCollection.find({ uid: { $in: user.devices } }).toArray();
        // ডাটা ফরম্যাটিং
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

    app.post('/api/user/device/add', authenticateJWT, async (req, res) => {
        const { uid } = req.body;
        if (!uid) return res.status(400).send({ message: 'UID needed' });
        await usersCollection.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $addToSet: { devices: String(uid).trim() } }
        );
        res.send({ success: true });
    });

    app.delete('/api/user/device/remove', authenticateJWT, async (req, res) => {
        const { uid } = req.body;
        await usersCollection.updateOne(
            { _id: new ObjectId(req.user.userId) },
            { $pull: { devices: String(uid).trim() } }
        );
        res.send({ success: true });
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

    // --- অ্যাডমিন রুটস ---
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

    app.put('/api/device/:uid', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;

        const { location, name, latitude, longitude, division } = req.body;
        await devicesCollection.updateOne(
            { uid: req.params.uid },
            { $set: { location, name, latitude, longitude, division } }
        );
        res.send({ success: true });
    });

    app.get('/api/admin/users', authenticateJWT, async (req, res) => {
        const check = await ensureAdmin(req, res);
        if (!check?.ok) return;
        const users = await usersCollection.find({}, { projection: { passwordHash: 0 } }).toArray();
        res.send(users);
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
});
 