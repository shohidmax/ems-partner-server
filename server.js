
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
require('dotenv').config();

// --- কনফিগারেশন এবং ধ্রুবক ---
const PORT = process.env.PORT || 3002;
const JWT_SECRET = process.env.JWT_SECRET || 'default_secret_please_change';
const MONGODB_URI = process.env.MONGODB_URI;

// টাইমিং কনফিগারেশন
const BATCH_INTERVAL_MS = 10000;       // ১০ সেকেন্ড
const DEVICE_SYNC_INTERVAL_MS = 600000; // ১০ মিনিট
const OFFLINE_CHECK_INTERVAL_MS = 60000; // ১ মিনিট
const OFFLINE_THRESHOLD_MS = 600000;    // ১০ মিনিট

// গ্লোবাল ভেরিয়েবল
let db;
let espDataBuffer = [];
const backupJobs = new Map();

// --- অ্যাপ ইনিশিয়ালাইজেশন ---
const app = express();
const http_server = http.createServer(app);
const io = new Server(http_server, {
    cors: { origin: "*" } // Socket.io CORS
});

// --- ইমেইল ট্রান্সপোর্টার ---
let mailTransporter;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
    mailTransporter = nodemailer.createTransport({
        host: process.env.EMAIL_HOST || 'smtp.gmail.com',
        port: parseInt(process.env.EMAIL_PORT || '587'),
        secure: process.env.EMAIL_SECURE === 'true',
        auth: {
            user: process.env.EMAIL_USER,
            pass: process.env.EMAIL_PASS,
        },
    });
    console.log('[Email] ইমেইল সিস্টেম সক্রিয় আছে।');
} else {
    console.warn('[Email] ইমেইল কনফিগারেশন পাওয়া যায়নি।');
}

// --- মিডলওয়্যার ---
app.use(helmet());
app.use(compression());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static('public'));

// ডাটাবেস অ্যাটাচমেন্ট মিডলওয়্যার (খুবই গুরুত্বপূর্ণ)
app.use((req, res, next) => {
    if (!db) return res.status(503).send({ message: 'Database connecting...' });
    req.db = db;
    next();
});

// --- অথেন্টিকেশন মিডলওয়্যার ---
const authenticateJWT = (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).send({ success: false, message: 'Authorization header missing' });

    const token = authHeader.split(' ')[1];
    if (!token) return res.status(401).send({ success: false, message: 'Token missing' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ success: false, message: 'Invalid token' });
        req.user = user;
        next();
    });
};

// --- অ্যাডমিন চেক হেল্পার ---
const ensureAdmin = async (req, res, next) => {
    try {
        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        const isAdminEnv = process.env.ADMIN_EMAIL && user && user.email === process.env.ADMIN_EMAIL;
        
        if (user && (user.isAdmin === true || isAdminEnv)) {
            req.userData = user; // পরবর্তী ব্যবহারের জন্য
            next();
        } else {
            res.status(403).send({ success: false, message: 'Admin access required' });
        }
    } catch (error) {
        res.status(500).send({ success: false, message: 'Internal server error during admin check' });
    }
};

// --- হেল্পার ফাংশন: কাস্টম ডেট পার্সার ---
// এখন থেকে এই ফাংশন শুধুমাত্র dateTime স্ট্রিংটি সরাসরি timestamp হিসেবে ব্যবহার করবে
function parseAndAssignTimestamp(data) {
    // 1. dateTime ফিল্ডকে timestamp হিসেবে ব্যবহার করা
    if (data.dateTime && typeof data.dateTime === 'string') {
        data.timestamp = data.dateTime;
    } 
    // 2. যদি dateTime না থাকে, তবে সার্ভারের বর্তমান সময়কে Date অবজেক্ট হিসেবে ব্যবহার করা
    else {
        data.timestamp = new Date();
    }
    
    // 3. সার্ভার কখন ডেটা পেয়েছে তার সময়
    data.receivedAt = new Date();
    
    return data;
}


// ------------------------------
// --- ব্যাকগ্রাউন্ড প্রসেস ---
// ------------------------------

// ১. ব্যাচ ডাটা ইনসার্ট এবং রিয়েল-টাইম আপডেট
async function processDataBuffer() {
    if (espDataBuffer.length === 0 || !db) return;

    const dataToInsert = [...espDataBuffer];
    espDataBuffer = []; // বাফার খালি করা

    const espCollection = db.collection('espdata2');
    const devicesCollection = db.collection('devices');

    try {
        // বাল্ক ইনসার্ট
        await espCollection.insertMany(dataToInsert, { ordered: false });
        
        // সকেটে নতুন ডাটা পাঠানো
        io.emit('new-data', dataToInsert);

        // ডিভাইসের লাস্ট সিন এবং স্ট্যাটাস আপডেট
        const bulkUpdates = [];
        const uniqueDevices = new Map();

        // ডুপ্লিকেট এড়িয়ে লেটেস্ট ডাটা বের করা
        dataToInsert.forEach(d => {
            if (d.uid) {
                // receivedAt ব্যবহার করা হচ্ছে, কারণ timestamp এখন স্ট্রিং
                const ts = new Date(d.receivedAt);
                if (!uniqueDevices.has(d.uid) || ts > new Date(uniqueDevices.get(d.uid).receivedAt)) {
                    uniqueDevices.set(d.uid, d);
                }
            }
        });

        uniqueDevices.forEach((data, uid) => {
            // নতুন JSON স্ট্রাকচার অনুযায়ী ডাটা ম্যাপ করা
            const deviceData = {
                version: data.version,
                pssensor: data.pssensor || {},     // { cable, mpa, avg_mpa, depth_ft }
                environment: data.environment || {}, // { temp, hum }
                rain: data.rain || {},             // { count, mm }
                
                // --- Backward Compatibility (যাতে আগের ফ্রন্টএন্ড না ভাঙ্গে) ---
                temperature: (data.environment && data.environment.temp !== undefined) ? data.environment.temp : data.temperature,
                humidity: (data.environment && data.environment.hum !== undefined) ? data.environment.hum : null,
                water_level: (data.pssensor && data.pssensor.depth_ft !== undefined) ? data.pssensor.depth_ft : data.water_level,
                rainfall: (data.rain && data.rain.mm !== undefined) ? data.rain.mm : data.rainfall
            };

            bulkUpdates.push({
                updateOne: {
                    filter: { uid: uid },
                    update: {
                        $set: {
                            lastSeen: data.receivedAt, // lastSeen এখন Date অবজেক্ট
                            status: 'online',
                            data: deviceData
                        },
                        $setOnInsert: {
                            addedAt: new Date(),
                            location: null,
                            name: `Device-${uid}`
                        }
                    },
                    upsert: true
                }
            });
        });

        if (bulkUpdates.length > 0) {
            await devicesCollection.bulkWrite(bulkUpdates, { ordered: false });
            io.emit('device-status-updated', Array.from(uniqueDevices.keys()));
        }
        
        // console.log(`[Batch] ${dataToInsert.length} records processed.`);

    } catch (error) {
        if (error.code !== 11000) { // Ignore duplicate key errors
             console.error('[Batch Error]', error.message);
        }
    }
}

// ২. অফলাইন চেকার
async function checkOfflineDevices() {
    if (!db) return;
    try {
        const threshold = new Date(Date.now() - OFFLINE_THRESHOLD_MS);
        const devicesCollection = db.collection('devices');

        const offlineDevices = await devicesCollection.find(
             { status: 'online', lastSeen: { $lt: threshold } },
             { projection: { uid: 1, _id: 0 } }
        ).toArray();

        if (offlineDevices.length > 0) {
            const uidsToUpdate = offlineDevices.map(d => d.uid);
            const result = await devicesCollection.updateMany(
                { uid: { $in: uidsToUpdate } },
                { $set: { status: 'offline' } }
            );

            if (result.modifiedCount > 0) {
                console.log(`[Offline Monitor] ${result.modifiedCount} devices marked offline.`);
                io.emit('device-status-updated', uidsToUpdate);
            }
        }
    } catch (error) {
        console.error('[Offline Monitor Error]', error);
    }
}

// ৩. পুরনো ব্যাকআপ ক্লিনআপ
function cleanupBackups() {
    const NOW = Date.now();
    backupJobs.forEach((job, id) => {
        if ((job.status === 'done' || job.status === 'error') && (NOW - job.finishedAt > 3600000)) {
            if (job.tmpDir) {
                fs.rm(job.tmpDir, { recursive: true, force: true }, (err) => {
                    if (err) console.error(`Failed to clean up backup directory: ${job.tmpDir}`, err);
                });
            }
            backupJobs.delete(id);
        }
    });
}

// ------------------------------
// --- রাউটস (Routes) ---
// ------------------------------

// ১. IoT ডাটা রিসিভার রাউটস
const iotRouter = express.Router();

const processIncomingData = (data) => {
    const processedData = parseAndAssignTimestamp(data);
    espDataBuffer.push(processedData);
};


iotRouter.post('/esp32pp', (req, res) => { // UTC রিসিভার
    processIncomingData(req.body);
    res.status(200).send({ message: 'Queued (UTC)' });
});

iotRouter.post('/esp32p', (req, res) => { // BD Time Zone হ্যান্ডলার
    processIncomingData(req.body);
    res.status(200).send({ message: 'Queued (BDT)' });
});

// ২. পাবলিক ডাটা API
const publicRouter = express.Router();

publicRouter.post('/device/data-by-range', authenticateJWT, async (req, res) => {
    try {
        const { uid, start, end, limit } = req.body || {};
        if (!uid) return res.status(400).send({ success: false, message: 'uid is required' });

        // ফিল্টারিং এর জন্য receivedAt (Date object) ব্যবহার করা হচ্ছে
        const query = { uid: String(uid) };
        if (start && end) {
            const startDate = new Date(start);
            const endDate = new Date(end);
             if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
                return res.status(400).send({ success: false, message: 'Invalid date format for start/end' });
            }
            query.receivedAt = { $gte: startDate, $lte: endDate };
        }
        
        const lim = Math.min(20000, Math.max(1, parseInt(limit, 10) || 10000));
        
        const docs = await req.db.collection('espdata2').find(query)
          .sort({ receivedAt: 1 }) // receivedAt দিয়ে সাজানো
          .limit(lim)
          .project({ uid: 1, pssensor: 1, environment: 1, rain: 1, timestamp: 1, dateTime: 1, temperature: 1, water_level: 1, rainfall: 1, _id: 0 })
          .toArray();

        return res.send(docs);
    } catch (error) {
        console.error('Error in /data-by-range:', error);
        return res.status(500).send({ success: false, message: 'Server error' });
    }
});


// ৩. অথেন্টিকেশন রাউটস
const authRouter = express.Router();

authRouter.post('/register', async (req, res) => {
    try {
        const { name, email, password } = req.body;
        if (!name || !email || !password) return res.status(400).send({ message: 'All fields required' });
        
        const users = req.db.collection('users');
        const exists = await users.findOne({ email });
        if (exists) return res.status(400).send({ message: 'Email already exists' });

        const passwordHash = await bcrypt.hash(password, 10);
        await users.insertOne({
            name, email, passwordHash,
            devices: [], createdAt: new Date(), isAdmin: false
        });
        
        res.send({ success: true, message: 'User registered' });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

authRouter.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const user = await req.db.collection('users').findOne({ email });
        
        if (!user || !(await bcrypt.compare(password, user.passwordHash))) {
            return res.status(401).send({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign({ userId: user._id, email: user.email }, JWT_SECRET, { expiresIn: '7d' });
        res.send({ success: true, token });
    } catch (e) { res.status(500).send({ error: e.message }); }
});

authRouter.post('/password/forgot', async (req, res) => {
    if (!mailTransporter) return res.status(503).send({ message: 'Email service unavailable' });
    
    try {
        const { email } = req.body;
        const user = await req.db.collection('users').findOne({ email });
        
        // নিরাপত্তা: ইউজার না থাকলেও আমরা বলব ইমেইল পাঠানো হয়েছে
        if (user) {
            const tempPass = crypto.randomBytes(4).toString('hex');
            const hash = await bcrypt.hash(tempPass, 10);
            
            await req.db.collection('users').updateOne({ _id: user._id }, { $set: { passwordHash: hash } });
            
            await mailTransporter.sendMail({
                from: process.env.EMAIL_USER,
                to: email,
                subject: 'Password Reset',
                text: `Your new temporary password is: ${tempPass}\nPlease change it immediately.`
            });
        }
        res.send({ success: true, message: 'If account exists, email sent.' });
    } catch (e) { res.status(500).send({ error: e.message }); }
});


// ৪. ইউজার প্রোটেক্টেড রাউটস
const userRouter = express.Router();
userRouter.use(authenticateJWT);

userRouter.get('/profile', async (req, res) => {
    const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) }, { projection: { passwordHash: 0 } });
    if(user) user.isAdmin = user.isAdmin || (process.env.ADMIN_EMAIL === user.email);
    res.send(user || {});
});

userRouter.post('/profile/update', async (req, res) => {
    try {
        const { name, address, mobile } = req.body;
        const updateFields = {};
        if (name) updateFields.name = name;
        if (address) updateFields.address = address;
        if (mobile) updateFields.mobile = mobile;

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({ message: "No fields to update." });
        }
        
        await req.db.collection('users').updateOne({ _id: new ObjectId(req.user.userId) }, { $set: updateFields });
        res.send({ success: true, message: "Profile updated." });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});


userRouter.get('/devices', async (req, res) => {
    const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
    if (!user || !user.devices) return res.send([]);

    const devices = await req.db.collection('devices').find({ uid: { $in: user.devices } }).toArray();
    res.send(devices);
});

userRouter.post('/device/add', async (req, res) => {
    const { uid } = req.body;
    if(!uid) return res.status(400).send({message: 'UID needed'});
    
    await req.db.collection('users').updateOne(
        { _id: new ObjectId(req.user.userId) },
        { $addToSet: { devices: String(uid).trim() } }
    );
    res.send({ success: true, message: 'Device Added' });
});

userRouter.post('/password/change', async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        if (!oldPassword || !newPassword) return res.status(400).send({ message: "Old and new passwords are required." });

        const user = await req.db.collection('users').findOne({ _id: new ObjectId(req.user.userId) });
        if (!user) return res.status(404).send({ message: "User not found." });

        const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
        if (!isMatch) return res.status(401).send({ message: "Invalid old password." });
        
        const newPasswordHash = await bcrypt.hash(newPassword, 10);
        await req.db.collection('users').updateOne({ _id: user._id }, { $set: { passwordHash: newPasswordHash } });

        res.send({ success: true, message: 'Password changed successfully.' });
    } catch (e) {
        res.status(500).send({ error: e.message });
    }
});


// ৫. অ্যাডমিন রাউটস
const adminRouter = express.Router();
adminRouter.use(authenticateJWT, ensureAdmin);

adminRouter.get('/stats', async (req, res) => {
    const stats = {
        totalDevices: await req.db.collection('devices').countDocuments(),
        onlineDevices: await req.db.collection('devices').countDocuments({ status: 'online' }),
        totalUsers: await req.db.collection('users').countDocuments(),
    };
    res.send(stats);
});

adminRouter.get('/devices', async (req, res) => {
    try {
        const devices = await req.db.collection('devices').find({}).toArray();
        const allDeviceUIDs = devices.map(d => d.uid);

        const users = await req.db.collection('users').find(
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


// ডিভাইস আপডেট করার জন্য নতুন রাউট
adminRouter.put('/device/:uid', async (req, res) => {
    try {
        const { uid } = req.params;
        const { location, name, latitude, longitude, division } = req.body;
        
        const updateFields = {};
        if (location !== undefined) updateFields.location = location;
        if (name !== undefined) updateFields.name = name;
        if (latitude !== undefined) updateFields.latitude = latitude;
        if (longitude !== undefined) updateFields.longitude = longitude;
        if (division !== undefined) updateFields.division = division;

        if (Object.keys(updateFields).length === 0) {
            return res.status(400).send({ success: false, message: 'No fields to update.' });
        }

        const result = await req.db.collection('devices').updateOne(
            { uid: uid },
            { $set: updateFields }
        );

        if (result.matchedCount === 0) {
            return res.status(404).send({ success: false, message: 'Device not found.' });
        }
        
        if (result.modifiedCount === 0 && result.matchedCount === 1) {
             return res.send({ success: true, message: 'No changes detected.' });
        }

        res.send({ success: true, message: `Device ${uid} updated successfully.` });
    } catch (error) {
        console.error('Error in /api/admin/device/:uid (PUT):', error);
        res.status(500).send({ success: false, message: 'Internal server error' });
    }
});


adminRouter.get('/users', async (req, res) => {
    const users = await req.db.collection('users').find({}, { projection: { passwordHash: 0 } }).toArray();
    res.send(users);
});


adminRouter.post('/user/make-admin', async (req, res) => {
    await req.db.collection('users').updateOne({ email: req.body.email }, { $set: { isAdmin: true } });
    res.send({ success: true, message: 'User promoted to Admin' });
});

adminRouter.post('/user/remove-admin', async (req, res) => {
    if (req.body.email === process.env.ADMIN_EMAIL) return res.status(403).send({ message: 'Cannot remove super admin' });
    await req.db.collection('users').updateOne({ email: req.body.email }, { $set: { isAdmin: false } });
    res.send({ success: true, message: 'Admin privileges removed' });
});


adminRouter.get('/report', async (req, res) => {
    const { period = 'monthly', year = new Date().getFullYear().toString() } = req.query;
    let group, sort;
    const matchYear = parseInt(year, 10);

    const matchStage = { 
        receivedAt: { 
            $gte: new Date(matchYear, 0, 1), 
            $lt: new Date(matchYear + 1, 0, 1)
        },
        'environment.temp': { $ne: 85 } // Ignore error value
    };

    switch (period) {
        case 'daily':
            group = {
                _id: { $dateToString: { format: '%Y-%m-%d', date: '$receivedAt', timeZone: 'Asia/Dhaka' } },
                avgTemp: { $avg: '$environment.temp' },
                avgRain: { $sum: '$rain.mm' },
                count: { $sum: 1 }
            };
            sort = { '_id': 1 };
            break;
        case 'yearly':
            group = {
                _id: { $year: { date: '$receivedAt', timeZone: 'Asia/Dhaka' } },
                avgTemp: { $avg: '$environment.temp' },
                avgRain: { $sum: '$rain.mm' },
                count: { $sum: 1 }
            };
            sort = { '_id': 1 };
            break;
        case 'monthly':
        default:
            group = {
                _id: { $dateToString: { format: '%Y-%m', date: '$receivedAt', timeZone: 'Asia/Dhaka' } },
                avgTemp: { $avg: '$environment.temp' },
                avgRain: { $sum: '$rain.mm' },
                count: { $sum: 1 }
            };
            sort = { '_id': 1 };
    }

    try {
        const data = await req.db.collection('espdata2').aggregate([
            { $match: matchStage },
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

adminRouter.post('/backup/start', async (req, res) => {
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
            const total = await req.db.collection('espdata2').countDocuments(q);
            const out = fs.createWriteStream(path.join(tmpDir, 'espdata.json'), { encoding: 'utf8' });
            out.write('[');
            let first = true, written = 0;
            for await (const doc of req.db.collection('espdata2').find(q).sort({ receivedAt: 1 })) {
                if (!first) out.write(',');
                // Clean Output
                const clean = { 
                    uid: doc.uid, timestamp: doc.timestamp, dateTime: doc.dateTime,
                    pssensor: doc.pssensor, environment: doc.environment, rain: doc.rain,
                    receivedAt: doc.receivedAt
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
             const downloadPath = `/api/admin/backup/download/${jobId}`;
             job.downloadUrl = downloadPath; 

        } catch (err) { job.status = 'error'; job.error = err.message; job.finishedAt = new Date(); }
    })();
});

adminRouter.get('/backup/status/:jobId', (req, res) => {
    const jobId = req.params.jobId;
    const token = req.query.token; // Get token from query string for GET request

    if (!token) return res.status(401).send({ message: 'Token missing' });
    
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).send({ message: 'Invalid token' });

        const job = backupJobs.get(jobId);
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
            const currentJob = backupJobs.get(jobId);
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
});

adminRouter.get('/backup/download/:jobId', (req, res) => {
    const job = backupJobs.get(req.params.jobId);
    if (!job || job.status !== 'done') return res.status(400).send('Not ready or invalid job ID');
    res.download(job.zipPath, 'espdata.zip');
});


// --- রাউটার মাউন্টিং ---
app.use('/api', iotRouter);
app.use('/api/public', publicRouter); 
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.use('/api/admin', adminRouter);

// রুট রুট
app.get('/', (req, res) => {
    res.send(`<h2 style="color:green;text-align:center;">Max IT IoT Server Running</h2>`);
});

// --- সার্ভার স্টার্টআপ ফাংশন ---
async function startServer() {
    try {
        if (!MONGODB_URI) throw new Error("MONGODB_URI missing in .env");
        
        const client = new MongoClient(MONGODB_URI);
        await client.connect();
        db = client.db('Esp32data');
        console.log('[Database] MongoDB Connected Successfully');

        // ইনডেক্স তৈরি (একবার রান হবে)
        db.collection('espdata2').createIndex({ receivedAt: -1 });
        db.collection('espdata2').createIndex({ uid: 1 });
        db.collection('users').createIndex({ email: 1 }, { unique: true });
        db.collection('devices').createIndex({ uid: 1 }, { unique: true });

        // ক্রোন জবস / টাইমার
        setInterval(processDataBuffer, BATCH_INTERVAL_MS);
        setInterval(checkOfflineDevices, OFFLINE_CHECK_INTERVAL_MS);
        setInterval(cleanupBackups, 3600000); // ১ ঘণ্টা পর পর

        // সার্ভার লিসেন
        http_server.listen(PORT, () => {
            console.log(`[Server] Running on port ${PORT}`);
            console.log(`[Time] Server Time: ${new Date().toString()}`);
        });

    } catch (error) {
        console.error('[Startup Error]', error);
        process.exit(1);
    }
}

// স্টার্ট!
startServer();

    

    