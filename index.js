const express = require('express');
const { exec } = require('child_process');
const mongoose = require('mongoose');
const moment = require('moment');
const natural = require('natural');
const cors = require('cors');
const Sentiment = require('sentiment');

const app = express();
const port = 3000;
const mongoUrl = 'mongodb://localhost:27017';

app.use(express.json());
app.use(cors());

const sentiment = new Sentiment();

function runADBCommand(command) {
    return new Promise((resolve, reject) => {
        exec(command, (error, stdout, stderr) => {
            if (error) {
                console.error(`Error executing command: ${error}`);
                return reject(error);
            }
            if (stderr) {
                console.error(`Command had errors: ${stderr}`);
                return reject(stderr);
            }
            resolve(stdout);
        });
    });
}

async function getDeviceName() {
    try {
        const command = 'adb shell getprop ro.product.model';
        const deviceName = await runADBCommand(command);
        return sanitizeDeviceName(deviceName.trim());
    } catch (err) {
        console.error('Error fetching device name:', err);
        throw err;
    }
}

function sanitizeDeviceName(name) {
    return name.replace(/[^a-zA-Z0-9_]/g, '_');
}

async function connectToDB(dbName) {
    try {
        const mongoUrlWithDB = `${mongoUrl}/${dbName}`;
        await mongoose.connect(mongoUrlWithDB, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            serverSelectionTimeoutMS: 30000
        });
        console.log(`Connected to MongoDB database: ${dbName}`);
    } catch (err) {
        console.error('Error connecting to MongoDB:', err);
        process.exit(1);
    }
}

const smsSchema = new mongoose.Schema({
    address: String,
    date: String,
    type: String,
    body: String,
    isSuspicious: Boolean,
    category: String
}, { timestamps: true, strict: false });

const callLogSchema = new mongoose.Schema({
    number: String,
    date: String,
    duration: String,
    type: String
}, { timestamps: true, strict: false });

const contactSchema = new mongoose.Schema({
    display_name: String,
    number: String
}, { timestamps: true, strict: false });

const SMS = mongoose.models.SMS || mongoose.model('SMS', smsSchema);
const CallLog = mongoose.models.CallLog || mongoose.model('CallLog', callLogSchema);
const Contact = mongoose.models.Contact || mongoose.model('Contact', contactSchema);

smsSchema.index({ address: 1 });
callLogSchema.index({ number: 1 });

const fraudKeywords = [
    'fraud', 'scam', 'money laundering', 'tax evasion', 'illegal transaction',
    'advance fee', 'phishing', 'investment scheme', 'fake lottery', 'unclaimed prize',
    'giveaway', 'credit card fraud', 'identity theft', 'wire transfer', 'account verification',
    'personal information', 'confidentiality', 'guaranteed win', 'earn money fast', 'risk-free'
];

const fraudPatterns = /buy now|limited time offer|guaranteed|risk-free|call now|exclusive deal|free gift|act now|urgent|cash prize/i;

const criminalKeywords = [
    'crime', 'theft', 'robbery', 'murder', 'assault', 'terrorism', 'drug trafficking',
    'illegal possession', 'kidnapping', 'extortion', 'arson', 'stolen goods', 'gang violence',
    'underworld', 'mafia', 'hitman', 'warrant', 'crime scene', 'criminal record', 
    'dakati', 'qatal', 'dhoka', 'bomb', 'explosive', 'attack', 'violence', 'assassin'
];

const criminalPatterns = /criminal|felony|law enforcement|arrest|warrant|wanted|gang|drug deal|illegal|offender|explosive|attack|violence/i;

const cyberbullyingKeywords = [
    'bully', 'harass', 'threaten', 'abuse', 'victim', 'cyberstalk', 'intimidate',
    'insult', 'demean', 'humiliate', 'shame', 'mock', 'belittle', 'coerce', 'blackmail',
    'derogatory', 'malicious', 'discriminate', 'targeted attack', 'online harassment'
];

const cyberbullyingPatterns = /bully|harassment|intimidation|abuse|stalker|humiliate|shame|mock|insult|derogatory/i;

const threatKeywords = [
    'explosive', 'bomb', 'attack', 'threat', 'danger', 'hazard', 'weapon', 
    'assassinate', 'kidnap', 'hostage', 'terror', 'risk', 'emergency', 
    'unsafe', 'explosive device', 'chemical weapon', 'biological weapon'
];

const threatPatterns = /bomb|explosive|attack|danger|threat|risk|terror|unsafe/i;

function parseData(data, fields) {
    return data.split('\n').filter(line => line.trim()).map(line => {
        const obj = {};
        const parts = line.match(/(\w+)=([^,]+)/g);
        if (parts) {
            parts.forEach(part => {
                const [key, value] = part.split('=');
                if (fields.includes(key)) {
                    obj[key] = value === 'NULL' ? null : value;
                }
            });
        }
        return obj;
    });
}

function detectFraudulentLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());
    
    return fraudKeywords.some(keyword => words.includes(keyword)) || fraudPatterns.test(text);
}

function detectCriminalLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());

    return criminalKeywords.some(keyword => words.includes(keyword)) || criminalPatterns.test(text);
}

function detectCyberbullyingLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());

    return cyberbullyingKeywords.some(keyword => words.includes(keyword)) || cyberbullyingPatterns.test(text);
}

function detectThreatLanguage(text) {
    const tokenizer = new natural.WordTokenizer();
    const words = tokenizer.tokenize(text.toLowerCase());

    return threatKeywords.some(keyword => words.includes(keyword)) || threatPatterns.test(text);
}

function analyzeSentiment(text) {
    const result = sentiment.analyze(text);
    return result.score < -2; // Arbitrary threshold for negative sentiment
}

function parseSMSData(data) {
    return parseData(data, ['address', 'date', 'type', 'body']).map(item => {
        if (item.type) {
            item.type = item.type === '1' ? 'received' : 'sent';
        }
        if (item.date) {
            item.date = moment(parseInt(item.date, 10)).format('YYYY-MM-DD HH:mm:ss');
        }
        if (item.body) {
            const isSuspicious = detectFraudulentLanguage(item.body) || 
                                 detectCriminalLanguage(item.body) || 
                                 detectCyberbullyingLanguage(item.body) || 
                                 detectThreatLanguage(item.body) || 
                                 analyzeSentiment(item.body);
            item.isSuspicious = isSuspicious;
            if (isSuspicious) {
                if (detectFraudulentLanguage(item.body)) {
                    item.category = 'fraud';
                } else if (detectCriminalLanguage(item.body)) {
                    item.category = 'criminal';
                } else if (detectCyberbullyingLanguage(item.body)) {
                    item.category = 'cyberbullying';
                } else if (detectThreatLanguage(item.body)) {
                    item.category = 'threat';
                } else if (analyzeSentiment(item.body)) {
                    item.category = 'negative_sentiment';
                }
            }
        }
        return item;
    });
}

function formatDuration(seconds) {
    const minutes = Math.floor(seconds / 60);
    const secs = seconds % 60;
    return `${minutes}m ${secs}s`;
}

function parseCallLogData(data) {
    return parseData(data, ['number', 'date', 'duration', 'type']).map(item => {
        if (item.type) {
            switch (item.type) {
                case '1':
                    item.type = 'incoming';
                    break;
                case '2':
                    item.type = 'outgoing';
                    break;
                case '3':
                    item.type = 'missed';
                    break;
                default:
                    item.type = 'unknown';
                    break;
            }
        }
        if (item.date) {
            item.date = moment(parseInt(item.date, 10)).format('YYYY-MM-DD HH:mm:ss');
        }
        if (item.duration) {
            item.duration = formatDuration(parseInt(item.duration, 10));
        }
        return item;
    });
}

function parseContactsData(data) {
    return parseData(data, ['display_name', 'number']);
}

app.get('/device-name', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        res.json({ deviceName });
    } catch (err) {
        console.error('Error fetching device name:', err);
        res.status(500).send('Error fetching device name');
    }
});

app.get('/sms', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        // Fetch received SMS
        const receivedSmsCommand = 'adb shell content query --uri content://sms/inbox/';
        const receivedSmsData = await runADBCommand(receivedSmsCommand);
        const parsedReceivedSmsData = parseSMSData(receivedSmsData);

        // Fetch sent SMS
        const sentSmsCommand = 'adb shell content query --uri content://sms/sent/';
        const sentSmsData = await runADBCommand(sentSmsCommand);
        const parsedSentSmsData = parseSMSData(sentSmsData);

        // Combine received and sent SMS data
        const allSmsData = [...parsedReceivedSmsData, ...parsedSentSmsData];

        // Fetch contacts data
        const contacts = await Contact.find({}).exec();
        const contactsMap = new Map(contacts.map(contact => [contact.number, contact.display_name]));

        // Update SMS data with contact names
        const updatedSmsData = allSmsData.map(sms => {
            if (contactsMap.has(sms.address)) {
                sms.contactName = contactsMap.get(sms.address);
            } else {
                sms.contactName = null; // or any other value if the contact name is not found
            }
            return sms;
        });

        // Clear existing SMS data before inserting new
        await SMS.deleteMany({});
        
        // Store new SMS data
        await SMS.insertMany(updatedSmsData);

        // Respond with updated SMS data
        res.json(updatedSmsData);
    } catch (err) {
        console.error('Error querying and saving SMS data:', err);
        res.status(500).send('Error querying and saving SMS data');
    }
});

app.get('/sms-stats', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        // Aggregate SMS data to count total SMS by number/address
        const smsStats = await SMS.aggregate([
            {
                $group: {
                    _id: "$address",
                    totalMessages: { $sum: 1 }
                }
            },
            {
                $sort: { totalMessages: -1 } // Sort by totalMessages in descending order
            }
        ]).exec();

        res.json(smsStats);
    } catch (err) {
        console.error('Error aggregating SMS data:', err);
        res.status(500).send('Error aggregating SMS data');
    }
});

app.get('/call-log', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const callLogCommand = 'adb shell content query --uri content://call_log/calls/';
        const callLogData = await runADBCommand(callLogCommand);
        const parsedCallLogData = parseCallLogData(callLogData);

        await CallLog.deleteMany({});
        await CallLog.insertMany(parsedCallLogData);

        res.json(parsedCallLogData);
    } catch (err) {
        console.error('Error querying and saving call log data:', err);
        res.status(500).send('Error querying and saving call log data');
    }
});

app.get('/contacts', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const contactsCommand = 'adb shell content query --uri content://contacts/phones/';
        const contactsData = await runADBCommand(contactsCommand);
        const parsedContactsData = parseContactsData(contactsData);

        await Contact.deleteMany({});
        await Contact.insertMany(parsedContactsData);

        res.json(parsedContactsData);
    } catch (err) {
        console.error('Error querying and saving contacts data:', err);
        res.status(500).send('Error querying and saving contacts data');
    }
});

app.get('/search', async (req, res) => {
    const { keyword } = req.query;

    if (!keyword) {
        return res.status(400).send('Keyword is required');
    }

    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const smsResults = await SMS.find({
            $or: [
                { body: new RegExp(keyword, 'i') },
                { address: new RegExp(keyword, 'i') }
            ]
        }).exec().then(sms => sms.map(item => ({
            ...item.toObject(),
            isSuspicious: detectFraudulentLanguage(item.body) || 
                          detectCriminalLanguage(item.body) || 
                          detectCyberbullyingLanguage(item.body) || 
                          detectThreatLanguage(item.body) || 
                          analyzeSentiment(item.body)
        })));

        const callLogResults = await CallLog.find({
            $or: [
                { number: new RegExp(keyword, 'i') }
            ]
        });

        const contactResults = await Contact.find({
            $or: [
                { display_name: new RegExp(keyword, 'i') },
                { number: new RegExp(keyword, 'i') }
            ]
        });

        res.json({
            sms: smsResults,
            callLog: callLogResults,
            contacts: contactResults
        });
    } catch (err) {
        console.error('Error searching data:', err);
        res.status(500).send('Error searching data');
    }
});

app.get('/timeline-analysis', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const timelineResults = await SMS.aggregate([
            {
                $addFields: {
                    date: {
                        $dateFromString: { dateString: "$date" }
                    }
                }
            },
            {
                $match: {
                    date: { $gte: new Date('2024-01-01T00:00:00Z'), $lte: new Date() }
                }
            },
            {
                $group: {
                    _id: {
                        year: { $year: "$date" },
                        month: { $month: "$date" },
                        day: { $dayOfMonth: "$date" }
                    },
                    totalMessages: { $sum: 1 },
                    suspiciousMessages: { $sum: { $cond: [{ $eq: ["$isSuspicious", true] }, 1, 0] } }
                }
            },
            {
                $addFields: {
                    date: {
                        $dateFromParts: {
                            year: "$_id.year",
                            month: "$_id.month",
                            day: "$_id.day"
                        }
                    }
                }
            },
            {
                $project: {
                    _id: 0,
                    date: { $dateToString: { format: "%Y-%m-%d", date: "$date" } },
                    totalMessages: 1,
                    suspiciousMessages: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        res.json(timelineResults);
    } catch (err) {
        console.error('Error performing timeline analysis:', err);
        res.status(500).send('Error performing timeline analysis');
    }
});

app.get('/url-analysis', async (req, res) => {
    try {
        const deviceName = await getDeviceName();
        await connectToDB(deviceName);

        const smsWithUrls = await SMS.find({ body: /http:\/\/|https:\/\/|www\./i });

        res.json(smsWithUrls);
    } catch (err) {
        console.error('Error performing URL analysis:', err);
        res.status(500).send('Error performing URL analysis');
    }
});

app.get('/data-correlation', async (req, res) => {
    try {
        const smsData = await SMS.aggregate([
            { $group: { _id: "$address", smsCount: { $sum: 1 } } },
            { $sort: { smsCount: -1 } },
            { $limit: 10 }
        ]);

        const correlatedNumbersPromises = smsData.map(async (sms) => {
            try {
                const callLogs = await CallLog.find({ number: sms._id });
                return {
                    number: sms._id,
                    smsCount: sms.smsCount,
                    callLogs
                };
            } catch (error) {
                console.error(`Error fetching call logs for number ${sms._id}:`, error);
                return {
                    number: sms._id,
                    smsCount: sms.smsCount,
                    callLogs: []
                };
            }
        });

        const results = await Promise.all(correlatedNumbersPromises);

        res.json(results);
    } catch (err) {
        console.error('Error performing data correlation:', err);
        res.status(500).send('Error performing data correlation');
    }
});

app.listen(port, async () => {
    console.log(`Server running on http://localhost:${port}`);
});
