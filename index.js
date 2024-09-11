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

async function connectToDB(dbName, connectorId, additionalInfo = 'hi') {
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


// Define the schema for ConnectionDetail
const connectionDetailSchema = new mongoose.Schema({
    deviceName: {
        type: String,
        required: true,
    },
    connectorId: {
        type: String,
        required: true,
    },
    additionalInfo: {
        type: String,
        required: false, // Set to true if this field should be required
    },
    investigatorId: {
        type: String,
        required: true,
    },
}, {
    timestamps: true, // Adds createdAt and updatedAt fields
});

// Create the model from the schema
const ConnectionDetail = mongoose.model('ConnectionDetail', connectionDetailSchema);

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



// Define a function to get an emoji based on the sentiment score
function getSentimentEmoji(score) {
    if (score < -2) {
        return '😡'; // Angry or very negative sentiment
    } else if (score < 0) {
        return '😞'; // Sad or negative sentiment
    } else if (score === 0) {
        return '😐'; // Neutral sentiment
    } else if (score <= 2) {
        return '😊'; // Happy or positive sentiment
    } else {
        return '😁'; // Very happy or extremely positive sentiment
    }
}

// Update the analyzeSentiment function to include emojis
function analyzeSentiment(text) {
    const result = sentiment.analyze(text); 
    return {
        isNegative: result.score < -2, // Arbitrary threshold for negative sentiment
        emoji: getSentimentEmoji(result.score)
    };
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
            const sentimentAnalysis = analyzeSentiment(item.body);
            const isSuspicious = detectFraudulentLanguage(item.body) || 
                                 detectCriminalLanguage(item.body) || 
                                 detectCyberbullyingLanguage(item.body) || 
                                 detectThreatLanguage(item.body) || 
                                 sentimentAnalysis.isNegative;
            item.isSuspicious = isSuspicious;
            item.sentimentEmoji = sentimentAnalysis.emoji; // Add sentiment emoji

            if (isSuspicious) {
                if (detectFraudulentLanguage(item.body)) {
                    item.category = 'fraud';
                } else if (detectCriminalLanguage(item.body)) {
                    item.category = 'criminal';
                } else if (detectCyberbullyingLanguage(item.body)) {
                    item.category = 'cyberbullying';
                } else if (detectThreatLanguage(item.body)) {
                    item.category = 'threat';
                } else if (sentimentAnalysis.isNegative) {
                    item.category = 'negative_sentiment';
                }
            } else {
                item.category = 'normal';
            }
        }
        return item;
    });
}

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

        // Update SMS data with contact names and categories
        const updatedSmsData = allSmsData.map(sms => {
            if (contactsMap.has(sms.address)) {
                sms.contactName = contactsMap.get(sms.address);
            } else {
                sms.contactName = null; // or any other value if the contact name is not found
            }
            if (sms.body) {
                const sentimentAnalysis = analyzeSentiment(sms.body);
                sms.isSuspicious = detectFraudulentLanguage(sms.body) || 
                                   detectCriminalLanguage(sms.body) || 
                                   detectCyberbullyingLanguage(sms.body) || 
                                   detectThreatLanguage(sms.body) || 
                                   sentimentAnalysis.isNegative;
                sms.sentimentEmoji = sentimentAnalysis.emoji; // Add sentiment emoji

                if (sms.isSuspicious) {
                    if (detectFraudulentLanguage(sms.body)) {
                        sms.category = 'fraud';
                    } else if (detectCriminalLanguage(sms.body)) {
                        sms.category = 'criminal';
                    } else if (detectCyberbullyingLanguage(sms.body)) {
                        sms.category = 'cyberbullying';
                    } else if (detectThreatLanguage(sms.body)) {
                        sms.category = 'threat';
                    } else if (sentimentAnalysis.isNegative) {
                        sms.category = 'negative_sentiment';
                    }
                } else {
                    sms.category = 'normal';
                }
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


// Assuming you are using Express and have a model ConnectionDetail


app.get('/connection-details', async (req, res) => {
    try {
        // Retrieve all documents from the ConnectionDetail collection
        const connectionDetails = await ConnectionDetail.find();

        res.status(200).json(connectionDetails);
    } catch (err) {
        console.error('Error retrieving additional information:', err);
        res.status(500).send('Error retrieving additional information');
    }
});


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


app.get('/comprehensive-report', async (req, res) => {
    try {
        // Step 1: Get the device name
        const deviceName = await getDeviceName();
        const dbName = sanitizeDeviceName(deviceName);

        // Step 2: Connect to the appropriate MongoDB database
        await connectToDB(dbName);

        // Step 3: Fetch SMS data
        const smsData = await SMS.find().sort({ date: -1 }).exec();

        // Step 4: Fetch call logs
        const callLogs = await CallLog.find().sort({ date: -1 }).exec();

        // Step 5: Fetch contacts
        const contacts = await Contact.find().exec();

        // Step 6: Aggregate SMS statistics
        const smsStats = await SMS.aggregate([
            {
                $group: {
                    _id: null,
                    totalMessages: { $sum: 1 },
                    suspiciousMessages: { $sum: { $cond: ['$isSuspicious', 1, 0] } },
                    fraud: { $sum: { $cond: [{ $eq: ['$category', 'fraud'] }, 1, 0] } },
                    criminal: { $sum: { $cond: [{ $eq: ['$category', 'criminal'] }, 1, 0] } },
                    cyberbullying: { $sum: { $cond: [{ $eq: ['$category', 'cyberbullying'] }, 1, 0] } },
                    threat: { $sum: { $cond: [{ $eq: ['$category', 'threat'] }, 1, 0] } },
                    negative_sentiment: { $sum: { $cond: [{ $eq: ['$category', 'negative_sentiment'] }, 1, 0] } }
                }
            }
        ]).exec();

        // Step 7: Aggregate call statistics
        const callStats = await CallLog.aggregate([
            {
                $group: {
                    _id: null,
                    totalCalls: { $sum: 1 },
                    incomingCalls: { $sum: { $cond: [{ $eq: ['$type', 'incoming'] }, 1, 0] } },
                    outgoingCalls: { $sum: { $cond: [{ $eq: ['$type', 'outgoing'] }, 1, 0] } },
                    missedCalls: { $sum: { $cond: [{ $eq: ['$type', 'missed'] }, 1, 0] } }
                }
            }
        ]).exec();

        // Step 8: Perform timeline analysis for SMS
        const smsTimeline = await SMS.aggregate([
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

        // Step 9: Perform timeline analysis for calls
        const callTimeline = await CallLog.aggregate([
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
                    totalCalls: { $sum: 1 },
                    incomingCalls: { $sum: { $cond: [{ $eq: ["$type", "incoming"] }, 1, 0] } },
                    outgoingCalls: { $sum: { $cond: [{ $eq: ["$type", "outgoing"] }, 1, 0] } },
                    missedCalls: { $sum: { $cond: [{ $eq: ["$type", "missed"] }, 1, 0] } }
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
                    totalCalls: 1,
                    incomingCalls: 1,
                    outgoingCalls: 1,
                    missedCalls: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        // Step 10: Perform URL analysis
        const smsWithUrls = await SMS.find({ body: /http:\/\/|https:\/\/|www\./i }).exec();

        // Step 11: Perform data correlation
        const dataCorrelation = await SMS.aggregate([
            { $group: { _id: "$address", smsCount: { $sum: 1 } } },
            { $sort: { smsCount: -1 } },
            { $limit: 10 }
        ]).exec();

        const correlatedNumbersPromises = dataCorrelation.map(async (sms) => {
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

        const dataCorrelationResults = await Promise.all(correlatedNumbersPromises);

        // Combine SMS and Call Log timeline data
        const combinedTimeline = [];

        const allDates = new Set([
            ...smsTimeline.map(entry => entry.date),
            ...callTimeline.map(entry => entry.date)
        ]);

        allDates.forEach(date => {
            const smsEntry = smsTimeline.find(entry => entry.date === date) || {};
            const callEntry = callTimeline.find(entry => entry.date === date) || {};

            combinedTimeline.push({
                date,
                totalMessages: smsEntry.totalMessages || 0,
                suspiciousMessages: smsEntry.suspiciousMessages || 0,
                totalCalls: callEntry.totalCalls || 0,
                incomingCalls: callEntry.incomingCalls || 0,
                outgoingCalls: callEntry.outgoingCalls || 0,
                missedCalls: callEntry.missedCalls || 0
            });
        });

        combinedTimeline.sort((a, b) => new Date(a.date) - new Date(b.date));

        // Step 12: Respond with the comprehensive report
        res.json({
            deviceName,
            smsData,
            callLogs,
            contacts,
            smsStats: smsStats[0] || {},
            callStats: callStats[0] || {},
            timelineAnalysis: combinedTimeline,
            smsWithUrls,
            dataCorrelationResults
        });
    } catch (err) {
        console.error('Error generating comprehensive report:', err);
        res.status(500).json({ error: 'Failed to generate comprehensive report' });
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

        // Aggregate SMS data
        const smsTimeline = await SMS.aggregate([
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

        // Aggregate Call Log data
        const callTimeline = await CallLog.aggregate([
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
                    totalCalls: { $sum: 1 },
                    incomingCalls: { $sum: { $cond: [{ $eq: ["$type", "incoming"] }, 1, 0] } },
                    outgoingCalls: { $sum: { $cond: [{ $eq: ["$type", "outgoing"] }, 1, 0] } },
                    missedCalls: { $sum: { $cond: [{ $eq: ["$type", "missed"] }, 1, 0] } }
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
                    totalCalls: 1,
                    incomingCalls: 1,
                    outgoingCalls: 1,
                    missedCalls: 1
                }
            },
            {
                $sort: { date: 1 }
            }
        ]).exec();

        // Combine SMS and Call Log timeline data
        const combinedTimeline = [];

        const allDates = new Set([
            ...smsTimeline.map(entry => entry.date),
            ...callTimeline.map(entry => entry.date)
        ]);

        allDates.forEach(date => {
            const smsEntry = smsTimeline.find(entry => entry.date === date) || {};
            const callEntry = callTimeline.find(entry => entry.date === date) || {};

            combinedTimeline.push({
                date,
                totalMessages: smsEntry.totalMessages || 0,
                suspiciousMessages: smsEntry.suspiciousMessages || 0,
                totalCalls: callEntry.totalCalls || 0,
                incomingCalls: callEntry.incomingCalls || 0,
                outgoingCalls: callEntry.outgoingCalls || 0,
                missedCalls: callEntry.missedCalls || 0
            });
        });

        combinedTimeline.sort((a, b) => new Date(a.date) - new Date(b.date));

        res.json(combinedTimeline);
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
