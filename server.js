const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const multer = require('multer');
const cors = require('cors');
const fs = require('fs');
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
let otpStore = {};





const app = express();
app.use(cors());
app.use(express.json());

/* ---------- CREATE UPLOADS FOLDER ---------- */
if (!fs.existsSync('uploads')) {
    fs.mkdirSync('uploads');
}

/* ---------- DATABASE ---------- */
let db = new sqlite3.Database("complaints.db");
db.run("PRAGMA foreign_keys = ON");

/* ---------- TABLES ---------- */
/* ---------- USERS TABLE ---------- */
db.run(`
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    user_id TEXT UNIQUE NOT NULL,
    fullname TEXT NOT NULL,
    
    email TEXT UNIQUE NOT NULL,
    mobile TEXT UNIQUE NOT NULL,
    
    password TEXT NOT NULL,
    
    state TEXT,
    city TEXT,
    gender TEXT,
    dob TEXT,
    
    verified INTEGER DEFAULT 0
);
`);


/* ---------- INVESTIGATORS TABLE ---------- */
db.run(`
CREATE TABLE IF NOT EXISTS investigators_new (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    investigator_id TEXT UNIQUE NOT NULL,
    
    name TEXT NOT NULL,
    designation TEXT,
    type TEXT,
    expertise TEXT,
    
    email TEXT UNIQUE,
    mobile TEXT UNIQUE,
    
    password TEXT NOT NULL
);
`);


/* ---------- COMPLAINTS TABLE ---------- */
db.run(`
CREATE TABLE IF NOT EXISTS complaints (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    complaint_id TEXT UNIQUE NOT NULL,
    
    user_id TEXT NOT NULL,
    investigator_id TEXT,
    
    complaint_date TEXT,
    
    type TEXT NOT NULL,
    date TEXT,
    time TEXT,
    location TEXT,
    
    description TEXT,
    evidence TEXT,
    
    status TEXT DEFAULT 'Pending',

    FOREIGN KEY (user_id)
        REFERENCES users(user_id),

    FOREIGN KEY (investigator_id)
        REFERENCES investigators_new(investigator_id)
);
`);


/* ---------- ESCALATIONS TABLE ---------- */
db.run(`
CREATE TABLE IF NOT EXISTS escalations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    
    complaint_id TEXT NOT NULL,
    investigator_id TEXT,
    
    reason TEXT NOT NULL,
    type TEXT,
    
    status TEXT DEFAULT 'Pending',
    
    created_at TEXT DEFAULT CURRENT_TIMESTAMP,

    FOREIGN KEY (complaint_id)
        REFERENCES complaints(complaint_id),

    FOREIGN KEY (investigator_id)
        REFERENCES investigators_new(investigator_id)
);
`);


/* ---------- FILE UPLOAD ---------- */
const storage = multer.diskStorage({
    destination: (req, file, cb) => {
        cb(null, 'uploads');   // folder
    },
    filename: (req, file, cb) => {
        cb(null, Date.now() + "-" + file.originalname);
    }
});

const upload = multer({

    storage: storage,

    limits: {

        fileSize: 5 * 1024 * 1024

    },

    fileFilter: (req, file, cb) => {

        const allowedTypes = [

            "image/jpeg",

            "image/png",

            "application/pdf"

        ];

        if (allowedTypes.includes(file.mimetype)) {

            cb(null, true);

        } else {

            cb(new Error("Invalid File Type"));

        }

    }

});
const JWT_SECRET = "SECRET_KEY";
let blacklistedTokens = new Set();

function verifyToken(req, res, next) {

    const authHeader = req.headers.authorization;

    if (!authHeader) {
        return res.status(403).json({ message: "No Token Provided" });
    }

    if (!authHeader.startsWith("Bearer ")) {
        return res.status(403).json({ message: "Invalid Token Format" });
    }

    const token = authHeader.split(" ")[1];

    if (blacklistedTokens.has(token)) {
        return res.status(403).json({ message: "Token Expired (Logged Out)" });
    }

    jwt.verify(token, JWT_SECRET, (err, decoded) => {

        if (err) {
            return res.status(403).json({ message: "Invalid or Expired Token" });
        }

        req.user = decoded;
        next();
    });
}

/* ---------- SERVE FILES ---------- */
app.use('/uploads', express.static('uploads'));

/* ---------- ADD COMPLAINT ---------- */
app.post('/addComplaint',verifyToken, upload.single('evidence'), (req, res) => {

    let c = req.body;
    let file = req.file ? req.file.filename :null;

    console.log("Complaint received:", c);

    db.run(`
        INSERT INTO complaints 
        (complaint_date, user_id, complaint_id, type, date, time, location, description, evidence, status, investigator_id)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        c.complaint_date,
        c.user_id,
        c.complaint_id,
        c.type,
        c.date,
        c.time,
        c.location,
        c.description,
        file,
        c.status || "Pending",
        c.investigator_id || "Not Assigned"
    ], (err) => {
        if(err){
            console.log("DB ERROR:", err);  //  important
            return res.status(500).send("Error saving complaint");
        }
        res.json({message:"Complaint Saved Successfully"});
    });
});

/* ---------- REGISTER USER ---------- */

app.post("/registerUser",  async (req, res)  => {

    let u = req.body;

    console.log("User received:", u);
    
    const hashedPassword =
    await bcrypt.hash(u.password, 10);
    db.run(`
        INSERT INTO users 
        (user_id, fullname, email, mobile, password, state, city, gender, dob)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, [
        u.user_id,
        u.fullname,
        u.email,
        u.mobile,
        hashedPassword,
        u.state,
        u.city,
        u.gender,
        u.dob
    ], (err) => {
        if(err){
            console.log(err);
            return res.status(500).send("Error saving user");
        }
        res.send("User Registered Successfully");
    });
});


/* ---------------- USER LOGIN ---------------- */

app.post("/userLogin", (req, res) => {

    const { user_id, password } = req.body;

    /* INPUT VALIDATION */

    if (!user_id || !password) {

        return res.status(400).json({
            message: "User ID and Password required"
        });

    }

    /* CHECK USER IN DATABASE */

    db.get(

        "SELECT * FROM users WHERE user_id = ?",

        [user_id],

        async (err, user) => {

            /* DATABASE ERROR */

            if (err) {

                return res.status(500).json({
                    message: "Database Error"
                });

            }

            /* USER NOT FOUND */

            if (!user) {

                return res.status(401).json({
                    message: "Invalid User ID"
                });

            }

            /* PASSWORD CHECK */

            const isMatch =
            await bcrypt.compare(password, user.password);

            /* WRONG PASSWORD */

            if (!isMatch) {

                return res.status(401).json({
                    message: "Wrong Password"
                });

            }

            /* JWT TOKEN CREATION */

            const token = jwt.sign(

                {

                    user_id: user.user_id,
                    role: "user"

                },

                "SECRET_KEY",

                {

                    expiresIn: "1h"

                }

            );

            /* SUCCESS RESPONSE */

            res.json({

                message: "Login Successful",

                token: token

            });

        }

    );

});
const ADMIN_ID = "admin@12";

const ADMIN_HASH =
"$2b$10$u1UqIeOCYy164npjA5gjGerlcq7ZVThi7gneI4jI0yzlvKLFZbeO2";

app.post("/adminLogin", async (req, res) => {

    const { admin_id, password } = req.body;

    if(admin_id !== ADMIN_ID){

        return res.status(401).json({
            message: "Invalid Admin ID"
        });

    }

    const isMatch =
    await bcrypt.compare(password, ADMIN_HASH);

    if(!isMatch){

        return res.status(401).json({
            message: "Wrong Password"
        });

    }

    const token = jwt.sign(

        {
            admin_id: admin_id,
            role: "admin"
        },

        "SECRET_KEY",

        {
            expiresIn: "1h"
        }

    );

    res.json({

        message: "Admin Login Successful",

        token: token

    });

});


/* =========================
   ADMIN CHECK
========================= */

function isAdmin(req, res, next) {

    if (!req.user || req.user.role !== "admin") {

        return res.status(403).json({
            message: "Access Denied"
        });

    }

    next();

}
/* ---------- GET ALL USERS (ADMIN) ---------- */
app.get(

"/allUsers",

verifyToken,

isAdmin,

(req, res) => {

    db.all(
    `
        SELECT 
        users.*,
        COUNT(complaints.id) AS total_complaints

        FROM users

        LEFT JOIN complaints
        ON users.user_id = complaints.user_id

        GROUP BY users.user_id
        `,

        [],

        (err, rows) => {

            if (err) {

                return res.status(500).json([]);

            }

            res.json(rows);

        }

    );

});
/* ---------- GET USER COMPLAINTS ---------- */

app.get("/userComplaints", verifyToken,(req, res) => {

    let user_id = req.query.user_id;

    db.all(

        "SELECT * FROM complaints WHERE user_id = ?",

        [user_id],

        (err, rows) => {

            if(err){

                console.log(err);

                return res.json([]);

            }

            res.json(rows);

        }

    );

});


app.post("/verifyInvID", (req, res) => {

    let { investigator_id } = req.body;

    db.get(

        `
        SELECT *
        FROM investigators_new
        WHERE investigator_id = ?
        `,

        [investigator_id],

        (err, user) => {

            if(err){

                console.log(err);

                return res.json({

                    status:"error"

                });

            }

            if(!user){

                return res.json({

                    status:"invalid"

                });

            }

            res.json({

                status:"valid"

            });

        }

    );

});

app.post("/verifyPassword", async (req, res) => {

    let { investigator_id, password } = req.body;

    db.get(
        `SELECT * FROM investigators_new WHERE investigator_id = ?`,
        [investigator_id],
        async (err, user) => {

            if (err) {
                console.log(err);
                return res.json({ status: "error" });
            }

            if (!user) {
                return res.json({ status: "invalid_id" });
            }

            let isMatch = false;

            // CASE 1: hashed password
            if (user.password.startsWith("$2b$")) {
                isMatch = await bcrypt.compare(password, user.password);
            }

            // CASE 2: plain text password (OLD DB)
            else {
                isMatch = (password === user.password);

                // upgrade to hash after success
                if (isMatch) {
                    const hashed = await bcrypt.hash(password, 10);

                    db.run(
                        `UPDATE investigators_new SET password = ? WHERE investigator_id = ?`,
                        [hashed, investigator_id]
                    );
                }
            }

            if (!isMatch) {
                return res.json({ status: "wrong_password" });
            }

            res.json({ status: "correct" });
        }
    );
});
app.post("/investigatorLogin", (req, res) => {

    let { investigator_id, password } = req.body;

    if (!investigator_id || !password) {
        return res.status(400).json({
            success: false,
            message: "All Fields Required"
        });
    }

    db.get(
        `SELECT * FROM investigators_new WHERE investigator_id = ?`,
        [investigator_id],
        async (err, investigator) => {

            if (err) {
                console.log(err);
                return res.status(500).json({
                    success: false,
                    message: "Database Error"
                });
            }

            if (!investigator) {
                return res.status(401).json({
                    success: false,
                    message: "Invalid Investigator ID"
                });
            }

            let isMatch = false;

            // CASE 1: already hashed password (bcrypt format starts with $2b$)
            if (investigator.password.startsWith("$2b$")) {
                isMatch = await bcrypt.compare(password, investigator.password);
            }

            // CASE 2: legacy plain-text password in DB
            else {
                isMatch = (password === investigator.password);

                // upgrade to hashed password after successful login
                if (isMatch) {
                    const hashed = await bcrypt.hash(password, 10);

                    db.run(
                        `UPDATE investigators_new SET password = ? WHERE investigator_id = ?`,
                        [hashed, investigator_id]
                    );
                }
            }

            if (!isMatch) {
                return res.status(401).json({
                    success: false,
                    message: "Wrong Password"
                });
            }

            // JWT token
            const token = jwt.sign(
                {
                    investigator_id: investigator.investigator_id,
                    role: "investigator"
                },
                "SECRET_KEY",
                { expiresIn: "1h" }
            );

            res.json({
                success: true,
                message: "Login Successful",
                token,
                investigator: {
                    name: investigator.name,
                    designation: investigator.designation,
                    type: investigator.type
                }
            });
        }
    );
});
app.get(
"/getInvestigators",

verifyToken,

isAdmin,

(req, res) => {

    db.all(
        `
        SELECT
            investigator_id,
            name,
            designation,
            type,
            expertise
        FROM investigators_new
        `,
        [],

        (err, rows) => {

            if(err){

                console.log(err);

                return res.status(500).json([]);

            }

            res.json(rows);

        }

    );

});
/* ---------- GET ALL COMPLAINTS (ADMIN) ---------- */
app.get("/allComplaints", verifyToken,
isAdmin,(req, res) => {

    db.all("SELECT * FROM complaints WHERE is_deleted=0", [], (err, rows) => {

        if(err){
            console.log(err);
            return res.status(500).json([]);
        }

        res.json(rows);
    });

});
app.get("/filterComplaints",verifyToken,
isAdmin, (req, res) => {

let { date, type, year, month, status, assign, user, complaint_id } = req.query;

let conditions = [];
let params = [];

// Exact Complaint Date
if(date){
    conditions.push("complaint_date = ?");
    params.push(date);
}

// Crime Type
if(type){
    conditions.push("type = ?");
    params.push(type);
}

// Year
if(year){
    conditions.push("strftime('%Y', complaint_date) = ?");
    params.push(year);
}

// Month
if(month){
    conditions.push("strftime('%m', complaint_date) = ?");
    params.push(month);
}

// 🔹 Status
if(status){
    conditions.push("status = ?");
    params.push(status);
}

// User ID (partial search)
if(user){
    conditions.push("user_id LIKE ?");
    params.push(`%${user}%`);
}

// Complaint ID (partial or exact)
if(complaint_id){
    conditions.push("complaint_id LIKE ?");
    params.push(`%${complaint_id}%`);
}

// Assignment
if(assign === "assigned"){
    conditions.push("investigator_id IS NOT NULL AND investigator_id != 'Not Assigned'");
}
else if(assign === "not_assigned"){
    conditions.push("(investigator_id IS NULL OR investigator_id = 'Not Assigned')");
}

//  FINAL QUERY
let query = "SELECT * FROM complaints";

if(conditions.length > 0){
    query += " WHERE " + conditions.join(" AND ");
}

console.log("QUERY:", query);
console.log("PARAMS:", params);

db.all(query, params, (err, rows) => {
    if(err){
        console.error(err);
        return res.json([]);
    }
    res.json(rows);
});

});
app.post("/sendOTP", (req, res) => {

let mobile = req.body.mobile;

if(!mobile){
    return res.status(400).json({message: "Mobile number required"});
}

let otp = Math.floor(100000 + Math.random() * 900000);

// store OTP with expiry (2 minutes)
otpStore[mobile] = {
    otp: otp,
    expiry: Date.now() + 2 * 60 * 1000
};

console.log("OTP for", mobile, "is:", otp);

res.json({message: "OTP sent"});

});
app.post("/verifyMobileOTP", (req, res) => {

let mobile = req.body.mobile;
let enteredOTP = req.body.otp;

if(!otpStore[mobile]){
    return res.json({success: false, message: "No OTP found"});
}

// check expiry
if(Date.now() > otpStore[mobile].expiry){
    delete otpStore[mobile];
    return res.json({success: false, message: "OTP expired"});
}

// check OTP
if(otpStore[mobile].otp == enteredOTP){
    delete otpStore[mobile]; // remove after success
    res.json({success: true});
} else {
    res.json({success: false, message: "Wrong OTP"});
}

});
let emailOtpStore = {};

app.post("/sendemailOTP", (req, res) => {

let email = req.body.email;

if(!email){
    return res.status(400).json({message: "Email required"});
}

let otp = Math.floor(100000 + Math.random() * 900000);

emailOtpStore[email] = {
    otp: otp,
    expiry: Date.now() + 2 * 60 * 1000
};

console.log("OTP for", email, "is:", otp);

res.json({message: "OTP sent"});

});


app.post("/verifyemailOTP", (req, res) => {

let email = req.body.email;
let enteredOTP = req.body.otp;

if(!emailOtpStore[email]){
    return res.json({success: false, message: "No OTP found"});
}

if(Date.now() > emailOtpStore[email].expiry){
    delete emailOtpStore[email];
    return res.json({success: false, message: "OTP expired"});
}

if(emailOtpStore[email].otp == enteredOTP){
    delete emailOtpStore[email];
    res.json({success: true});
} else {
    res.json({success: false, message: "Wrong OTP"});
}

});

/* ---------- UPDATE USER PROFILE ---------- */
app.post("/updateProfile",verifyToken, (req, res) => {

    let u = req.body;

    console.log("Update request:", u);

    db.run(`
        UPDATE users 
        SET fullname = ?, email = ?, mobile = ?, state = ?
        WHERE user_id = ?
    `, [
        u.fullname,
        u.email,
        u.mobile,
        u.state,
        u.user_id
    ], function(err){

        if(err){
            console.log(err);
            return res.status(500).json({message:"Update failed"});
        }

        if(this.changes === 0){
            return res.json({message:"User not found"});
        }

        res.json({message:"Profile updated successfully"});
    });

});
app.post("/updateInvProfile", async (req, res) => {

    let {

        email,

        mobile,

        password

    } = req.body;

    try{

        /* HASH PASSWORD */

        const hashedPassword =
        await bcrypt.hash(password, 10);

        db.run(

            `
            UPDATE investigators_new
            SET
                mobile = ?,
                password = ?
            WHERE email = ?
            `,

            [

                mobile,

                hashedPassword,

                email

            ],

            function(err){

                if(err){

                    console.log(err);

                    return res.json({

                        success:false

                    });

                }

                res.json({

                    success:true,

                    message:
                    "Profile updated successfully"

                });

            }

        );

    }

    catch(error){

        console.log(error);

        res.status(500).json({

            success:false

        });

    }

});

/* =========================================
   INVESTIGATOR AUTHORIZATION
========================================= */

function isInvestigator(req, res, next){

    if(req.user.role !== "investigator"){

        return res.status(403).json({

            message:"Access Denied"

        });

    }

    next();

}
app.get("/myComplaints", verifyToken,

isInvestigator,(req, res) => {

    let id = req.query.id;

    db.all(
        `SELECT * FROM complaints 
         WHERE investigator_id = ? 
         AND is_deleted = 0 
         AND is_escalated = 0`,
        [id],
        (err, rows) => {

            if (err) {
                console.log(err);
                return res.json([]);
            }

            res.json(rows);
        }
    );
});
app.post("/assignComplaint", verifyToken, isAdmin, (req, res) => {

    let { complaint_id, investigator_id } = req.body;

    db.get(
        `SELECT investigator_id FROM complaints WHERE complaint_id = ?`,
        [complaint_id],
        (err, row) => {

            if (err) {
                console.log(err);
                return res.status(500).json({ message: "DB error" });
            }

            if (!row) {
                return res.status(404).json({
                    message: "Complaint not found"
                });
            }

            // BLOCK IF ALREADY ASSIGNED
            if (row.investigator_id && row.investigator_id !== "Not Assigned") {
                return res.status(400).json({
                    message: "Already assigned. Cannot reassign."
                });
            }

            // ASSIGN ONLY IF NOT ASSIGNED
            db.run(
                `UPDATE complaints
                 SET investigator_id = ?, status = 'Assigned'
                 WHERE complaint_id = ?`,
                [investigator_id, complaint_id],
                function (err2) {

                    if (err2) {
                        console.log(err2);
                        return res.status(500).json({
                            message: "Assignment failed"
                        });
                    }

                    res.json({
                        message: "Complaint assigned successfully"
                    });
                }
            );
        }
    );
});// This now correctly closes the single app.post call
app.get("/", (req, res) => {

    res.send("Cybercrime Server Running");

});
app.post("/updateStatus",verifyToken,

isInvestigator, (req, res) => {

    let { complaint_id, status } = req.body;

    if (!complaint_id || !status) {
        return res.json({ success: false, message: "Missing data" });
    }

    db.run(
        `UPDATE complaints SET status = ? WHERE complaint_id = ?`,
        [status, complaint_id],
        function (err) {

            if (err) {
                console.log("Status Update Error:", err);
                return res.json({ success: false });
            }

            if (this.changes === 0) {
                return res.json({ success: false, message: "Complaint not found" });
            }

            res.json({
                success: true,
                message: "Status updated successfully",
                updatedComplaintId: complaint_id
            });
        }
    );

});
app.get("/verifyComplaintId", (req, res) => {

    let id = req.query.id;

    db.get(
        "SELECT complaint_id FROM complaints WHERE complaint_id = ?",
        [id],
        (err, row) => {

            if (err) {
                console.log(err);
                return res.json({ valid: false });
            }

            if (!row) {
                return res.json({ valid: false });
            }

            res.json({ valid: true });

        }
    );

});
app.get("/getComplaintStatus", (req, res) => {

    let id = req.query.id;

    db.get(
        "SELECT * FROM complaints WHERE complaint_id = ?",
        [id],
        (err, row) => {

            if(err){
                console.log(err);
                return res.json([]);
            }

            if(!row){
                return res.json([]);
            }

            res.json(row);
        }
    );

});
app.post("/escalateCase", verifyToken, isInvestigator, (req, res) => {

    let { complaint_id, investigator_id, reason, type } = req.body;

    // STEP 1: GET COMPLAINT
    db.get(
        `SELECT * FROM complaints WHERE complaint_id = ?`,
        [complaint_id],
        (err, complaint) => {

            if (err || !complaint) {
                return res.json({
                    success: false,
                    message: "Complaint not found"
                });
            }

            // STEP 2: INSERT ESCALATION
            db.run(
                `INSERT INTO escalations
                (complaint_id, investigator_id, reason, type)
                VALUES (?, ?, ?, ?)`,
                [
                    complaint_id,
                    investigator_id,
                    reason,
                    type
                ],
                function (err2) {

                    if (err2) {
                        console.log(err2);
                        return res.json({ success: false });
                    }

                    // STEP 3: UPDATE COMPLAINT STATUS + REMOVE INVESTIGATOR
                    db.run(
                        `UPDATE complaints
                         SET is_escalated = 1,
                             investigator_id = 'Not Assigned',
                             status = 'Escalated'
                         WHERE complaint_id = ?`,
                        [complaint_id],
                        function (err3) {

                            if (err3) {
                                console.log(err3);
                                return res.json({ success: false });
                            }

                            res.json({
                                success: true,
                                message: "Case escalated successfully"
                            });
                        }
                    );
                }
            );
        }
    );
});
app.get("/allEscalations",verifyToken,

isAdmin, (req, res) => {
    db.all("SELECT * FROM escalations", [], (err, rows) => {
        if(err){
            console.log(err);
            return res.json([]);
        }
        res.json(rows);
    });
});

app.post(

"/deleteComplaint",

verifyToken,

isAdmin,

(req, res) => {

    let { complaint_id } =
    req.body;

    db.run(
        `
        UPDATE complaints
        SET is_deleted = 1
        WHERE complaint_id = ?
        AND status = 'Resolved'
        `,
        [complaint_id],
        function(err){

            if(err){

                return res.json({

                    success:false

                });

            }

            res.json({

                success:
                this.changes > 0

            });

        }
    );

});
/* =========================================
   GLOBAL ERROR HANDLER
========================================= */

app.use((err, req, res, next) => {

    console.error(

        "SERVER ERROR:",

        err

    );

    res.status(500).json({

        success:false,

        message:"Internal Server Error"

    });

});
app.post("/SendemailOTP", (req, res) => {

    let { email } = req.body;

    if(!email){
        return res.json({ success:false, message:"Email required" });
    }

    //  CHECK EMAIL EXISTS
    db.get("SELECT * FROM users WHERE email = ?", [email], (err, user) => {

        if(err){
            return res.json({ success:false });
        }

        if(!user){
            return res.json({ success:false, message:"Email not registered" });
        }

        //  GENERATE OTP
        let otp = Math.floor(100000 + Math.random() * 900000);

        emailOtpStore[email] = {
            otp: otp,
            expiry: Date.now() + 2 * 60 * 1000
        };

        console.log("OTP for", email, "is:", otp);

        res.json({ success:true, message:"OTP sent" });

    });

});
app.get("/getUserByEmail", (req, res) => {

    let email = req.query.email;

    db.get("SELECT user_id, fullname, mobile, city, state FROM users WHERE email = ?", 
    [email], 
    (err, user) => {

        if(err || !user){
            return res.json(null);
        }

        res.json(user);
    });

});
app.post(

"/updateProfileSecure",
verifyToken,
async (req, res) => {

    try {

        let {
            email,
            mobile,
            city,
            state,
            password
        } = req.body;

        const hashedPassword =
        await bcrypt.hash(password, 10);

        db.run(`
            UPDATE users
            SET
                mobile = ?,
                city = ?,
                state = ?,
                password = ?
            WHERE email = ?
        `,
        [
            mobile,
            city,
            state,
            hashedPassword,
            email
        ],
        function(err){

            if(err){

                console.log(err);

                return res.json({

                    success:false

                });

            }

            res.json({

                success:true,

                message:"Profile Updated Successfully"

            });

        });

    } catch(error){

        console.log(error);

        res.status(500).json({

            success:false

        });

    }

});

app.post("/sendInvEmailOTP", (req, res) => {

    let { email } = req.body;

    db.get("SELECT * FROM investigators_new WHERE email = ?", [email], (err, user) => {

        if(err){
            return res.json({success:false});
        }

        if(!user){
            return res.json({success:false, message:"Email not registered"});
        }

        let otp = Math.floor(100000 + Math.random() * 900000);

        emailOtpStore[email] = {
            otp: otp,
            expiry: Date.now() + 2 * 60 * 1000
        };

        console.log("Investigator OTP:", otp);

        res.json({success:true, message:"OTP sent"});
    });

});
app.get("/getInvByEmail", (req, res) => {

    let email = req.query.email;

    db.get(
        "SELECT investigator_id, name, mobile FROM investigators_new WHERE email = ?",
        [email],
        (err, user) => {

            if(err || !user){
                return res.json(null);
            }

            res.json(user);
        }
    );

});

/* ================================
   ADMIN ANALYTICS BACKEND API
================================ */

app.get("/analytics",verifyToken,  isAdmin, (req, res) => {

    let analytics = {};

    /* TOTAL USERS */
    db.get(
        "SELECT COUNT(*) AS totalUsers FROM users",
        [],
        (err, userRow) => {

            if(err){
                return res.json({success:false});
            }

            analytics.totalUsers = userRow.totalUsers;

            /* TOTAL COMPLAINTS */
            db.get(
                "SELECT COUNT(*) AS totalComplaints FROM complaints",
                [],
                (err, complaintRow) => {

                    analytics.totalComplaints =
                    complaintRow.totalComplaints;

                    /* TOTAL INVESTIGATORS */
                    db.get(
                        "SELECT COUNT(*) AS totalInvestigators FROM investigators_new",
                        [],
                        (err, invRow) => {

                            analytics.totalInvestigators =
                            invRow.totalInvestigators;

                            /* TOTAL ESCALATED */
                            db.get(
                                "SELECT COUNT(*) AS escalatedCases FROM complaints WHERE is_escalated = 1",
                                [],
                                (err, escRow) => {

                                    analytics.escalatedCases =
                                    escRow.escalatedCases;

                                    res.json(analytics);

                                }
                            );

                        }
                    );

                }
            );

        }
    );

});


/* ================================
   ASSIGNED / NOT ASSIGNED
================================ */

app.get("/assignmentAnalytics", (req, res) => {

    let type = req.query.type;

    let query = "";

    if(type === "assigned"){

        query =
        `SELECT COUNT(*) AS total 
         FROM complaints
         WHERE investigator_id != 'Not Assigned'`;

    }
    else{

        query =
        `SELECT COUNT(*) AS total 
         FROM complaints
         WHERE investigator_id = 'Not Assigned'`;

    }

    db.get(query, [], (err, row) => {

        if(err){
            return res.json({total:0});
        }

        res.json({
            total: row.total
        });

    });

});
/* ================================
   MOST OCCURRED CRIME
================================ */

app.get("/mostCrime", (req, res) => {

    db.get(
        `SELECT type, COUNT(*) AS total
         FROM complaints
         GROUP BY type
         ORDER BY total DESC
         LIMIT 1`,
        [],
        (err, row) => {

            if(err){
                return res.json({});
            }

            res.json(row);

        }
    );

});


/* ================================
   STATUS ANALYTICS
================================ */

app.get("/statusAnalytics", (req, res) => {

    let status = req.query.status;

    db.get(
        `SELECT COUNT(*) AS total
         FROM complaints
         WHERE status = ?`,
        [status],
        (err, row) => {

            if(err){
                return res.json({total:0});
            }

            res.json({
                total: row.total
            });

        }
    );

});


/* ================================
   CRIME TYPE ANALYTICS
================================ */

app.get("/crimeAnalytics", (req, res) => {

    let type = req.query.type;

    db.get(
        `SELECT COUNT(*) AS total
         FROM complaints
         WHERE type = ?`,
        [type],
        (err, row) => {

            if(err){
                return res.json({total:0});
            }

            res.json({
                total: row.total
            });

        }
    );

});
/* ---------- TOTAL CASES OF INVESTIGATOR ---------- */

app.get("/getInvestigatorCaseCount", verifyToken,

(req, res) => {

    let id = req.query.id;

    db.get(
        `SELECT COUNT(*) AS totalCases
         FROM complaints
         WHERE investigator_id = ?`,
        [id],
        (err, row) => {

            if(err){
                console.log(err);
                return res.json({ totalCases: 0 });
            }

            res.json({
                totalCases: row.totalCases
            });

        }
    );

});
app.get("/investigatorStatistics",verifyToken,

isInvestigator, (req, res) => {

    let id = req.query.id;

    let stats = {
        total:0,
        pending:0,
        progress:0,
        resolved:0,
        escalated:0,
        caseTypes:[]
    };

    db.get(
        `SELECT COUNT(*) AS total
         FROM complaints
         WHERE investigator_id=?`,
        [id],
        (err,row)=>{

            stats.total = row.total;

            db.get(
                `SELECT COUNT(*) AS total
                 FROM complaints
                 WHERE investigator_id=?
                 AND status='Pending'`,
                [id],
                (err,row2)=>{

                    stats.pending = row2.total;

                    db.get(
                        `SELECT COUNT(*) AS total
                         FROM complaints
                         WHERE investigator_id=?
                         AND status='In Progress'`,
                        [id],
                        (err,row3)=>{

                            stats.progress = row3.total;

                            db.get(
                                `SELECT COUNT(*) AS total
                                 FROM complaints
                                 WHERE investigator_id=?
                                 AND status='Resolved'`,
                                [id],
                                (err,row4)=>{

                                    stats.resolved = row4.total;

                                    db.get(
                                        `SELECT COUNT(*) AS total
                                         FROM escalations
                                         WHERE investigator_id=?`,
                                        [id],
                                        (err,row5)=>{

                                            stats.escalated =
                                            row5.total;

                                            db.all(
                                                `SELECT type,
                                                 COUNT(*) AS total
                                                 FROM complaints
                                                 WHERE investigator_id=?
                                                 GROUP BY type`,
                                                [id],
                                                (err,rows)=>{

                                                    stats.caseTypes =
                                                    rows;

                                                    res.json(stats);

                                                }
                                            );

                                        }
                                    );

                                }
                            );

                        }
                    );

                }
            );

        }
    );

});
app.post("/checkUserID", (req,res)=>{

let user_id = req.body.user_id;

db.get(
"SELECT * FROM users WHERE user_id=?",
[user_id],

(err,row)=>{

    if(row){
        res.json({exists:true});
    }
    else{
        res.json({exists:false});
    }

});

});
/* =========================================
   ADMIN LOGOUT BACKEND
========================================= */
app.post("/adminLogout", verifyToken, isAdmin, (req, res) => {

    try{

        /* GET TOKEN */

        const token =
        req.headers.authorization.split(" ")[1];

        /* BLACKLIST TOKEN */

        blacklistedTokens.add(token);

        console.log(

            "Admin Logged Out:",

            req.user.admin_id

        );

        res.json({

            success:true,

            message:"Admin Logout Successful"

        });

    }

    catch(error){

        console.log(error);

        res.status(500).json({

            success:false,

            message:"Logout Failed"

        });

    }

});
/* =========================================
   USER LOGOUT
========================================= */


app.post("/userLogout", verifyToken, (req, res) => {

    try{

        /* GET TOKEN */

        const token =
        req.headers.authorization.split(" ")[1];

        /* ADD TOKEN TO BLACKLIST */

        blacklistedTokens.add(token);

        console.log(

            "User Logged Out:",

            req.user.user_id

        );

        res.json({

            success:true,

            message:"User Logout Successful"

        });

    }

    catch(error){

        console.log(error);

        res.status(500).json({

            success:false,

            message:"Logout Failed"

        });

    }

});

/* =========================================
   INVESTIGATOR LOGOUT
========================================= */

app.post(

"/investigatorLogout",

verifyToken,

isInvestigator,

(req, res) => {

    try{

        /* GET TOKEN */

        const token =
        req.headers.authorization.split(" ")[1];

        /* BLACKLIST TOKEN */

        blacklistedTokens.add(token);

        console.log(

            "Investigator Logged Out:",

            req.user.investigator_id

        );

        res.json({

            success:true,

            message:"Investigator Logout Successful"

        });

    }

    catch(error){

        console.log(error);

        res.status(500).json({

            success:false,

            message:"Logout Failed"

        });

    }

});
app.get("/testToken", verifyToken, (req, res) => {

   res.json({

      decodedData: req.user

   });

});
app.get(
"/getInvestigatorsBasic",

verifyToken,

isAdmin,

(req, res) => {

    let { type, expertise } = req.query;

    let conditions = [];
    let params = [];

    /* FILTER TYPE */

    if(type && type !== "all"){

        conditions.push("type = ?");
        params.push(type);

    }

    /* FILTER EXPERTISE */

    if(expertise){

        conditions.push("expertise = ?");
        params.push(expertise);

    }

    let query = `
    SELECT
        investigator_id,
        name,
        designation,
        type,
        expertise,
        email,
        mobile
    FROM investigators_new
    `;

    /* ADD WHERE CONDITIONS */

    if(conditions.length > 0){

        query += " WHERE " + conditions.join(" AND ");

    }

    console.log(query);
    console.log(params);

    db.all(query, params, (err, rows) => {

        if(err){

            console.log(err);

            return res.status(500).json([]);

        }

        res.json(rows);

    });

});
app.get("/adminInvestigatorList", verifyToken, isAdmin, (req, res) => {

    db.all(
        `
        SELECT 
            i.investigator_id,
            i.name,
            i.designation,
            COUNT(c.id) AS total_assigned
        FROM investigators_new i
        LEFT JOIN complaints c
        ON i.investigator_id = c.investigator_id
        GROUP BY i.investigator_id
        `,
        [],
        (err, rows) => {

            if (err) {
                console.log(err);
                return res.json([]);
            }

            res.json(rows);
        }
    );

});
app.get("/getInvestigatorsBas", verifyToken, isAdmin, (req, res) => {

    let { type, expertise } = req.query;

    let conditions = [];
    let params = [];

    if(type && type !== "all"){
        conditions.push("type = ?");
        params.push(type);
    }

    if(expertise){
        conditions.push("expertise = ?");
        params.push(expertise);
    }

    let whereClause = conditions.length ? "WHERE " + conditions.join(" AND ") : "";

    db.all(
        `
        SELECT 
            i.*,
            COUNT(c.id) AS total_assigned
        FROM investigators_new i
        LEFT JOIN complaints c 
        ON i.investigator_id = c.investigator_id
        ${whereClause}
        GROUP BY i.investigator_id
        `,
        params,
        (err, rows) => {

            if(err){
                console.log(err);
                return res.json([]);
            }

            res.json(rows);
        }
    );
});
app.delete("/deleteEscalation/:complaint_id", (req, res) => {

    const complaint_id = req.params.complaint_id;

    const sql = `
        DELETE FROM escalations
        WHERE complaint_id = ?
    `;

    db.run(sql, [complaint_id], function (err) {
        if (err) {
            console.log(err);
            return res.status(500).json({ message: "DB error" });
        }

        // this.changes → number of rows deleted
        if (this.changes === 0) {
            return res.status(404).json({ message: "No escalation found" });
        }

        res.json({ message: "Escalation deleted permanently" });
    });
});
/* ---------- START SERVER ---------- */
app.listen(3000, () => {
    console.log("Server running on http://localhost:3000");
});
