
const express = require("express");
const Database = require("better-sqlite3");
const app = express();
const db = new Database("taskflow.db");
const bcrypt = require("bcryptjs");
const session = require("express-session");

db.exec(`
    CREATE TABLE IF NOT EXISTS tasks (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        user_id INTEGER
    )
`);

const columns = db.prepare("PRAGMA table_info(tasks)").all();

if (!columns.some(column => column.name === "user_id")) {
    db.exec("ALTER TABLE tasks ADD COLUMN user_id INTEGER");
}

db.exec(`
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL
    )
`);

app.set("view engine", "ejs");
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

app.use(session({
    secret: process.env.SESSION_SECRET || "taskflow-dev-secret-change-me",
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        sameSite: "lax",
        secure: false,
        maxAge: 60 * 60 * 1000
    }
}));

app.use(express.static("public"));

// AUTHENTICATION MIDDLEWARE
function requireAuth(req, res, next) {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "Please login first"
        });
    }

    next();
}

app.get("/", (req, res) => {
    res.render("index");
});

// REGISTER
app.post("/api/register", async (req, res) => {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";

    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        return res.status(400).json({
            error: "Enter a valid email"
        });
    }

    if (password.length < 8) {
        return res.status(400).json({
            error: "Password must be at least 8 characters"
        });
    }

    try {
        const hashedPassword = await bcrypt.hash(password, 10);

        const result = db.prepare(
            "INSERT INTO users (email, password) VALUES (?, ?)"
        ).run(email, hashedPassword);
       
     req.session.userId = Number(result.lastInsertRowid);
     req.session.email = email;

      req.session.save((err) => {
    if (err) {
        return res.status(500).json({
            error: "Session save failed"
        });
    }

    res.status(201).json({
        message: "Registration successful"
    });
});

    } catch (err) {
        if (err.code === "SQLITE_CONSTRAINT_UNIQUE") {
            return res.status(409).json({
                error: "Email already registered"
            });
        }

        console.error(err);
        res.status(500).json({
            error: "Registration failed"
        });
    }
});

// LOGIN
app.post("/api/login", async (req, res) => {
    const email = (req.body.email || "").trim().toLowerCase();
    const password = req.body.password || "";

    const user = db.prepare(
        "SELECT * FROM users WHERE email = ?"
    ).get(email);

    if (!user || !(await bcrypt.compare(password, user.password))) {
        return res.status(401).json({
            error: "Invalid email or password"
        });
    }

    req.session.regenerate((err) => {
        if (err) {
            return res.status(500).json({
                error: "Login failed"
            });
        }

        req.session.userId = user.id;
        req.session.email = user.email;

        req.session.save((err) => {
            if (err) {
                return res.status(500).json({
                    error: "Session save failed"
                });
            }

            res.json({
                message: "Login successful",
                email: user.email
            });
        });
    });
});

// CHECK LOGIN STATUS
app.get("/api/me", (req, res) => {
    if (!req.session.userId) {
        return res.status(401).json({
            error: "Not logged in"
        });
    }

    res.json({
        id: req.session.userId,
        email: req.session.email
    });
});

// LOGOUT
app.post("/api/logout", (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            return res.status(500).json({
                error: "Logout failed"
            });
        }

        res.clearCookie("connect.sid");

        res.json({
            message: "Logout successful"
        });
    });
});

// READ - User's tasks only
app.get("/api/tasks", requireAuth, (req, res) => {
    const tasks = db.prepare(
        "SELECT * FROM tasks WHERE user_id = ? ORDER BY id DESC"
    ).all(req.session.userId);

    res.json(tasks);
});

// CREATE

app.post("/api/tasks", requireAuth, (req, res) => {
    const name = (req.body.name || "").trim();

    if (name.length < 3) {
        return res.status(400).json({
            error: "Task must contain at least 3 characters"
        });
    }

    const result = db.prepare(
        "INSERT INTO tasks (name, user_id) VALUES (?, ?)"
    ).run(name, req.session.userId);

    res.status(201).json({
        id: Number(result.lastInsertRowid),
        name
    });
});
// UPDATE - Own tasks only
app.put("/api/tasks/:id", requireAuth, (req, res) => {
    const name = (req.body.name || "").trim();

    if (name.length < 3) {
        return res.status(400).json({
            error: "Task must contain at least 3 characters"
        });
    }

    const result = db.prepare(
        "UPDATE tasks SET name = ? WHERE id = ? AND user_id = ?"
    ).run(name, req.params.id, req.session.userId);

    if (result.changes === 0) {
        return res.status(404).json({
            error: "Task not found"
        });
    }

    res.json({
        id: Number(req.params.id),
        name
    });
});

// DELETE - Own tasks only
app.delete("/api/tasks/:id", requireAuth, (req, res) => {
    const id = Number(req.params.id);

    const result = db.prepare(
        "DELETE FROM tasks WHERE id = ? AND user_id = ?"
    ).run(id, req.session.userId);

    if (result.changes === 0) {
        return res.status(404).json({
            error: "Task not found"
        });
    }

    res.json({
        message: "Task deleted successfully"
    });
});

const PORT = 3000;

app.listen(PORT, () => {
    console.log(`TaskFlow running at http://localhost:${PORT}`);
});
 