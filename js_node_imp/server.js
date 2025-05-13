// server.js
import express from 'express';
import bodyParser from 'body-parser';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { initialize } from 'zokrates-js';
import cors from 'cors';
import path from 'path';
import compression from 'compression';
import fs from 'fs';
import { fileURLToPath } from 'url';

// Resolve __dirname for ES modules
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

// Paths for metrics storage
const metricsPath = path.join(__dirname, 'metrics');
const metricsFile = path.join(metricsPath, 'auth_metrics.csv');

// Ensure metrics directory and file exist
if (!fs.existsSync(metricsPath)) {
  fs.mkdirSync(metricsPath, { recursive: true });
}
if (!fs.existsSync(metricsFile)) {
  fs.writeFileSync(metricsFile, 'timestamp,event,username,duration_ms,extra1,extra2,extra3\n');
}

// Middleware setup
app.use(compression()); // Enable response compression
app.use(cors()); // Enable Cross-Origin Resource Sharing
app.use(bodyParser.json()); // Parse JSON request bodies
app.use(express.static(__dirname)); // Serve static files from the current directory
app.use("/zk", express.static(path.join(__dirname, "zk"))); // Serve ZoKrates artifacts

// Database and ZoKrates variables
let db;
let zokrates;
let artifacts;
let keypair;

// Initialize server and dependencies
const startServer = async () => {
  try {
    // Open SQLite database and create users table if it doesn't exist
    db = await open({ filename: './zk_users.db', driver: sqlite3.Database });
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        stored_hash TEXT
      )
    `);

    // Initialize ZoKrates
    zokrates = await initialize();
    console.log("ZoKrates initialized");

    // ZoKrates program source code
    const source = `
      import \"hashes/sha256/512bitPacked\" as sha256packed;
      def main(private field[4] hash_input, field[2] stored_hash) {
          field[2] computed = sha256packed(hash_input);
          assert(computed[0] == stored_hash[0]);
          assert(computed[1] == stored_hash[1]);
      }
    `;

    // Compile ZoKrates program and generate keypair
    artifacts = zokrates.compile(source);
    keypair = zokrates.setup(artifacts.program);

    // Save ZoKrates artifacts to the "zk" directory
    fs.mkdirSync("zk", { recursive: true });
    fs.writeFileSync("zk/out", Buffer.from(artifacts.program));
    fs.writeFileSync("zk/abi.json", JSON.stringify(artifacts.abi, null, 2));
    fs.writeFileSync("zk/proving.key", Buffer.from(keypair.pk));
    console.log("📦 ZoKrates artifacts saved to zk/");

    // Start the server
    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (err) {
    console.error("❌ Error starting server:", err);
  }
};

startServer();

// Endpoint to register a new user
app.post('/register', async (req, res) => {
    const { username, stored_hash } = req.body;

    console.log("Registering user:", username);
    console.log("Stored hash:", stored_hash);   
    // Validate stored_hash format
    if (!Array.isArray(stored_hash) || stored_hash.length !== 2) {
      return res.status(400).send('❌ Invalid stored hash format');
    }

    // Check if the user already exists
    const existingUser = await db.get('SELECT * FROM users WHERE username = ?', [username]);
    if (existingUser) {
      return res.status(409).send('❌ User already exists');
    }
  
    // Insert or replace user in the database
    await db.run(
      'INSERT OR REPLACE INTO users (username, stored_hash) VALUES (?, ?)',
      [username, JSON.stringify(stored_hash)]
    );

    // Log metrics for the registration event
    const end = Date.now();
    const duration = req.body.metrics?.client_duration_ms || (end - start);
    const extra1 = `start=${req.body.metrics?.client_start_ms || start}`;
    const extra2 = `end=${req.body.metrics?.client_end_ms || end}`;
    const extra3 = `stored_hash=${stored_hash[0]}|${stored_hash[1]}`;
    const row = `${new Date().toISOString()},register,${username},${duration},${extra1},${extra2},${extra3}\n`;
    fs.appendFileSync(metricsFile, row);

    res.send("✅ Registered");
});

// Endpoint to log in a user
app.post('/login', async (req, res) => {
    const { username, proof, inputs } = req.body;

    // Retrieve stored hash for the user
    const row = await db.get('SELECT stored_hash FROM users WHERE username = ?', [username]);
    if (!row) return res.status(404).send('❌ User not found');

    const expectedHash = JSON.parse(row.stored_hash);
    const flatInputs = inputs.flat();

    console.log("Flat inputs:", flatInputs);
    console.log("Expected hash:", expectedHash);

    // Validate that the last 2 inputs match the stored hash
    const inputHashFromClient = flatInputs.slice(-2);
    if (
      inputHashFromClient[0] !== expectedHash[0] ||
      inputHashFromClient[1] !== expectedHash[1]
    ) {
      return res.status(403).send('❌ Wrong credentials');
    }

    console.log("Full Proof:", JSON.stringify(proof, null, 2));

    // Verify the proof using ZoKrates
    console.log("Verifying proof...");
    const isValid = zokrates.verify(keypair.vk, proof);

    // Log metrics for the login event
    const end = Date.now();
    const m = req.body.metrics || {};
    const duration = m.total_duration_ms || (end - start);
    const extra1 = `fetch=${m.fetch_duration_ms || 0}`;
    const extra2 = `proof=${m.proof_duration_ms || 0}`;
    const extra3 = `-`;
    const csvrow = `${new Date().toISOString()},${isValid ? "login-success" : "login-invalid"},${username},${duration},${extra1},${extra2},${extra3}\n`;
    fs.appendFileSync(metricsFile, csvrow);

    res.send(isValid ? `✅ Welcome back, ${username}` : '❌ Invalid proof');
});

// Endpoint to serve ZoKrates program binary
app.get("/zk/out", (req, res) => {
    const filePath = path.join(__dirname, "zk", "out");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/octet-stream");
    res.sendFile(filePath);
});

// Endpoint to serve ZoKrates proving key
app.get("/zk/proving.key", (req, res) => {
    const filePath = path.join(__dirname, "zk", "proving.key");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/octet-stream");
    res.sendFile(filePath);
});

// Endpoint to serve ZoKrates ABI
app.get("/zk/abi.json", (req, res) => {
    const filePath = path.join(__dirname, "zk", "abi.json");
    res.setHeader("Access-Control-Allow-Origin", "*");
    res.setHeader("Content-Type", "application/json");
    res.sendFile(filePath);
});