// server.js
import express from 'express';
import bodyParser from 'body-parser';
import sqlite3 from 'sqlite3';
import { open } from 'sqlite';
import { initialize } from 'zokrates-js';
import cors from 'cors';
import path from 'path';
import fs from 'fs';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = 5000;

app.use(cors());
app.use(bodyParser.json());
app.use(express.static(__dirname));
app.use("/zk", express.static(path.join(__dirname, "zk")));

let db;
let zokrates;
let artifacts;
let keypair;

const startServer = async () => {
  try {
    db = await open({ filename: './zk_users.db', driver: sqlite3.Database });
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        stored_hash TEXT
      )
    `);

    zokrates = await initialize();
    console.log("ZoKrates initialized");

    const source = `
      import \"hashes/sha256/512bitPacked\" as sha256packed;
      def main(private field[4] hash_input, field[2] stored_hash) {
          field[2] computed = sha256packed(hash_input);
          assert(computed[0] == stored_hash[0]);
          assert(computed[1] == stored_hash[1]);
      }
    `;

    artifacts = zokrates.compile(source);
    keypair = zokrates.setup(artifacts.program);

    fs.mkdirSync("zk", { recursive: true });
    fs.writeFileSync("zk/out", Buffer.from(artifacts.program));
    fs.writeFileSync("zk/abi.json", JSON.stringify(artifacts.abi, null, 2));
    fs.writeFileSync("zk/proving.key", Buffer.from(keypair.pk));
    console.log("📦 ZoKrates artifacts saved to zk/");

    app.listen(PORT, () => console.log(`🚀 Server running on http://localhost:${PORT}`));
  } catch (err) {
    console.error("❌ Error starting server:", err);
  }
};

startServer();
// Inside server.js (replace your /register endpoint with this):

app.post('/register', async (req, res) => {
    const { username, stored_hash } = req.body;
  
    console.log("Registering user:", username);
    console.log("Stored hash:", stored_hash);   
    // Expecting stored_hash to be an array of 2 strings
    if (!Array.isArray(stored_hash) || stored_hash.length !== 2) {
      return res.status(400).send('❌ Invalid stored hash format');
    }
  
    await db.run(
      'INSERT OR REPLACE INTO users (username, stored_hash) VALUES (?, ?)',
      [username, JSON.stringify(stored_hash)]
    );
  
    res.send('✅ Registered');
  });
  
app.post('/login', async (req, res) => {
    const { username, proof, inputs } = req.body;
  
    const row = await db.get('SELECT stored_hash FROM users WHERE username = ?', [username]);
    if (!row) return res.status(404).send('❌ User not found');
  
    const expectedHash = JSON.parse(row.stored_hash);
    const flatInputs = inputs.flat();
  
    console.log("Flat inputs:", flatInputs);
    console.log("Expected hash:", expectedHash);
  
    // Check the last 2 inputs match expectedHash
    const inputHashFromClient = flatInputs.slice(-2);
    if (
      inputHashFromClient[0] !== expectedHash[0] ||
      inputHashFromClient[1] !== expectedHash[1]
    ) {
      return res.status(403).send('❌ Hash mismatch');
    }
  
    console.log("Full Proof:", JSON.stringify(proof, null, 2));
  
    console.log("Verifying proof...");
  
    const isValid = zokrates.verify(keypair.vk, proof);
    res.send(isValid ? `✅ Welcome back, ${username}` : '❌ Invalid proof');
  });
  
