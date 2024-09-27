const express = require('express');
const crypto = require('crypto');
const bcrypt = require('bcrypt');

const app = express();
app.use(express.json()); // To handle JSON requests

// In-memory storage for encrypted and hashed data
let encryptedMessages = [];
let hashedMessages = [];

// Secret key for encryption and decryption
const SECRET_KEY = 'secretKey12345'; // Example secret key
const ALGORITHM = 'aes-256-ctr';

// Helper function for encryption
const encrypt = (message) => {
  const cipher = crypto.createCipher(ALGORITHM, SECRET_KEY);
  let encrypted = cipher.update(message, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return encrypted;
};

// Helper function for decryption
const decrypt = (encryptedMessage) => {
  const decipher = crypto.createDecipher(ALGORITHM, SECRET_KEY);
  let decrypted = decipher.update(encryptedMessage, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
};

// Route 1: Encrypt the message using Node.js Crypto module
app.get('/encrypt1/:message', (req, res) => {
  const message = req.params.message;
  const encryptedMessage = encrypt(message);
  encryptedMessages.push(encryptedMessage);
  res.json({ encryptedMessage });
});

// Route 2: Decrypt the message using Node.js Crypto module
app.get('/decrypt1/:encryptedMessage', (req, res) => {
  const encryptedMessage = req.params.encryptedMessage;
  const originalMessage = decrypt(encryptedMessage);
  res.json({ originalMessage });
});

// Route 3: Encrypt the message using external module (bcrypt)
app.get('/encrypt2/:message', async (req, res) => {
  const message = req.params.message;
  const saltRounds = 10;
  const encryptedMessage = await bcrypt.hash(message, saltRounds);
  encryptedMessages.push(encryptedMessage);
  res.json({ encryptedMessage });
});

// Route 4: Verify message using bcrypt (Note: bcrypt is a one-way hash)
app.get('/decrypt2/:encryptedMessage', async (req, res) => {
  const encryptedMessage = req.params.encryptedMessage;
  res.send("bcrypt encryption is one-way and cannot be decrypted.");
});

// Route 5: Hash the message using Node.js Crypto module
app.get('/hash1/:message', (req, res) => {
  const message = req.params.message;
  const hashedMessage = crypto.createHash('sha256').update(message).digest('hex');
  hashedMessages.push(hashedMessage);
  res.json({ hashedMessage });
});

// Route 6: Verify the hashed message
app.get('/retrieve1/:hashedMessage', (req, res) => {
  const hashedMessage = req.params.hashedMessage;
  const isMatch = hashedMessages.includes(hashedMessage);
  res.json({ match: isMatch });
});

// Start the server
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});
