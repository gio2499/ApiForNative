
require('dotenv').config();
const express  = require('express');
const bcrypt   = require('bcryptjs');
const jwt      = require('jsonwebtoken');
const cors     = require('cors');
const pool     = require('./db');

const app = express();
app.use(cors());
app.use(express.json());


function generateAccessToken(user) {
  return jwt.sign({ id: user.id }, process.env.ACCESS_SECRET, {
    expiresIn: '15s'
  });
}
function generateRefreshToken(user) {
  return jwt.sign({ id: user.id }, process.env.REFRESH_SECRET, {
    expiresIn: '1d'
  });
}


function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader?.split(' ')[1];
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.ACCESS_SECRET, (err, user) => {
    if (err) return res.sendStatus(401);
    req.user = user;
    next();
  });
}


app.post('/register', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [exists] = await pool.query(
      'SELECT id FROM users WHERE email = ?',
      [email]
    );
    if (exists.length) {
      return res.status(400).json({ error: 'User already exists' });
    }
    const hash = await bcrypt.hash(password, 10);
    await pool.query(
      'INSERT INTO users (email, password) VALUES (?, ?)',
      [email, hash]
    );
    res.json({ message: 'Registered successfully' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});


app.post('/login', async (req, res) => {
  const { email, password } = req.body;
  try {
    const [rows] = await pool.query(
      'SELECT * FROM users WHERE email = ?',
      [email]
    );
    const user = rows[0];
    if (!user || !(await bcrypt.compare(password, user.password))) {
      return res.status(400).json({ error: 'Invalid credentials' });
    }
    const accessToken  = generateAccessToken(user);
    const refreshToken = generateRefreshToken(user);
    res.json({ accessToken, refreshToken });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});


app.post('/token', (req, res) => {
  const { token } = req.body;
  if (!token) return res.sendStatus(401);
  jwt.verify(token, process.env.REFRESH_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    const accessToken = generateAccessToken({ id: user.id });
    res.json({ accessToken });
  });
});


app.post('/logout', (req, res) => {
  res.sendStatus(204);
});


app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: `Hello user #${req.user.id}` });
});


app.get('/me', authenticateToken, async (req, res) => {
  try {
    const [[user]] = await pool.query(
      'SELECT id, email /*, other fields */ FROM users WHERE id = ?',
      [req.user.id]
    );
    if (!user) return res.sendStatus(404);
    res.json(user);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});



app.get('/cart', authenticateToken, async (req, res) => {
  try {
    const userId = req.user.id;
    const [items] = await pool.query(
      'SELECT product_id, quantity FROM cart_items WHERE user_id = ?',
      [userId]
    );
    res.json({ items });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});



app.post('/cart', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { productId, quantity = 1 } = req.body;
  try {
    const [[existing]] = await pool.query(
      'SELECT id, quantity FROM cart_items WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );
    if (existing) {
      await pool.query(
        'UPDATE cart_items SET quantity = ? WHERE id = ?',
        [existing.quantity + quantity, existing.id]
      );
    } else {
      await pool.query(
        'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)',
        [userId, productId, quantity]
      );
    }
    res.json({ message: 'Cart updated' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});


app.patch('/cart', authenticateToken, async (req, res) => {
  const userId = req.user.id;
  const { productId, quantity } = req.body;
  try {
    if (quantity <= 0) {
      await pool.query(
        'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?',
        [userId, productId]
      );
    } else {
      const [[existing]] = await pool.query(
        'SELECT id FROM cart_items WHERE user_id = ? AND product_id = ?',
        [userId, productId]
      );
      if (existing) {
        await pool.query(
          'UPDATE cart_items SET quantity = ? WHERE id = ?',
          [quantity, existing.id]
        );
      } else {
        await pool.query(
          'INSERT INTO cart_items (user_id, product_id, quantity) VALUES (?, ?, ?)',
          [userId, productId, quantity]
        );
      }
    }
    res.json({ message: 'Cart updated' });
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});


app.delete('/cart/:productId', authenticateToken, async (req, res) => {
  const userId    = req.user.id;
  const productId = Number(req.params.productId);
  try {
    await pool.query(
      'DELETE FROM cart_items WHERE user_id = ? AND product_id = ?',
      [userId, productId]
    );
    res.sendStatus(204);
  } catch (e) {
    console.error(e);
    res.sendStatus(500);
  }
});


const PORT = process.env.PORT || 4000;
app.listen(PORT, () =>
  console.log(`API on port ${PORT}`)
);
