/**************************************
 * server.js
 **************************************/
require('dotenv').config(); // Load environment variables from .env
const express = require('express');
const session = require('express-session');
const PgSession = require('connect-pg-simple')(session);
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const cors = require('cors');
const path = require('path');

const app = express();

/**************************************
 * 1) Environment Variables
 **************************************/
const PORT = process.env.PORT || 5000;
const SESSION_SECRET = process.env.SESSION_SECRET || 'fallback_secret';

// Choose the database connection string in order of preference:
// 1. DATABASE_URL (if set directly)
// 2. DATABASE_URL_TRANSACTION_POOLER (recommended for IPv4 compatibility)
// 3. DATABASE_URL_DIRECT
// 4. DATABASE_URL_SESSION_POOLER
const DATABASE_URL =
  process.env.DATABASE_URL ||
  process.env.DATABASE_URL_TRANSACTION_POOLER ||
  process.env.DATABASE_URL_DIRECT ||
  process.env.DATABASE_URL_SESSION_POOLER;

if (!DATABASE_URL) {
  console.error('❌ No DATABASE_URL configuration found in environment variables.');
  process.exit(1);
} else {
  // Truncate the URL for logging (avoid printing full credentials)
  console.log('ℹ️ Using DATABASE_URL:', DATABASE_URL.substring(0, 30) + '...');
}

// Configure SSL based on DATABASE_SSL setting (set to "true" to enable)
const useSSL = process.env.DATABASE_SSL === 'true';

/**************************************
 * 2) Initialize PostgreSQL Pool
 **************************************/
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

// Test the connection before initializing tables
pool.connect()
  .then(client => {
    console.log('✅ Successfully connected to PostgreSQL database.');
    client.release();
  })
  .catch(err => {
    console.error('❌ Error connecting to PostgreSQL:', err.message);
    // If connection fails, exit to avoid further errors
    process.exit(1);
  });

/**************************************
 * 3) Middleware & Session Configuration
 **************************************/
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(cors({
  origin: 'http://localhost:3000', // Adjust if needed
  credentials: true,
  methods: ['GET','POST','DELETE','PUT','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization']
}));

app.use(session({
  store: new PgSession({
    pool: pool,
    tableName: 'session'
  }),
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: false, // Set to true if using HTTPS
    httpOnly: true,
    maxAge: 1000 * 60 * 60 * 24 * 7, // 1 week
    sameSite: 'lax'
  }
}));

/**************************************
 * 4) Serve Static Files
 **************************************/
app.use(express.static(path.join(__dirname, 'public')));

/**************************************
 * 5) Initialize Database & Hardcoded Users
 **************************************/
async function initializeDatabase() {
  try {
    console.log('ℹ️ Initializing database structures...');

    // Enable pgcrypto extension (if you have privileges)
    await pool.query('CREATE EXTENSION IF NOT EXISTS pgcrypto;');

    // Create users table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(255) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create orders table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.orders (
        id SERIAL PRIMARY KEY,
        user_id INTEGER REFERENCES public.users(id) NOT NULL,
        timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
        total NUMERIC(10,2) NOT NULL,
        tip NUMERIC(10,2) NOT NULL,
        payment_method VARCHAR(50) NOT NULL,
        table_number VARCHAR(50) NOT NULL,
        comments TEXT,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create order_items table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.order_items (
        id SERIAL PRIMARY KEY,
        order_id INTEGER REFERENCES public.orders(id) NOT NULL,
        name VARCHAR(255) NOT NULL,
        quantity INTEGER NOT NULL,
        price NUMERIC(10,2) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
      );
    `);

    // Create item_addons table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.item_addons (
        id SERIAL PRIMARY KEY,
        order_item_id INTEGER NOT NULL,
        name VARCHAR(255) NOT NULL,
        price NUMERIC(10,2) NOT NULL,
        created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
        CONSTRAINT item_addons_order_item_id_fkey
          FOREIGN KEY (order_item_id)
          REFERENCES public.order_items (id)
          ON DELETE RESTRICT
      );
    `);

    // Session table required by connect-pg-simple
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.session (
        "sid" varchar NOT NULL COLLATE "default" PRIMARY KEY,
        "sess" json NOT NULL,
        "expire" timestamp(6) NOT NULL
      ) WITH (OIDS=FALSE);
    `);

    // Index on session expire
    await pool.query(`
      CREATE INDEX IF NOT EXISTS "IDX_session_expire"
      ON public.session ("expire");
    `);

    // Create menu_items table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.menu_items (
        id SERIAL PRIMARY KEY,
        category_key VARCHAR(255),
        name_el VARCHAR(255),
        name_en VARCHAR(255),
        description_el TEXT,
        description_en TEXT,
        price VARCHAR(50),
        image TEXT
      );
    `);

    // Create addons table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.addons (
        id SERIAL PRIMARY KEY,
        group_id INT NOT NULL,
        addon_name_el VARCHAR(255),
        addon_name_en VARCHAR(255),
        price NUMERIC(10,2) NOT NULL
      );
    `);

    // many-to-many relationship table
    await pool.query(`
      CREATE TABLE IF NOT EXISTS public.menu_item_addons2 (
        id SERIAL PRIMARY KEY,
        menu_item_id INT NOT NULL,
        addon_id INT NOT NULL,
        CONSTRAINT mia2_menu_item_id_fkey
          FOREIGN KEY (menu_item_id)
          REFERENCES public.menu_items (id)
          ON DELETE CASCADE,
        CONSTRAINT mia2_addon_id_fkey
          FOREIGN KEY (addon_id)
          REFERENCES public.addons (id)
          ON DELETE CASCADE
      );
    `);

    // Insert hardcoded users
    const hardcodedUsers = {
      thanasis: 'thanasis123',
      dimitris: 'dimitrisPass!',
      user3: 'user3Secure#',
      dashboard_user: 'dashboardpass',
      christos: 'christosPass@',
    };

    for (const [username, password] of Object.entries(hardcodedUsers)) {
      const userCheck = await pool.query('SELECT * FROM public.users WHERE username = $1', [username]);
      if (userCheck.rows.length === 0) {
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(password, saltRounds);
        await pool.query(
          'INSERT INTO public.users (username, password_hash) VALUES ($1, $2)',
          [username, hashedPassword]
        );
        console.log(`✅ Inserted hardcoded user: ${username}`);
      } else {
        console.log(`ℹ️ User already exists: ${username}`);
      }
    }

    console.log('✅ Database initialized successfully.');
  } catch (err) {
    console.error('❌ Error initializing database:', err);
    // Exit if you want to stop the server on DB init failure
    process.exit(1);
  }
}
initializeDatabase();

/**************************************
 * 6) User Registration Route
 **************************************/
app.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password.' });
  }

  try {
    const userCheck = await pool.query('SELECT * FROM public.users WHERE username = $1', [username]);
    if (userCheck.rows.length > 0) {
      return res.status(409).json({ error: 'Username already exists.' });
    }

    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await pool.query(
      'INSERT INTO public.users (username, password_hash) VALUES ($1, $2)',
      [username, hashedPassword]
    );
    res.status(201).json({ message: 'User registered successfully.' });
  } catch (err) {
    console.error('❌ Error during registration:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/**************************************
 * 7) User Login Route
 **************************************/
app.post('/login', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Missing username or password.' });
  }

  try {
    const userResult = await pool.query('SELECT * FROM public.users WHERE username = $1', [username]);
    if (userResult.rows.length === 0) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    const user = userResult.rows[0];
    const passwordMatch = await bcrypt.compare(password, user.password_hash);
    if (!passwordMatch) {
      return res.status(401).json({ error: 'Invalid username or password.' });
    }

    // Store session data
    req.session.userId = user.id;
    req.session.username = user.username;
    res.status(200).json({ message: 'Login successful.', username: user.username });
  } catch (err) {
    console.error('❌ Error during login:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/**************************************
 * 8) User Logout Route
 **************************************/
app.post('/logout', (req, res) => {
  if (req.session) {
    req.session.destroy(err => {
      if (err) {
        console.error('❌ Error destroying session:', err);
        return res.status(500).json({ error: 'Could not log out. Please try again.' });
      } else {
        res.clearCookie('connect.sid');
        return res.status(200).json({ message: 'Logout successful.' });
      }
    });
  } else {
    res.status(200).json({ message: 'No active session.' });
  }
});

/**************************************
 * 9) Authentication Status Route
 **************************************/
app.get('/api/auth/status', (req, res) => {
  if (req.session && req.session.userId) {
    res.status(200).json({ authenticated: true, username: req.session.username });
  } else {
    res.status(200).json({ authenticated: false });
  }
});

/**************************************
 * 10) Middleware to Protect Routes
 **************************************/
function isAuthenticated(req, res, next) {
  if (req.session && req.session.userId) {
    next();
  } else {
    res.status(401).json({ error: 'Unauthorized. Please log in.' });
  }
}

/**************************************
 * 11) Fetch Menu Items + Addons (Public Endpoint)
 **************************************/
app.get('/api/menu', async (req, res) => {
  try {
    const query = `
      SELECT
        mi.id AS menu_item_id,
        mi.category_key,
        mi.name_el,
        mi.name_en,
        mi.description_el,
        mi.description_en,
        mi.price,
        mi.image,
        mia2.id AS mia2_id,
        a.id AS addon_id,
        a.group_id,
        a.addon_name_el,
        a.addon_name_en,
        a.price AS addon_price
      FROM public.menu_items mi
      LEFT JOIN public.menu_item_addons2 mia2
        ON mi.id = mia2.menu_item_id
      LEFT JOIN public.addons a
        ON mia2.addon_id = a.id
      ORDER BY mi.id ASC, mia2.id ASC
    `;
    const { rows } = await pool.query(query);

    const itemsMap = new Map();
    rows.forEach(row => {
      if (!itemsMap.has(row.menu_item_id)) {
        itemsMap.set(row.menu_item_id, {
          id: row.menu_item_id,
          category_key: row.category_key,
          name_el: row.name_el,
          name_en: row.name_en,
          description_el: row.description_el,
          description_en: row.description_en,
          price: row.price,
          image: row.image,
          addons: []
        });
      }
      if (row.addon_id) {
        itemsMap.get(row.menu_item_id).addons.push({
          addon_id: row.addon_id,
          group_id: row.group_id,
          addon_name_el: row.addon_name_el,
          addon_name_en: row.addon_name_en,
          price: row.addon_price
        });
      }
    });

    const items = Array.from(itemsMap.values());
    res.status(200).json({ items });
  } catch (err) {
    console.error('❌ Error fetching menu items with addons:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/**************************************
 * 12) Orders (Protected Routes)
 **************************************/

// GET /api/orders
app.get('/api/orders', isAuthenticated, async (req, res) => {
  try {
    let ordersResult;

    if (req.session.username === 'dashboard_user') {
      // Dashboard user sees all orders
      ordersResult = await pool.query(`
        SELECT 
          o.id,
          o.timestamp,
          u.username,
          o.total,
          o.tip,
          o.payment_method,
          o.table_number,
          o.comments,
          o.created_at,
          oi.id as order_item_id,
          oi.name as item_name,
          oi.quantity,
          oi.price as item_price,
          ia.name as addon_name,
          ia.price as addon_price
        FROM public.orders o
        JOIN public.users u ON o.user_id = u.id
        LEFT JOIN public.order_items oi ON o.id = oi.order_id
        LEFT JOIN public.item_addons ia ON oi.id = ia.order_item_id
        ORDER BY o.timestamp DESC, oi.id ASC, ia.id ASC;
      `);
    } else {
      // Only this user's orders
      ordersResult = await pool.query(`
        SELECT 
          o.id,
          o.timestamp,
          u.username,
          o.total,
          o.tip,
          o.payment_method,
          o.table_number,
          o.comments,
          o.created_at,
          oi.id as order_item_id,
          oi.name as item_name,
          oi.quantity,
          oi.price as item_price,
          ia.name as addon_name,
          ia.price as addon_price
        FROM public.orders o
        JOIN public.users u ON o.user_id = u.id
        LEFT JOIN public.order_items oi ON o.id = oi.order_id
        LEFT JOIN public.item_addons ia ON oi.id = ia.order_item_id
        WHERE o.user_id = $1
        ORDER BY o.timestamp DESC, oi.id ASC, ia.id ASC;
      `, [req.session.userId]);
    }

    const ordersMap = new Map();
    ordersResult.rows.forEach(row => {
      if (!ordersMap.has(row.id)) {
        ordersMap.set(row.id, {
          id: row.id,
          timestamp: row.timestamp,
          username: row.username,
          total: parseFloat(row.total),
          tip: parseFloat(row.tip),
          paymentMethod: row.payment_method,
          tableNumber: row.table_number,
          comments: row.comments,
          createdAt: row.created_at,
          items: []
        });
      }
      if (row.order_item_id) {
        const order = ordersMap.get(row.id);
        let item = order.items.find(i => i.id === row.order_item_id);
        if (!item) {
          item = {
            id: row.order_item_id,
            name: row.item_name,
            quantity: row.quantity,
            price: parseFloat(row.item_price),
            addOns: []
          };
          order.items.push(item);
        }
        if (row.addon_name) {
          item.addOns.push({
            name: row.addon_name,
            price: parseFloat(row.addon_price)
          });
        }
      }
    });

    const orders = Array.from(ordersMap.values());
    res.status(200).json({ orders });
  } catch (err) {
    console.error('❌ Error fetching orders:', err);
    res.status(500).json({ error: 'Internal server error.' });
  }
});

/**************************************
 * POST /api/orders Route (Custom)
 **************************************/
app.post('/api/orders', isAuthenticated, async (req, res) => {
  const { timestamp, items, tip, paymentMethod, table, comments } = req.body;
  console.log('Received Order Data:', { timestamp, items, tip, paymentMethod, table, comments });

  if (!timestamp || !items || !paymentMethod || !table) {
    return res.status(400).json({ error: 'Missing required order fields.' });
  }

  const computeTotal = (itemsArr) => {
    return itemsArr.reduce((total, item) => {
      const quantity = parseInt(item.quantity) || 1;
      const price = parseFloat(item.price) || 0;
      total += price * quantity;
      if (item.addOns && Array.isArray(item.addOns)) {
        total += item.addOns.reduce(
          (addonTotal, addon) => addonTotal + (parseFloat(addon.price) || 0),
          0
        ) * quantity;
      }
      return total;
    }, 0);
  };

  const computedTotal = computeTotal(items);
  const parsedTip = parseFloat(tip) || 0;

  if (computedTotal > 99999999.99 || parsedTip > 99999999.99 || computedTotal < 0 || parsedTip < 0) {
    return res.status(400).json({ error: 'Invalid total or tip value.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN'); // Start transaction

    // Insert into orders
    const orderResult = await client.query(
      `INSERT INTO orders (user_id, timestamp, total, tip, payment_method, table_number, comments)
       VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
      [req.session.userId, timestamp, computedTotal, parsedTip, paymentMethod, table, comments]
    );

    const orderId = orderResult.rows[0].id;
    console.log(`✅ Order inserted successfully with ID: ${orderId}`);

    // Insert order items
    for (const item of items) {
      const { name, quantity, price } = item;
      const orderItemResult = await client.query(
        `INSERT INTO order_items (order_id, name, quantity, price)
         VALUES ($1, $2, $3, $4) RETURNING id`,
        [orderId, name, quantity, price]
      );
      const orderItemId = orderItemResult.rows[0].id;
      console.log(`✅ Inserted item: ${name} with ID: ${orderItemId}`);

      // Insert add-ons for each order item
      if (item.addOns && Array.isArray(item.addOns)) {
        for (const addon of item.addOns) {
          const { name: addonName, price: addonPrice } = addon;
          await client.query(
            `INSERT INTO item_addons (order_item_id, name, price)
             VALUES ($1, $2, $3)`,
            [orderItemId, addonName, addonPrice]
          );
          console.log(`✅ Inserted add-on: ${addonName} for order item ID: ${orderItemId}`);
        }
      }
    }

    await client.query('COMMIT'); // Commit transaction
    res.status(201).json({ message: 'Order submitted successfully.' });
  } catch (err) {
    await client.query('ROLLBACK'); // Rollback transaction on error
    console.error('❌ Error submitting order:', err);
    res.status(500).json({ error: 'Internal server error.' });
  } finally {
    client.release();
  }
});

/**************************************
 * DELETE /api/orders/:id Route
 **************************************/
app.delete('/api/orders/:id', isAuthenticated, async (req, res) => {
  const orderId = parseInt(req.params.id, 10);
  if (isNaN(orderId)) {
    return res.status(400).json({ error: 'Invalid order ID.' });
  }

  const client = await pool.connect();
  try {
    await client.query('BEGIN'); // Start transaction

    // Check ownership or dashboard admin
    const orderCheck = await client.query(`
      SELECT * FROM public.orders
      WHERE id = $1 
        AND (user_id = $2 OR $3 = 'dashboard_user')
    `, [orderId, req.session.userId, req.session.username]);

    if (orderCheck.rows.length === 0) {
      await client.query('ROLLBACK');
      return res.status(404).json({ error: 'Order not found or unauthorized.' });
    }

    // Delete from item_addons
    const deleteItemAddonsQuery = `
      DELETE FROM item_addons
      WHERE order_item_id IN (
        SELECT id FROM order_items WHERE order_id = $1
      )
    `;
    await client.query(deleteItemAddonsQuery, [orderId]);

    // Delete from order_items
    const deleteOrderItemsQuery = `
      DELETE FROM order_items WHERE order_id = $1
    `;
    await client.query(deleteOrderItemsQuery, [orderId]);

    // Delete from orders
    const deleteOrdersQuery = `
      DELETE FROM orders WHERE id = $1
    `;
    const deleteOrdersResult = await client.query(deleteOrdersQuery, [orderId]);

    if (deleteOrdersResult.rowCount === 0) {
      throw new Error('Order not found or already deleted.');
    }

    await client.query('COMMIT');
    res.status(200).json({ message: 'Order and related records deleted successfully.' });
  } catch (err) {
    await client.query('ROLLBACK');
    console.error('❌ Error deleting order:', err);
    res.status(500).json({ error: 'Failed to delete order. Please try again.' });
  } finally {
    client.release();
  }
});

/**************************************
 * 13) Start the Server
 **************************************/
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});
