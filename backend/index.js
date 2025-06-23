// --- 1. IMPORTS & SETUP ---
const express = require('express');
const cors = require('cors');
const { MongoClient, ServerApiVersion, ObjectId } = require('mongodb');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const { body, validationResult } = require('express-validator');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { OAuth2Client } = require('google-auth-library');
require('dotenv').config();

const app = express();
const port = process.env.PORT || 5000;

// --- 2. MIDDLEWARE ---
app.use(helmet()); // Adds security headers
app.use(cors({ origin: 'http://localhost:3000' })); // Restrict to frontend origin
app.use(express.json());
app.use(
  rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per windowMs
  })
);

// --- 3. DATABASE CONNECTION ---
const uri =
  process.env.DB_URI ||
  `mongodb+srv://${process.env.DB_USER}:${process.env.DB_PASS}@cluster0.nqxpuoo.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0`;

const client = new MongoClient(uri, {
  serverApi: {
    version: ServerApiVersion.v1,
    strict: true,
    deprecationErrors: true,
  },
});

// --- 4. JWT VERIFICATION MIDDLEWARE ---
const verifyJWT = (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).send({ message: 'unauthorized access' });
  }
  const token = authHeader.split(' ')[1];

  jwt.verify(token, process.env.JWT_SECRET, (err, decoded) => {
    if (err) {
      console.error('JWT Verification Error:', err.message);
      return res.status(403).send({ message: 'forbidden access' });
    }
    req.decoded = decoded;
    next();
  });
};

// --- 5. GOOGLE OAUTH CLIENT ---
const googleClient = new OAuth2Client({
  clientId: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  redirectUri: 'http://localhost:3000/api/auth/callback/google',
});

// --- 6. MAIN API LOGIC ---
async function run() {
  try {
    // Connect to MongoDB
    await client.connect();
    console.log('Successfully connected to MongoDB Atlas!');

    // Define collections with indexes
    const db = client.db('Nextstock');
    const usersCollection = db.collection('users');
    await usersCollection.createIndex({ email: 1 }, { unique: true });
    const productsCollection = db.collection('products');
    const ordersCollection = db.collection('orders');

    // =================================================================
    // AUTHENTICATION ROUTES
    // =================================================================

    // POST /api/auth/register
    app.post(
      '/api/auth/register',
      [
        body('email').isEmail().normalizeEmail(),
        body('password').isLength({ min: 6 }),
        body('name').notEmpty(),
      ],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty())
          return res.status(400).send({ message: errors.array() });

        const { name, email, password, role } = req.body;
        const salt = await bcrypt.genSalt(10);
        const hashedPassword = await bcrypt.hash(password, salt);

        const existingUser = await usersCollection.findOne({ email });
        if (existingUser) {
          return res
            .status(400)
            .send({ message: 'User with this email already exists.' });
        }

        const newUser = {
          name,
          email,
          password: hashedPassword,
          role: role || 'buyer',
          createdAt: new Date(),
        };

        const result = await usersCollection.insertOne(newUser);
        const token = jwt.sign(
          { user: { id: result.insertedId } },
          process.env.JWT_SECRET,
          { expiresIn: '5h' }
        );
        res.send({ success: true, token, user: { name, email, role } });
      }
    );

    // POST /api/auth/login
    app.post(
      '/api/auth/login',
      [body('email').isEmail().normalizeEmail(), body('password').exists()],
      async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty())
          return res.status(400).send({ message: errors.array() });

        const { email, password } = req.body;
        const user = await usersCollection.findOne({ email });

        if (!user)
          return res.status(401).send({ message: 'Invalid credentials' });
        if (!(await bcrypt.compare(password, user.password)))
          return res.status(401).send({ message: 'Invalid credentials' });

        const token = jwt.sign(
          { user: { id: user._id } },
          process.env.JWT_SECRET,
          { expiresIn: '5h' }
        );
        res.send({
          success: true,
          token,
          user: { name: user.name, role: user.role, email },
        });
      }
    );

    // POST /api/auth/callback/google
    app.post('/api/auth/callback/google', async (req, res) => {
      console.log('Google callback received:', req.body);
      const { code, id_token } = req.body; // Expect id_token from the signIn event
      if (!id_token) {
        console.error('No id_token provided in request body');
        return res.status(400).send({ message: 'No id_token provided' });
      }

      try {
        const ticket = await googleClient.verifyIdToken({
          idToken: id_token,
          audience: process.env.GOOGLE_CLIENT_ID,
        });
        const payload = ticket.getPayload();
        const { email, name } = payload;
        console.log('User payload from Google:', { email, name });

        let user = await usersCollection.findOne({ email });
        console.log('Existing user found:', user ? 'Yes' : 'No');

        if (!user) {
          const newUser = {
            name,
            email,
            password: await bcrypt.hash(Date.now().toString(), 10), // Temporary password
            role: 'buyer',
            createdAt: new Date(),
          };
          console.log('Inserting new user:', newUser);
          const result = await usersCollection.insertOne(newUser);
          console.log('Insert result:', result);
          if (!result.insertedId) {
            throw new Error('Failed to insert new user');
          }
          user = await usersCollection.findOne({ _id: result.insertedId });
          console.log('New user after insert:', user);
        }

        const token = jwt.sign(
          { user: { id: user._id } },
          process.env.JWT_SECRET,
          { expiresIn: '5h' }
        );
        console.log('JWT token generated:', token);
        res.send({
          success: true,
          token,
          user: { name, email, role: user.role },
        });
      } catch (err) {
        console.error('Google Auth Error:', err.message, err.stack);
        res.status(500).send({
          message: 'Google authentication failed',
          error: err.message,
        });
      }
    });

    // =================================================================
    // PRODUCT ROUTES
    // =================================================================

    // GET /api/products (Get all unsold products with pagination)
    app.get('/api/products', async (req, res) => {
      const page = parseInt(req.query.page) || 1;
      const limit = parseInt(req.query.limit) || 10;
      const query = { sold: { $ne: true } };
      const products = await productsCollection
        .find(query)
        .skip((page - 1) * limit)
        .limit(limit)
        .toArray();
      res.send(products);
    });

    // GET /api/products/:id (Get a single product with ID validation)
    app.get('/api/products/:id', async (req, res) => {
      const id = req.params.id;
      if (!ObjectId.isValid(id))
        return res.status(400).send({ message: 'Invalid product ID' });
      const query = { _id: new ObjectId(id) };
      const product = await productsCollection.findOne(query);
      if (!product)
        return res.status(404).send({ message: 'Product not found' });
      res.send(product);
    });

    // POST /api/products (Create a new product, protected)
    app.post('/api/products', verifyJWT, async (req, res) => {
      const productData = req.body;
      const userId = req.decoded.user.id;

      const user = await usersCollection.findOne({ _id: new ObjectId(userId) });
      if (user.role !== 'seller') {
        return res
          .status(403)
          .send({ message: 'Forbidden: Only sellers can post products.' });
      }

      const newProduct = {
        ...productData,
        sellerId: new ObjectId(userId),
        sold: false,
        createdAt: new Date(),
      };

      const result = await productsCollection.insertOne(newProduct);
      res.send(result);
    });

    // =================================================================
    // ORDER & PURCHASE ROUTES
    // =================================================================

    // POST /api/orders/buy/:productId (Purchase a product with status)
    app.post('/api/orders/buy/:productId', verifyJWT, async (req, res) => {
      const productId = req.params.productId;
      const buyerId = req.decoded.user.id;

      const product = await productsCollection.findOne({
        _id: new ObjectId(productId),
      });
      if (!product)
        return res.status(404).send({ message: 'Product not found.' });
      if (product.sold)
        return res
          .status(400)
          .send({ message: 'Product has already been sold.' });
      if (product.sellerId.toString() === buyerId)
        return res
          .status(400)
          .send({ message: "You can't buy your own product." });

      const newOrder = {
        productId: new ObjectId(productId),
        buyerId: new ObjectId(buyerId),
        sellerId: product.sellerId,
        purchasePrice: product.price,
        status: 'completed',
        createdAt: new Date(),
      };

      const orderResult = await ordersCollection.insertOne(newOrder);

      const filter = { _id: new ObjectId(productId) };
      const updateDoc = { $set: { sold: true } };
      await productsCollection.updateOne(filter, updateDoc);

      res.send({
        success: true,
        message: 'Purchase successful!',
        orderId: orderResult.insertedId,
        digitalContent: product.digitalContent,
      });
    });

    // GET /api/orders/my-orders (Get a user's purchase history)
    app.get('/api/orders/my-orders', verifyJWT, async (req, res) => {
      const buyerId = req.decoded.user.id;
      const query = { buyerId: new ObjectId(buyerId) };
      const myOrders = await ordersCollection.find(query).toArray();
      res.send(myOrders);
    });
  } catch (err) {
    console.error('Server error:', err);
    process.exit(1);
  }
}

(async () => {
  try {
    await run();
  } catch (err) {
    console.error('Initial server error:', err);
    process.exit(1);
  }
})();

// --- 7. ROOT ROUTE & SERVER LISTEN ---
app.get('/', (req, res) => {
  res.send('Nextstock Server is Running!');
});

app
  .listen(port, () => {
    console.log(`Nextstock server is running on port ${port}`);
  })
  .on('error', (err) => {
    console.error('Server start error:', err);
  });
