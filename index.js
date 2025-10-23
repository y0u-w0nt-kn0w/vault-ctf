require('dotenv').config();
const express = require('express');
const { graphqlHTTP } = require('express-graphql');
const { buildSchema } = require('graphql');
const jwt = require('jsonwebtoken');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const _ = require('lodash');

const app = express();
const PORT = process.env.PORT || 3000;

// =====================
// Security Configuration
// =====================
app.use(helmet());
app.use(express.json({ limit: '100kb' }));
app.disable('x-powered-by');

// Fixed Rate Limiting Configuration
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: JSON.stringify({ errors: [{ message: 'Too many requests' }] }),
  standardHeaders: true,
  legacyHeaders: false
});

// =====================
// Environment Validation
// =====================
const SECRET_KEY = process.env.SECRET_KEY;
const FLAG = process.env.FLAG;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'temp_' + Math.random().toString(36).slice(2, 15);

if (!SECRET_KEY || !FLAG) {
  console.error('Missing required environment variables');
  process.exit(1);
}

// =====================
// Mock Database
// =====================
const users = [
  { id: 1, username: 'stewie', password: ADMIN_PASSWORD, role: 'admin' },
  { id: 2, username: 'admin', password: 'admin', role: 'admiin' }, // Intentional typo
  { id: 3, username: 'user1', password: 'admin123', role: 'user' }
];

const vault = [
  { id: 1, ownerId: 1, content: FLAG, isPublic: false },
  { id: 2, ownerId: 2, content: "Nothing to see here", isPublic: false },
  { id: 3, ownerId: 1, content: "Public note", isPublic: true },
  { id: 4, ownerId: 1, content: "FAKE_FLAG{dummy_flag}", isPublic: false } // Red herring
];

// =====================
// GraphQL Schema
// =====================
const schema = buildSchema(`
  type Query {
    login(username: String!, password: String!): AuthPayload
    vaultItems: [VaultItem]
    publicVaultItems: [VaultItem]
    searchVault(searchTerm: String!): [VaultItem]
  }

  type Mutation {
    createVaultItem(content: String!, isPublic: Boolean!): VaultItem
    makeVaultItemPublic(id: ID!): VaultItem
  }

  type VaultItem {
    id: ID!
    content: String!
    isPublic: Boolean!
    owner: User
  }

  type User {
    id: ID!
    username: String!
    role: String!
  }

  type AuthPayload {
    token: String!
    user: User!
  }
`);

// =====================
// Resolvers with Intentional Vulnerabilities
// =====================
const root = {
  login: ({ username, password }) => {
    const user = users.find(u => u.username === username && u.password === password);
    if (!user) throw new Error('Invalid credentials');
    
    return {
      token: jwt.sign(
        { 
          userId: user.id, 
          role: user.role,
          exp: Math.floor(Date.now() / 1000) + (60 * 60) // 1 hour expiry
        }, 
        SECRET_KEY,
        { algorithm: 'HS256' }
      ),
      user
    };
  },

  vaultItems: (_, context) => {
    if (!context.user) throw new Error('Not authenticated');
    // Intentional admin bypass vulnerability
    if (context.user.role === 'admin') return vault;
    return vault.filter(i => i.ownerId === context.user.id || i.isPublic);
  },

  publicVaultItems: () => vault.filter(i => i.isPublic),

  searchVault: ({ searchTerm }, context) => {
    // Field duplication vulnerability
    return vault.filter(i => 
      i.content.includes(searchTerm) && 
      (i.isPublic || (context.user && i.ownerId === context.user.id))
    );
  },

  createVaultItem: ({ content, isPublic }, context) => {
    if (!context.user) throw new Error('Not authenticated');
    const newItem = {
      id: vault.length + 1,
      ownerId: context.user.id,
      content,
      isPublic
    };
    vault.push(newItem);
    return newItem;
  },

  makeVaultItemPublic: ({ id }, context) => {
    if (!context.user) throw new Error('Not authenticated');
    const item = vault.find(i => i.id === parseInt(id));
    if (!item) throw new Error('Item not found');
    // Broken authorization vulnerability
    item.isPublic = true;
    return item;
  }
};

// =====================
// Authentication Middleware
// =====================
const authMiddleware = (req) => {
  const token = req.headers.authorization || '';
  try {
    if (token) {
      const decoded = jwt.verify(
        token.replace('Bearer ', ''), 
        SECRET_KEY,
        { algorithms: ['HS256'] }
      );
      return { user: users.find(u => u.id === decoded.userId) };
    }
    return {};
  } catch (e) {
    console.error('JWT Error:', e.message);
    return {};
  }
};

// =====================
// GraphQL Endpoint Configuration
// =====================
app.use('/graphql', limiter, graphqlHTTP((req) => ({
  schema: schema,
  rootValue: root,
  context: authMiddleware(req),
  graphiql: process.env.NODE_ENV === 'development',
  customFormatErrorFn: (err) => ({
    message: err.message,
    locations: err.locations,
    stack: null // Never show stack traces
  })
})));

// =====================
// Web Interface
// =====================
app.get('/', (req, res) => {
  res.send(`
    <!DOCTYPE html>
    <html>
    <head>
      <title>Vault CTF</title>
      <style>
        body { font-family: sans-serif; max-width: 800px; margin: 0 auto; padding: 20px; }
        .container { border: 1px solid #ddd; padding: 20px; border-radius: 5px; }
      </style>
    </head>
    <body>
      <div class="container">
        <h1>Vault CTF </h1>
        ${process.env.NODE_ENV === 'development' 
          ? `` 
          : ''}
        <h3>Challenge Hints:</h3>
        <ul>
          <li>Explore...</li>
        </ul>
      </div>
    </body>
    </html>
  `);
});

// =====================
// Server Startup
// =====================
app.listen(PORT, () => {
  console.log(`Server running in ${process.env.NODE_ENV || 'development'} mode`);
  console.log(`Access at: http://localhost:${PORT}`);
  if (process.env.NODE_ENV === 'development') {
    console.log(`GraphiQL: http://localhost:${PORT}/graphql`);
  }
});

process.on('unhandledRejection', (err) => {
  console.error('Unhandled rejection:', err);
});