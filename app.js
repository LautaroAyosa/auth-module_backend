require('dotenv').config();
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const { connectDB } = require('./config/db');

function createApp() {
  const app = express();
  app.use(express.json());
  app.use(cookieParser());
  app.use(cors({
    origin: process.env.FRONTEND_CORS_URL,
    credentials: true,
  }));
  return app;
}

async function initializeApp(dbConfig) {
  const app = createApp();
  await connectDB(dbConfig);
  const { createRepositories } = require('./repositories/repositoryFactory');
  const repositories = await createRepositories(dbConfig);
  const authRoutes = require('./routes/authRoutes')(repositories);
  app.use('/auth', authRoutes);
  return app;
}

module.exports = { initializeApp, createApp };
