// Application setup
const express = require('express');
const cors = require('cors');
const dotenv = require('dotenv');
const passport = require('passport');
const authRoutes = require('./routes/authRoutes');
const { connectDB } = require('./config/db');
const cookieParser = require('cookie-parser');

dotenv.config();

const app = express();
app.use(express.json());
app.use(cookieParser());
app.use(cors({
    origin: "http://localhost:3000", // Frontend origin
    credentials: true, // Allow credentials
  })
);

// Connect to Database
connectDB();

// Routes
app.use('/auth', authRoutes);

module.exports = app;