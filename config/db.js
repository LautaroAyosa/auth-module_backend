const mongoose = require('mongoose');
const { Pool } = require('pg');

const connectDB = async () => {
    if (process.env.DB_TYPE === 'mongo') {
        try {
            await mongoose.connect(process.env.MONGO_URI);
            console.log('MongoDB Connected');
        } catch (err) {
            console.error('MongoDB Connection Error:', err);
        }
    } else {
        try {
            const pool = new Pool({ connectionString: process.env.PG_URI });
            await pool.connect();
            console.log('PostgreSQL Connected');
        } catch (err) {
            console.error('PostgreSQL Connection Error:', err);
        }
    }
};

module.exports = { connectDB };