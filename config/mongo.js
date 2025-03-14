// MongoDB setup 
const mongoose = require('mongoose');
const connectMongo = async (mongoUri) => {
  try {
    await mongoose.connect(mongoUri);
    console.log('MongoDB Connected');
  } catch (err) {
    console.error('MongoDB Connection Error:', err);
  }
};

const disconnectMongo = async () => {
  await mongoose.disconnect();
};

module.exports = { connectMongo, disconnectMongo }