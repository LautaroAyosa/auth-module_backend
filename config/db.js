// Connect to the appropriate database
// This function is called in the main server file

const connectDB = async () => {
  if (process.env.DB_TYPE === 'mongo') {
    const { connectMongo } = require('./mongo');
    await connectMongo();
  } else if (process.env.DB_TYPE === 'postgres') {
    const { connectPostgres } = require('./postgres');
    await connectPostgres();
  } else {
    console.error('Invalid DB_TYPE, Please set a valid database type in the .env file');
    process.exit(1);
  }
};

module.exports = { connectDB };