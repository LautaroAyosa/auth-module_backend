// Connect to the appropriate database
// This function is called in the main server file

const connectDB = async (dbConfig) => {
  // Accepts configuration parameters to not solely rely on env variables. (needed for testing).
  const dbType = dbConfig?.dbType || process.env.DB_TYPE;
  if (dbType === 'mongo') {
    // Connect to Mongo
    const { connectMongo } = require('./mongo');
    await connectMongo(dbConfig?.mongoUri || process.env.MONGO_URI);
    
  } else if (dbType === 'postgres') {
    // "Connect" to postgres.
    const { connectPostgres } = require('./postgres');
    await connectPostgres(dbConfig);

  } else {
    // Otherwise, show error and stop operations.
    console.error('Invalid DB_TYPE, Please set a valid database type in the .env file');
    process.exit(1);
  }
};

module.exports = { connectDB };