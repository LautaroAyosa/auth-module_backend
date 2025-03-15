const mongoose = require('mongoose');

module.exports = async () => {
    const dbType = process.env.DB_TYPE || 'postgres';
    if (dbType === 'mongo') {

      const collections = await mongoose.connection.db.collections();
      for (let collection of collections) {
        await collection.deleteMany({});
      }
      await mongoose.disconnect();
      
    } else {
      const { rollbackMigrations } = require('./postgres/setupTestDB');
      const { disconnectPostgres } = require('../config/postgres');
      // Disconnect from postgres after tests finish
      await rollbackMigrations();
      await disconnectPostgres();
    }
  };
  