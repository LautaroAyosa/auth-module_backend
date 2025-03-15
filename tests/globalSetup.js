const { initializeApp } = require('../app');

module.exports = async () => {
    const dbType = process.env.DB_TYPE || 'postgres';
    let app
    if (dbType === 'mongo') {
      // Run Mongo Setup
      app = await initializeApp({ dbType: 'mongo', mongoUri: process.env.MONGO_TEST_URI });

    } else {
      // Run Postgres Setup
      const { runMigrations, runSeeders } = require('./postgres/setupTestDB');
      app = await initializeApp({
        dbType: 'postgres',
        pgName: 'test_db',
        pgUri: 'postgres://postgres:3RNMCw%23F@localhost:5432/test_db'
      });
      await runMigrations();
      await runSeeders();
    }

    global.__APP__ = app;
  };
  