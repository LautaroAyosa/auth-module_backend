// Config file for migrations and seeders.
require('dotenv').config();

module.exports = {
  development: {
    username: process.env.PG_USER,
    password: process.env.PG_PASS,
    database: process.env.PG_DB_NAME,
    host: process.env.PG_HOST,
    dialect: 'postgres',
  },
  test: {
    username: process.env.PG_USER,
    password: process.env.PG_PASS,
    database: process.env.PG_DB_NAME,
    host: process.env.PG_HOST,
    dialect: 'postgres',
  },
  production: {
    use_env_variable: 'PG_URI',
    dialect: 'postgres',
  },
};
