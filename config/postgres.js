// PostgreSQL setup
const { Sequelize, DataTypes } = require('sequelize');
const config = require('../config/config.js')[process.env.NODE_ENV || 'development']; // Load correct env config

let sequelize

// Check if `use_env_variable` is set (for production)
if (process.env.NODE_ENV === 'production' && config.use_env_variable) {
    sequelize = new Sequelize(process.env[config.use_env_variable], {
      dialect: config.dialect,
      logging: false, 
    });
  } else {
    sequelize = new Sequelize(config.database, config.username, config.password, {
      host: config.host,
      dialect: config.dialect,
      logging: false,
    });
  }

const dbModels = {};

// Import models
dbModels.User = require('../models/sequelize/User')(sequelize, DataTypes);
dbModels.PasswordResetToken = require('../models/sequelize/PasswordResetToken')(sequelize, DataTypes);
dbModels.RefreshToken = require('../models/sequelize/RefreshToken')(sequelize, DataTypes);
dbModels.TemporarySession = require('../models/sequelize/TemporarySession')(sequelize, DataTypes);

// Run model associations
Object.keys(dbModels).forEach((modelName) => {
  if (dbModels[modelName].associate) {
    dbModels[modelName].associate(dbModels);
  }
});

// Connect to PostgreSQL
const connectPostgres = async () => {
  try {
    await sequelize.authenticate(); // Test connection only
    console.log('✅ PostgreSQL Connected via Sequelize to ', config.database);
  } catch (err) {
    console.error('❌ PostgreSQL Connection Error:', err);
  }
};

const getModels = () => dbModels;

// Export Sequelize for CLI and app use
module.exports = { sequelize, connectPostgres, getModels };
