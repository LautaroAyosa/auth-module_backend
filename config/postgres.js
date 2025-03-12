// PostgreSQL setup
const { Sequelize, DataTypes } = require('sequelize');
let sequelize;
let dbModels = {};

const connectPostgres = async () => {
  try {
    // Initialize Sequelize
    sequelize = new Sequelize(process.env.PG_URI, {
      dialect: 'postgres',
      logging: false, // disable logging if desired
    });

    // Import models
    const User = require('../models/sequelize/User')(sequelize, DataTypes);
    const PasswordResetToken = require('../models/sequelize/PasswordResetToken')(sequelize, DataTypes);
    const RefreshToken = require('../models/sequelize/RefreshToken')(sequelize, DataTypes);
    const TemporarySession = require('../models/sequelize/TemporarySession')(sequelize, DataTypes);

    // Set up associations
    RefreshToken.belongsTo(User, { foreignKey: 'userId' });
    PasswordResetToken.belongsTo(User, { foreignKey: 'userId' });
    TemporarySession.belongsTo(User, { foreignKey: 'userId' });

    // Sync models with the database
    await sequelize.sync();
    console.log('PostgreSQL Connected via Sequelize');

    // Store references in dbModels
    dbModels = {
      User,
      PasswordResetToken,
      RefreshToken,
      TemporarySession
    };
  } catch (err) {
    console.error('PostgreSQL Connection Error:', err);
  }
};

const getModels = () => dbModels;

module.exports = { connectPostgres, sequelize, getModels };