const { Sequelize, DataTypes } = require('sequelize');
const config = require('./config.js')[process.env.NODE_ENV || 'development'];

let sequelize;
let dbModels;

const createSequelizeInstance = (pgUri) => {
  if (pgUri) {
    return new Sequelize(pgUri, { dialect: 'postgres', logging: false });
  }
  if (process.env.NODE_ENV === 'production' && config.use_env_variable) {
    return new Sequelize(process.env[config.use_env_variable], { dialect: config.dialect, logging: false });
  }
  return new Sequelize(config.database, config.username, config.password, {
    host: config.host,
    dialect: config.dialect,
    logging: false,
  });
};

const loadModels = (sequelize) => {
    // Import models
  const User = require('../models/sequelize/User')(sequelize, DataTypes);
  const PasswordResetToken = require('../models/sequelize/PasswordResetToken')(sequelize, DataTypes);
  const RefreshToken = require('../models/sequelize/RefreshToken')(sequelize, DataTypes);
  const TemporarySession = require('../models/sequelize/TemporarySession')(sequelize, DataTypes);

  // Set up associations
  RefreshToken.belongsTo(User, { foreignKey: 'userId' });
  PasswordResetToken.belongsTo(User, { foreignKey: 'userId' });
  TemporarySession.belongsTo(User, { foreignKey: 'userId' });
  // const models = {};
  // ['User', 'PasswordResetToken', 'RefreshToken', 'TemporarySession'].forEach(modelName => {
  //   models[modelName] = require(`../models/sequelize/${modelName}`)(sequelize, DataTypes);
  // });
  // console.log(models);
  // Object.values(models).forEach(model => {
  //   if (model.associate) model.associate(models);
  // });

  models = {
    User,
    PasswordResetToken,
    RefreshToken,
    TemporarySession
  };
  return models;
};

const connectPostgres = async (dbConfig) => {
  try {
    sequelize = createSequelizeInstance(dbConfig?.pgUri);
    dbModels = loadModels(sequelize);
    await sequelize.authenticate();
    console.log('✅ PostgreSQL Connected via Sequelize to', dbConfig?.pgName || config.database);
  } catch (err) {
    console.error('❌ PostgreSQL Connection Error:', err);
  }
};

const disconnectPostgres = async () => {
  await sequelize.close();
};

const getModels = () => dbModels;

module.exports = { sequelize, connectPostgres, getModels, disconnectPostgres };
