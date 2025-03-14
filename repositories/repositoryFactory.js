const { PostgresUserRepository, MongoUserRepository } = require('./userRepository/userRepositories');
const { PostgresRefreshTokenRepository, MongoRefreshTokenRepository } = require('./refreshTokenRepository/refreshTokenRepositories');
const { PostgresTemporarySessionRepository, MongoTemporarySessionRepository } = require('./temporarySession/temporarySessionRepositories');
const { PostgresPasswordResetTokenRepository, MongoPasswordResetTokenRepository } = require('./passwordResetToken/passwordResetTokenRepositories');
// ... import other repositories


async function createRepositories(dbConfig) {
  const dbType = dbConfig?.dbType || process.env.DB_TYPE;
  if (dbType == 'postgres') {
    // Postgres Models
    const { getModels } = require('../config/postgres');
    const { User, RefreshToken, TemporarySession, PasswordResetToken } = getModels();
    // ... import other postgres models
    return {
      userRepository: new PostgresUserRepository(User),
      refreshTokenRepository: new PostgresRefreshTokenRepository(RefreshToken),
      temporarySessionRepository: new PostgresTemporarySessionRepository(TemporarySession),
      passwordResetTokenRepository: new PostgresPasswordResetTokenRepository(PasswordResetToken),
      // ... add more repos
    };
  } else {
    // Mongoose Models
    const MongooseUser = require('../models/mongoose/User');
    const MongooseRefreshToken = require('../models/mongoose/RefreshToken');
    const MongooseTemporarySession = require('../models/mongoose/TemporarySession');
    const MongoosePasswordResetToken = require('../models/mongoose/PasswordResetToken');
    // ... import other mongoose models
    return {
      userRepository: new MongoUserRepository(MongooseUser),
      refreshTokenRepository: new MongoRefreshTokenRepository(MongooseRefreshToken),
      temporarySessionRepository: new MongoTemporarySessionRepository(MongooseTemporarySession),
      passwordResetTokenRepository: new MongoPasswordResetTokenRepository(MongoosePasswordResetToken),
      // ... add more repos
    };
  }
}

module.exports = { createRepositories };
