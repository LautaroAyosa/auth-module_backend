module.exports = (sequelize, DataTypes) => {
    const passwordResetToken = sequelize.define('password_reset_token', {
      token: DataTypes.STRING,
      expiresAt: DataTypes.DATE,
    }, {
      timestamps: false,
      tableName: 'password_reset_tokens',
    });
  
    // A foreign key to User will be set up via associations
    passwordResetToken.associate = (models) => {
      passwordResetToken.belongsTo(models.user, { foreignKey: 'userId' });
    };
  
    return passwordResetToken;
  };
  