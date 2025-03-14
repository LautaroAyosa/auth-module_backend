module.exports = (sequelize, DataTypes) => {
    const PasswordResetToken = sequelize.define('password_reset_token', {
      token: { type: DataTypes.STRING, allowNull: false, unique: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
    }, {
      timestamps: false,
      tableName: 'password_reset_token',
    });
  
    // A foreign key to User will be set up via associations
    PasswordResetToken.associate = (models) => {
      PasswordResetToken.belongsTo(models.User, { foreignKey: 'userId', onDelete: 'CASCADE' });
    };
  
    return PasswordResetToken;
  };
  