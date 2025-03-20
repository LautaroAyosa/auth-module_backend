module.exports = (sequelize, DataTypes) => {
    const EmailVerificationToken = sequelize.define('email_verification_token', {
      token: { type: DataTypes.STRING, allowNull: false, unique: true },
      newEmail: { type: DataTypes.STRING, allowNull: false },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
    }, {
      timestamps: false,
      tableName: 'email_verification_token',
    });
  
    // A foreign key to User will be set up via associations
    EmailVerificationToken.associate = (models) => {
        EmailVerificationToken.belongsTo(models.User, { foreignKey: 'userId', onDelete: 'CASCADE' });
    };
  
    return EmailVerificationToken;
  };
  