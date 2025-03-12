module.exports = (sequelize, DataTypes) => {
    const refreshToken = sequelize.define('refresh_token', {
      token: { type: DataTypes.STRING, allowNull: false, unique: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
    }, {
      timestamps: true,
      tableName: 'refresh_tokens',
    });
  
    refreshToken.associate = (models) => {
      refreshToken.belongsTo(models.user, { foreignKey: 'userId' });
    };
  
    return refreshToken;
  };
  