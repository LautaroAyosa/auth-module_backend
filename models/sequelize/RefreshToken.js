module.exports = (sequelize, DataTypes) => {
    const RefreshToken = sequelize.define('refresh_token', {
      token: { type: DataTypes.STRING, allowNull: false, unique: true },
      expiresAt: { type: DataTypes.DATE, allowNull: false },
    }, {
      timestamps: true,
      tableName: 'refresh_tokens',
    });
  
    RefreshToken.associate = (models) => {
      RefreshToken.belongsTo(models.User, { foreignKey: 'userId', onDelete: 'CASCADE' });
    };
  
    return RefreshToken;
  };
  