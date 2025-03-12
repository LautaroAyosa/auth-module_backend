module.exports = (sequelize, DataTypes) => {
    const temporarySession = sequelize.define('temporary_session', {
      sessionId: { type: DataTypes.STRING, allowNull: false, unique: true },
      // createdAt will be managed automatically; to simulate auto-expiry you may use a cron job or database job
    }, {
      timestamps: true,
      tableName: 'temporary_sessions',
    });
  
    temporarySession.associate = (models) => {
      temporarySession.belongsTo(models.user, { foreignKey: 'userId' });
    };
  
    return temporarySession;
};
