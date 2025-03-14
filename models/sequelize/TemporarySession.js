module.exports = (sequelize, DataTypes) => {
    const TemporarySession = sequelize.define('temporary_session', {
      sessionId: { type: DataTypes.STRING, allowNull: false, unique: true },
      // createdAt will be managed automatically; to simulate auto-expiry you may use a cron job or database job
    }, {
      timestamps: true,
      tableName: 'temporary_sessions',
    });
  
    TemporarySession.associate = (models) => {
      TemporarySession.belongsTo(models.User, { foreignKey: 'userId', onDelete: 'CASCADE' });
    };
  
    return TemporarySession;
};
