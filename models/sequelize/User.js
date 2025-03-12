module.exports = (sequelize, DataTypes) => {
    return sequelize.define('user', {
      id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
      },
      name: { type: DataTypes.STRING, allowNull: false },
      email: { type: DataTypes.STRING, unique: true, allowNull: false },
      password: DataTypes.STRING,
      googleId: { type: DataTypes.STRING, unique: true, allowNull: true },
      role: { type: DataTypes.ENUM('user', 'admin'), defaultValue: 'user' },
      mfaEnabled: { type: DataTypes.BOOLEAN, defaultValue: false },
      mfaSecret: DataTypes.STRING,
      recoveryCode: DataTypes.STRING,
    }, {
      timestamps: true,
      tableName: 'users',
    });
  };
  