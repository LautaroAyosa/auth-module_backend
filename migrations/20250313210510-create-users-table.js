'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.createTable('users', {
      id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
      name: { type: Sequelize.STRING, allowNull: false },
      email: { type: Sequelize.STRING, unique: true, allowNull: false },
      password: { type: Sequelize.STRING },
      googleId: { type: Sequelize.STRING, unique: true, allowNull: true },
      role: { type: Sequelize.ENUM('user', 'admin'), defaultValue: 'user' },
      mfaEnabled: { type: Sequelize.BOOLEAN, defaultValue: false },
      mfaSecret: { type: Sequelize.STRING },
      recoveryCode: { type: Sequelize.STRING },
      createdAt: { type: Sequelize.DATE, allowNull: false },
      updatedAt: { type: Sequelize.DATE, allowNull: false },
    })
  },

  async down (queryInterface, Sequelize) {
    await queryInterface.dropTable('users');
  }
};
