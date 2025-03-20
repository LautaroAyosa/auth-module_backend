'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.createTable('email_verification_token', {
      id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
      token: { type: Sequelize.STRING, allowNull: false, unique: true },
      newEmail: { type: Sequelize.STRING, allowNull: false },
      expiresAt: { type: Sequelize.DATE, allowNull: false },
      userId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: { model: 'users', key: 'id' },
        onDelete: 'CASCADE'
      },
    })
  },

  async down (queryInterface, Sequelize) {
    await queryInterface.dropTable('email_verification_token')
  }
};
