'use strict';

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    await queryInterface.createTable('temporary_sessions', {
      id: { type: Sequelize.INTEGER, primaryKey: true, autoIncrement: true },
      sessionId: { type: Sequelize.STRING, allowNull: false, unique: true },
      userId: {
        type: Sequelize.INTEGER,
        allowNull: false,
        references: { model: 'users', key: 'id' }, // 👈 Foreign Key
        onDelete: 'CASCADE'
      },
      createdAt: { type: Sequelize.DATE, allowNull: false },
      updatedAt: { type: Sequelize.DATE, allowNull: false },
    })
  },

  async down (queryInterface, Sequelize) {
    await queryInterface.dropTable('temporary_sessions')
  }
};
