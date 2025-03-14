'use strict';
require('dotenv').config();
const bcrypt = require('bcryptjs');

/** @type {import('sequelize-cli').Migration} */
module.exports = {
  async up (queryInterface, Sequelize) {
    if (!process.env.ADMIN_PASS || !process.env.ADMIN_NAME || !process.env.ADMIN_EMAIL) {
      throw new Error("ADMIN Credentials are not set in the .env file! Seeder aborted.");
    }

    const hashedPassword = await bcrypt.hash(process.env.ADMIN_PASS , 10);

    await queryInterface.bulkInsert('users', [
      {
        name: process.env.ADMIN_NAME,
        email: process.env.ADMIN_EMAIL,
        password: hashedPassword,
        role: 'admin',
        mfaEnabled: false,
        createdAt: new Date(),
        updatedAt: new Date(),
      }
    ]);
  },

  async down (queryInterface, Sequelize) {
    await queryInterface.bulkDelete('users', { email: process.env.ADMIN_EMAIL }, {});
  }
};
