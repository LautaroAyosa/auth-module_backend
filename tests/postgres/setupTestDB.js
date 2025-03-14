// tests/postgres/setupTestDB.js
const { execSync } = require('child_process');

const runMigrations = () => {
  execSync('npm run db:migrations', { stdio: 'inherit' });
};

const runSeeders = () => {
  execSync('npm run db:seeders', { stdio: 'inherit' });
};

const rollbackMigrations = () => {
  execSync('npm run db:migrations:undo', { stdio: 'inherit' });
};

module.exports = { runMigrations, runSeeders, rollbackMigrations };
