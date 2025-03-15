// tests/postgres/setupTestDB.js
const { execSync } = require('child_process');

const runMigrations = () => {
  execSync('npm run db:migrate', { stdio: 'inherit' });
};

const runSeeders = () => {
  execSync('npm run db:seed', { stdio: 'inherit' });
};

const rollbackMigrations = () => {
  execSync('npm run db:migrate:undo:all', { stdio: 'inherit' });
};

module.exports = { runMigrations, runSeeders, rollbackMigrations };
