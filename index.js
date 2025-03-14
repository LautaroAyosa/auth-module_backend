const { initializeApp } = require('./app');
const PORT = process.env.PORT || 5000;

initializeApp().then(app => {
  app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
}).catch(console.error);
