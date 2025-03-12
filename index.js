// Server Entrypoint

// const appInstance = require('./app');
// const PORT = process.env.PORT || 5000;
// appInstance.listen(PORT, () => console.log(`Server running on port ${PORT}`));


require('dotenv').config();
const express = require('express');
const cors = require('cors');
const passport = require('passport');
const cookieParser = require('cookie-parser');

const { connectDB } = require('./config/db')

async function startServer() {
    // 1) Connect the DB
    await connectDB();

    // 2) Now that the DB is connected the models are loaded, require and import repos
    const { createRepositories } = require('./repositories/repositoryFactory');
    const repositories = await createRepositories();

    // 3) Initialize the server
    const app = express();
    app.use(express.json());
    app.use(cookieParser());
    app.use(cors({
        origin: "http://localhost:3000", // Frontend origin
        credentials: true, // Allow credentials
    })
    );

    const authRoutes = require('./routes/authRoutes')(repositories);
    // Routes
    app.use('/auth', authRoutes);


    // 4) Finally, listen on your port
    app.listen(5000, () => {
    console.log('Server running on port 5000');
    });
}

startServer().catch(console.error);
