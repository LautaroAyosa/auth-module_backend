const { sequelize } = require("../../config/postgres");

// I'm currently only doing 3 actions with the refresh token: save, find, and delete.


// Postgres implementation of the refresh token repository.
class PostgresEmailVerificationTokenRepository {
    constructor(EmailVerificationTokenModel) {
        this.EmailVerificationTokenModel = EmailVerificationTokenModel;
    }

    // Create a new refresh token in the PostgreSQL database.
    async createToken(data) {
        return this.EmailVerificationTokenModel.create({ 
            token: data.token, 
            newEmail: data.newEmail,
            expiresAt: data.expiresAt,
            userId: data.userId
        });
    }

    // Find a refresh token by the token string.
    async findToken({token}) {
        return this.EmailVerificationTokenModel.findOne({ where: { token: token } });
    }

    // Delete a refresh token by the token string.
    async deleteToken({token}) {
        return this.EmailVerificationTokenModel.destroy({ where: { token: token } });
    }

    async deleteManyFromUser({userId}) {
        return this.EmailVerificationTokenModel.destroy({ where: { userId: userId }})
    }
}


// Mongo implementation of the refresh token repository.
class MongoEmailVerificationTokenRepository {     
    constructor(EmailVerificationTokenModel) {
        this.EmailVerificationTokenModel = EmailVerificationTokenModel;
    }

    // Create a new refresh token in the MongoDB database.
    async createToken({token, userId, newEmail, expiresAt}) {
        return await this.EmailVerificationTokenModel.create({
            token: token,
            userId: userId,
            newEmail: newEmail,
            expiresAt: expiresAt
        });
    }

    // Find a token by the token string.
    async findToken({token}) {
        return await this.EmailVerificationTokenModel.findOne({ token: token });
    }

    // Delete token by token string
    async deleteToken({token}) {
        return await this.EmailVerificationTokenModel.deleteOne({ token: token });
    }

    async deleteManyFromUser({userId}) {
        return await this.EmailVerificationTokenModel.deleteMany({ userId: userId })
    }
}

module.exports = { PostgresEmailVerificationTokenRepository, MongoEmailVerificationTokenRepository };