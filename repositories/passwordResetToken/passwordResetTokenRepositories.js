// I'm currently only doing 3 actions with the refresh token: save, find, and delete.

// Postgres implementation of the refresh token repository.
class PostgresPasswordResetTokenRepository {
    constructor(PasswordResetTokenModel) {
        this.PasswordResetTokenModel = PasswordResetTokenModel;
    }

    // Create a new refresh token in the PostgreSQL database.
    async createPasswordResetToken(data) {
        return await this.PasswordResetTokenModel.create({ 
            token: data.token, 
            expiresAt: data.expiresAt, 
            userId: data.userId });
    }

    // Find a refresh token by the token string.
    async findPasswordResetToken({token}) {
        return await this.PasswordResetTokenModel.findOne({ where: { token: token } });
    }

    // Delete a refresh token by the token string.
    async deletePasswordResetToken({token}) {
        return await this.PasswordResetTokenModel.destroy({ where: { token: token } });
    }

    async deleteManyFromUser({userId}) {
        return await this.PasswordResetTokenModel.destroy({ where: { userId: userId }})
    }
}


// Mongo implementation of the refresh token repository.
class MongoPasswordResetTokenRepository {     
    constructor(PasswordResetTokenModel) {
        this.PasswordResetTokenModel = PasswordResetTokenModel;
    }

    // Create a new refresh token in the MongoDB database.
    async createPasswordResetToken({token, userId, expiresAt}) {
        return await this.PasswordResetTokenModel.create({
            token: token,
            userId: userId,
            expiresAt: expiresAt
        });
    }

    // Find a token by the token string.
    async findPasswordResetToken({token}) {
        return await this.PasswordResetTokenModel.findOne({ token: token });
    }

    // Delete token by token string
    async deletePasswordResetToken({token}) {
        return await this.PasswordResetTokenModel.deleteOne({ token: token });
    }

    async deleteManyFromUser({userId}) {
        return await this.PasswordResetTokenModel.deleteMany({ userId: userId })
    }
}

module.exports = { PostgresPasswordResetTokenRepository, MongoPasswordResetTokenRepository };