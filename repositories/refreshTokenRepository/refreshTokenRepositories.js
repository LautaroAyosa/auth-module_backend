// I'm currently only doing 3 actions with the refresh token: save, find, and delete.

// Postgres implementation of the refresh token repository.
class PostgresRefreshTokenRepository {
    constructor(RefreshTokenModel) {
        this.RefreshTokenModel = RefreshTokenModel;
    }

    // Create a new refresh token in the PostgreSQL database.
    async createRefreshToken(data) {
        return await this.RefreshTokenModel.create(data); 
    }

    // Find a refresh token by the token string.
    async findRefreshToken(data) {
        return await this.RefreshTokenModel.findOne({ where: { token: data.token } });
    }

    // Delete a refresh token by the token string.
    async deleteRefreshToken(data) {
        return await this.RefreshTokenModel.destroy({ where: { token: data.token } });
    }
}


// Mongo implementation of the refresh token repository.
class MongoRefreshTokenRepository {     
    constructor(RefreshTokenModel) {
        this.RefreshTokenModel = RefreshTokenModel;
    }

    // Create a new refresh token in the MongoDB database.
    async createRefreshToken(data) {
        return await this.RefreshTokenModel.create(data);
    }

    // Find a token by the token string.
    async findRefreshToken(data) {
        return await this.RefreshTokenModel.findOne({token: data.token});
    }

    // Delete token by token string
    async deleteRefreshToken(data) {
        return await this.RefreshTokenModel.deleteOne({token: data.token});
    }
}

module.exports = { PostgresRefreshTokenRepository, MongoRefreshTokenRepository };