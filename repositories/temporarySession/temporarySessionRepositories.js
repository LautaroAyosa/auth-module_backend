// I'm currently only doing 3 actions with the refresh token: save, find, and delete.

// Postgres implementation of the refresh token repository.
class PostgresTemporarySessionRepository {
    constructor(TemporarySessionModel) {
        this.TemporarySessionModel = TemporarySessionModel;
    }

    // Create a new refresh token in the PostgreSQL database.
    async createTemporarySession(data) {
        return await this.TemporarySessionModel.create({ 
            sessionId: data.sessionId,
            userId: data.userId
        });
    }

    // Find a sessionId.
    async findTemporarySession(data) {
        return await this.TemporarySessionModel.findOne({ where: { sessionId: data.sessionId } });
    }

    // Delete a sessionId
    async deleteTemporarySession(data) {
        return await this.TemporarySessionModel.destroy({ where: { sessionId: data.sessionId } });
    }
}


// Mongo implementation of the refresh token repository.
class MongoTemporarySessionRepository {     
    constructor(TemporarySessionModel) {
        this.TemporarySessionModel = TemporarySessionModel;
    }

    // Create a new refresh token in the MongoDB database.
    async createTemporarySession(data) {
        return await this.TemporarySessionModel.create({
            sessionId: data.sessionId,
            userId: data.userId
        });
    }

    // Find a token by the token string.
    async findTemporarySession(data) {
        return await this.TemporarySessionModel.findOne({ sessionId: data.sessionId });
    }

    // Delete token by token string
    async deleteTemporarySession(data) {
        return await this.TemporarySessionModel.deleteOne({ sessionId: data.sessionId });
    }
}

module.exports = { PostgresTemporarySessionRepository, MongoTemporarySessionRepository };