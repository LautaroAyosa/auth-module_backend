// Code for the user repositories. This handles the database queries for the user entity. 
// The PostgresUserRepository class is for PostgreSQL queries, while the MongoUserRepository class is for MongoDB queries. 
// The module exports the PostgresUserRepository and MongoUserRepository classes.

// PostgreSQL Repository using Sequelize
class PostgresUserRepository {
  constructor(UserModel) {
    this.UserModel = UserModel;
  }

  async findAllUsers() {
    return this.UserModel.findAll();
  }

  async findUserById(data) {
    return this.UserModel.findByPk(data.id);
  }

  async findUserByEmail(data) {
    return await this.UserModel.findOne({ where: { email: data.email } });
  }

  async createUser(data) {
    return this.UserModel.create({
      name: data.name,
      email: data.email,
      password: data.password
    });
  }

  async updateUser(id, data) {
    const user = await this.UserModel.findByPk(id.id);
    if (!user) {
      throw new Error('User not found');
    }
    return user.update(data);
  }
}
  
// MongoDB Repository
class MongoUserRepository {
  constructor(UserModel) {
    this.UserModel = UserModel;
  }

  async findAllUsers() {
    return this.UserModel.find();
  }

  async findUserById(data) {
    return this.UserModel.findById(data.id);
  }

  async findUserByEmail(data) {
    return this.UserModel.findOne({email: data.email});
  }

  async createUser(data) {
    return this.UserModel.create(data);
  }

  async updateUser(id, data) {
    return this.UserModel.findOneAndUpdate({_id: id.id}, data, {new: true});
  }
}
  
  module.exports = { PostgresUserRepository, MongoUserRepository };
  