// Code for the user repositories. This handles the database queries for the user entity. 
// The PostgresUserRepository class is for PostgreSQL queries, while the MongoUserRepository class is for MongoDB queries. 
// The module exports the PostgresUserRepository and MongoUserRepository classes.

// PostgreSQL Repository using Sequelize
class PostgresUserRepository {
  constructor(UserModel) {
    this.UserModel = UserModel;
  }

  async findAllUsers(fields = []) {
    const attributes = ['id', ...fields];
    return this.UserModel.findAll({ attributes });
  }

  async findUserById(data, fields = []) {
    const attributes = ['id', ...fields];
    return this.UserModel.findByPk(data.id, { attributes });
  }

  async findUserByEmail(data, fields = []) {
    const attributes = ['id', ...fields];
    return this.UserModel.findOne({ 
      where: { email: data.email },
      attributes,
      raw: true
    });
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

  async deleteOneUser(data) {
    if (data.id) {
      return this.UserModel.destroy({ where: {id: data.id } });
    } else if (data.email) {
      return this.UserModel.destroy({ where: {email: data.email } });
    }
  }
}
  
// MongoDB Repository
class MongoUserRepository {
  constructor(UserModel) {
    this.UserModel = UserModel;
  }

  async findAllUsers(fields = []) {
    const projection = this._buildProjection(fields);
    const users = await this.UserModel.find({}, projection).lean();
    return users.map(this._formatMongoDoc);
  }

  async findUserById(data, fields = []) {
    const projection = this._buildProjection(fields);
    const user = await this.UserModel.findById(data.id, projection).lean();
    return this._formatMongoDoc(user);
  }

  async findUserByEmail(data, fields = []) {
    const projection = this._buildProjection(fields);
    const user = await this.UserModel.findOne({ email: data.email }, projection).lean();
    return this._formatMongoDoc(user);
  }

  async createUser(data) {
    return this.UserModel.create(data);
  }

  async updateUser(id, data) {
    const updated = await this.UserModel.findOneAndUpdate(
        { _id: id }, 
        { $set: data },
        { new: true, runValidators: true, lean: true }
    );
    return this._formatMongoDoc(updated);
  }

  // Delete User by id or email string
  async deleteOneUser(data) {
    if (data.id) {
      return this.UserModel.deleteOne({ id: data.id });
    } else if (data.email) {
      return this.UserModel.deleteOne({ email: data.email });
    }
  }

  _buildProjection(fields) {
    const projection = { _id: 1 };
    fields.forEach(field => projection[field] = 1);
    return projection;
  }

  _formatMongoDoc(doc) {
    if (!doc) return null;
    const { _id, ...rest } = doc;
    return { id: _id.toString(), ...rest };
  }
}
  
module.exports = { PostgresUserRepository, MongoUserRepository };