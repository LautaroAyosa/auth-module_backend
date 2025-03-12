

## How to handle requests to repositories.

For a seamless experience you should pass objects to the repositories. Since we're working with two databases we need to keep an eye on how we send information to the repositories. We must not play with this.

Doesn't matter if you're using postgres or mongo, always call to the database in the following matter:

``` javascript
    module.exports = (repositories) => {

        return {
            register: async (req, res) => {
                const body = req.body
                const hashedPassword = await bcrypt.hash(password, 10);
                // Since it's a call to the DB we need to await.
                // Sending the data as an object allows the repositories to handle inputs in a standardized way
                // Otherwise this would be imposible or extremely hard.
                await userRepositories.createUser({ 
                    name: body.name, 
                    email: body.email, 
                    password: hashedPassword 
                })
            }
        }
    }
```