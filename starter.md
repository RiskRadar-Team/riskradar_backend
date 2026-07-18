1. npm init -y
2. npm install express
3. npm install pg - for postgresql
4. npm install bcrypt
5. npm install jsonwebtoken
6. npm install dotenv
7. npm install cookie-parser
8. npm install cors
9. npm install express-validator

10. npm install --save-dev nodemon

# if package.json exist then run

npm install

# .env file setup

PORT=5000
DATABASE_URL=postgresql database url
JWT_SECRET=your jwt secret key
JWT_ACCESS_EXPIRES_IN=15m
JWT_REFRESH_EXPIRES_IN=7d
REFRESH_TOKEN_EXPIRES_MS=604800000
NODE_ENV=development
BCRYPT_SALT_ROUNDS=10
