const Pool = require("pg").Pool;
const dotenv = require("dotenv");

dotenv.config();

const connection = new Pool({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: 5432,
  // ssl: {
  //   rejectUnauthorized: false,
  // },
});

module.exports = connection;
