const { Pool } = require("pg");
require("dotenv").config();

const client = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: {
    rejectUnauthorized: false,
  },
});

async function connectToDb() {
  try {
    await client.connect();
    console.log("Database connected successfully");
    return true;
  } catch (err) {
    console.error("Database connection error:", err.stack);
    throw err;
  }
}

module.exports = {
  client,
  connectToDb,
};
