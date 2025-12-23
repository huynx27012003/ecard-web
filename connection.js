const mongoose = require('mongoose');
const dotenv = require('dotenv');

// Load the environment variables from .env file
dotenv.config();

// MongoDB connection URL
const mongoUrl = "mongodb+srv://nxh27012003:Huyhuhong123@cluster0.wsw5i0f.mongodb.net/ecardify?retryWrites=true&w=majority";

// Set up MongoDB connection
console.log('Connecting to MongoDB Atlas...');
mongoose.connect(mongoUrl);

const db = mongoose.connection;

// Event listeners for MongoDB connection
db.on('error', (error) => {
  console.error('MongoDB connection error:', error);
  process.exit(1); // Exit process on connection error
});

db.on('connected', () => {
  console.log('Connected to MongoDB');
});

db.on('disconnected', () => {
  console.log('Disconnected from MongoDB');
});

process.on('SIGINT', async () => {
  try {
    await mongoose.connection.close();
    console.log('MongoDB connection closed due to application termination');
    process.exit(0);
  } catch (error) {
    console.error('Error closing MongoDB connection:', error);
    process.exit(1);
  }
});

module.exports = mongoose;
