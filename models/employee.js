const mongoose = require('mongoose');

const employeeSchema = new mongoose.Schema({
  photo: String,
  name: { type: String, required: true },
  contact: String,
  phone2: String,
  email: String,
  website: String,
  address: String,
  videoUrl: String,
  imageFit: { type: String, default: 'cover' },
  imagePos: { type: String, default: '50' },
  rank: Number,
  designation: {
    type: String,
    default: 'Agent',
  },
  employeeid: String,
  branchid: String,
  area: {
    type: String,
    default: 'NA',
  },
  teamSize: Number,
  experience: Number,
  achievements: String,
  company: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'Company',
    required: true,
  },
});

const Employee = mongoose.model('Employee', employeeSchema);
module.exports = Employee;