const mongoose = require("mongoose");

const connect = mongoose.connect("mongodb://127.0.0.1:27017/loginDataBase", {
  useNewUrlParser: true,
  useUnifiedTopology: true,
});


connect.then(() => {
    console.log("database connected successfully");
  })
  .catch((err) => {
    console.log("database disconnected", err);
  });

//creating schema

const loginSchema = new mongoose.Schema({
  name: {
    type: String,
    required: true,
  },
  password: {
    type: String,
    required: true,
  },
  token:{
    type:String,
    required:true
  }

  
});

//create a model

const collection = new mongoose.model("usersDetails", loginSchema);

module.exports = collection;
