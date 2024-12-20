const mongoose=require("mongoose");
const dotenv = require("dotenv");
dotenv.config();

mongoose.connect(process.env.MONGODB_URL)
// mongoose.connect("mongodb://localhost:27017/userdb")



const userschema=mongoose.Schema({
    username:String,
    email:String,
    password:String,
    joindate:{
        type:Date,
        default:Date.now()
    }
})

module.exports=mongoose.model("userdb",userschema);
