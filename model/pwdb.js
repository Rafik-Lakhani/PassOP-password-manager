const  mongoose=require("mongoose");


const pwdbschema=mongoose.Schema({
    userid:{
        type:mongoose.Schema.Types.ObjectId,
        ref:"userdb"
    },
    siteurl:String,
    usernm:String,
    sitepw:String,
    pwdate:{
        type:Date,
        default:Date.now()
    }
})

module.exports=mongoose.model("pwdb",pwdbschema);