const mongoose=require('mongoose');

const PostSchema=mongoose.Schema({
    place:{
        type:String,
        required:true
    },
    area:{
        type:String,
        required:true
    },
    noOfBedrooms:{
        type:Number,
        required:true
    },
    noOfBathrooms:{
        type:Number,
        required:true
    },
    hospital:{
        type:String,
        required:true
    },
    collegeNearBy:{
        type:String,
        required:true
    },email:{
        type:String,
        required:true
    },rent:{
        type:Number,
        required:true
    },furnished:{
        type:String
    },parking:{
        type:String
    },pet:{
        type:String
    },description:{
        type:String
    },ratings:{
        type:Number
    }
})

const Post=mongoose.model("Post",PostSchema);
module.exports=Post;