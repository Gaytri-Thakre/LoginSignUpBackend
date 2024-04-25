// protected routes 
// student cannot go to admin
// auth,isStudent,isAdmin

const jwt = require("jsonwebtoken");
require("dotenv").config();
// authentication
exports.auth = async (req,res,next)=>{
    try{
        // extract token
        console.log("cookie",req.cookies.token);
        console.log("body",req.body.token);
        const token = req.cookies.token || req.body.token || req.header("Authorization").replace("Bearer"," ");
        if(!token){
            return res.status(401).json({
                success:false,
                message:"Token is Missing",
            })
        }
        // verify token:
        try{
            const decode = jwt.verify(token,process.env.JWT_SECRET);
            console.log(decode);
            req.user = decode;
        }catch(error){
            return res.status(401).json({
                success:false,
                message:"Token is invalid",
            })
        }
        next();

    }catch(error){
        return res.status(401).json({
            success:false,
            message:"Something went wrong"
        });
    }
}
// authorization:
exports.isStudent = (req,res,next) =>{
    try{
        if(req.user.role !=='Student'){
            return res.status(401).json({
                success:false,
                message:"This is Protected route for students",
            })
        }
        next()
    }catch(err){
        console.log(err);
        return res.status(500).json({
            success:false,
            message:"User Role is not matching",
        })
    }
}
exports.isAdmin=(req,res,next)=>{
    try{
        if(req.user.role !=='Admin'){
            return res.status(401).json({
                success:false,
                message:"This is Protected route for admin",
            })
        }
        next()

    }catch(error){
        console.log(error);
        return res.status(500).json({
            success:false,
            message:"User Role is not matching",
        })
    }
}