const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../model/User");
require("dotenv").config()

// signup Handler:
exports.signup = async(req,res)=>{
    try{
        const {name,email,password,role} = req.body;
        // if not filled all details
        if(!name || !role || !email || !password){
            return res.status(400).json({
                success:false,
                message:"Fill all credentials"
            })
        }
        // find the existance user

        const existingUser = await User.findOne({email});
        if(existingUser){
            return res.status(400).json({
                success:false,
                message:"User already exists",
            });
        }

        // password secure
        let hashedPassword;
        try{
            hashedPassword = await bcrypt.hash(password,10);
        }
        catch(err){
            return res.status(500).json({
                success:false,
                message:"Error in hashing password",
            })
        }

        // create entry for User
        const user = await User.create({
            name,email,password:hashedPassword,role
        })
        res.status(200).json({
            success:true,
            message:"SignUp successfully"
        })
    }
    catch(error){
        console.error(error)
        res.status(500)
        .json({
            success:false,
            message:"User canot be registered Please try again later",
        })
    }
}

exports.login = async(req,res)=>{
    const {email,password}=req.body;
    try{
        // if email,password is not given
        if(!email || !password){
            return res.status(400).json({
                success:false,
                message:"Fill all credentials"
            })
        }
        // user is not present in db
        let user =await User.findOne({email});
        if(!user){
            return res.status(401).json({
                success:false,
                message:"Invalid credentials"
            })
        }
        // user is present check the password with hashed password

        const passwordMatch = await bcrypt.compare(password, user.password);
        
        if (!passwordMatch) {
            return res.status(403).json({
                success: false,
                message: "Incorrect Password"
            });
        }
        
        // password also matched
        // create a token
        const payload ={
            userId:user.id,
            email:user.email,
            role:user.role,
        }
        let token = jwt.sign(payload,
            process.env.JWT_SECRET,
            {
                expiresIn: "1h", // Token expires in 1 hour, you can adjust this
            });
            
        user=  user.toObject();
        
        user.token = token;
        delete user.password;
        const options={
            expiresIn:new Date(Date.now() + 3*24*60*60*1000),
            httpOnly:true,
        }
        res.cookie("Cookie",token,options).status(200).json({
            success:true,
            token,
            user,
            message:"Login successful",
        });
        // res.status(200).json({
        //     success:true,
        //     token,
        //     user,
        //     message:"Login successful",
        // });

    }
    
    catch(error){
        console.error(error);
        res.status(500).json({
            success:false,
            message:"Login failed, Please try again later.",
        });
    }
};