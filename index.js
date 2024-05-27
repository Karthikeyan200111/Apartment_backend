const mongoose=require('mongoose');
const express = require('express')
const bcrypt=require('bcrypt')
const User=require('./models/Register')
const Post=require('./models/Post')
const app = express()

const jwt=require('jsonwebtoken')
const cors=require('cors')
const multer=require('multer')
const CookieParser = require('cookie-parser');
app.use(CookieParser());
app.use(express.json());

const path=require('path')
const nodemailer=require('nodemailer');
const bodyparser=require('body-parser')
require('dotenv').config()

const port = process.env.PORT || 3001;



mongoose.connect(process.env.MONGODB_URL,{ enableUtf8Validation: true })

app.use(cors({
    credentials: true,
    origin: [process.env.ALLOWED_SITE1, process.env.ALLOWED_SITE2]
  }));
app.get('/', (req, res) => res.send('Hello World!'))
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(bodyparser.json());

const otpMap=new Map();


const storage = multer.diskStorage({
    destination: function (req, file, cb) {
      cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
      cb(null, Date.now() + '-' + file.originalname);
    }
  });

const upload=multer({storage:storage})

const authenticate=(req,res,next)=>{
    console.log(req.cookies)
    const {token}=req.cookies;
    if(token){
        jwt.verify(token,process.env.SECRET_KEY,(err,user)=>{
            if(err){
                return res.status(401).json({err:"Unauthorized.. for token"})
            }
            req.user=user;
           
            next();
        })

    }else{
        return res.status(404).json({err:"Token not found.."})
    }
   
}

const authenticateRole=(role)=>{
   
        return(req,res,next)=>{
           // console.log(req.user)
            if(req.user.role.toLowerCase()===role.toLowerCase()){
                next();
            }else{
                return res.status(401).json({err:"Unauthorized.. for role"})
            }
        }
}


const transporter=nodemailer.createTransport({
    service:'gmail.com',
    auth:{
        user:process.env.EMAIL_ID,
        pass:process.env.PASSWORD
    }
})

app.post('/send-otp',async(req,res)=>{
    const{email}=req.body
    const found=await User.findOne({email});
    
    if(!found){
        return res.status(400).json({err:"Invalid Credentials...."})
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();

    otpMap.set(email, otp);

    const mailOptions = {
        from: process.env.EMAIL_ID,
        to:found.email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error.message)
            return res.status(500).json({ msg: 'Error sending OTP', error });
          
        } else {
            res.status(200).json({ msg: 'OTP sent successfully' });
        }
    });
})

app.post('/verify-otp', async(req, res) => {

    try{
        const { email, otp } = req.body;
    if (!email || !otp) {
        return res.status(400).json({ msg: 'Email and OTP are required' });
    }

    const found=await User.findOne({email});

    const storedOtp = otpMap.get(email);
    if (storedOtp === otp) {
        otpMap.delete(email); // OTP is used once
        const token =jwt.sign({email:found.email,role:found.role,firstName:found.firstName},process.env.SECRET_KEY);
        return res.cookie("token",token,{ httpOnly: true, secure: true }).status(200).json({msg:"Login successful....."})

    } else {
        return res.status(400).json({ msg: 'Invalid OTP' });
    }

    }catch(err){
        console.log(err.message);
        return res.status(500).send("server Error")
    }
    
});






app.post('/register',async(req,res)=>{
    try{
        const{firstName,lastName,email,phoneNumber,role,password}=req.body

        const existingEmail=await User.findOne({email})
        if(existingEmail){
            return res.status(400).send("Email Id Already There....")
        }
        const salt = bcrypt.genSaltSync(10);

        const hashPassword=bcrypt.hashSync(password,salt); 
        const newUser=await new User({firstName,lastName,email,phoneNumber,role,password:hashPassword});
    
        await newUser.save();

        return res.status(200).json({msg:"New User Created....."})

    }catch(err){
        console.log(err.message);
        return res.status(500).send("server Error")
    }
   

})

app.post('/login',async(req,res)=>{
    try{
        const {email,password}=req.body;

        const found=await User.findOne({email});
    
        if(!found){
            return res.status(400).json({err:"Email Not Found...."})
        }
    
        const checkPassword=bcrypt.compareSync(password,found.password);
    
    
        if(!checkPassword){
            return res.status(401).json({msg:"Invalid Credentials..."})
        }
    
        
        const token =jwt.sign({email:found.email,role:found.role,firstName:found.firstName},process.env.SECRET_KEY);
            return res.cookie("token",token).status(200).json({msg:"Login successful....."})

    }catch(err){
        console.log(err.message);
        return res.status(500).json({err:"server Error"})
    }
   
})
app.post('/post',authenticate,authenticateRole('Seller'),upload.single('place'),async(req,res)=>{
    try{
        const email=req.user.email
        const {area,noOfBedrooms,noOfBathrooms,hospital,collegeNearBy,rent,furnished,parking,pet,description,ratings}=req.body
        const foundEmail=await User.findOne({email});
        if(!foundEmail){
            return res.status(404).json({err:"Email id  Not Found..."})
        }
      //  console.log(req.file)
        const place=req.file ? req.file.filename:null;
        const newPost=await Post({place,area,noOfBedrooms,noOfBathrooms,hospital,collegeNearBy,email,rent,furnished,parking,pet,description,ratings})
        await newPost.save();
        return res.status(200).json({msg:"Post Created..."})

    }catch(err){
        console.log(err.message);
        return res.status(500).json({err:"server Error"})
    }
   
})
app.get('/getpost',authenticate,async(req,res)=>{
    const{token}=req.cookies;

    if(token){
        const allPost=await Post.find({});
        if(!allPost){
            return res.status(404).json({msg:"No Post"})
        }else{
            return  res.status(200).json({post:allPost,role:req.user.role})
        }

    }else{
        return res.status(401).json({err:"Unauthorised to see the post"})
    }
    
})
app.get('/get/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    try {
        if (id) {
            const currentPost = await Post.findById(id);
            if (!currentPost) {
                return res.status(404).json({ msg: "No Post" });
            } else {
                return res.status(200).json({ currentPost });
            }
        } else {
            return res.status(404).json({ err: "Not Found" });
        }
    } catch (error) {
        return res.status(500).json({ err: "Server Error", details: error.message });
    }
});

app.get('/profile',authenticate,async(req,res)=>{
    try{
      // console.log(req.user)
        return res.status(200).json({role:req.user.role,email:req.user.email,firstName:req.user.firstName})
    }catch(err){
        console.log(err.message);
        return res.status(500).json({err:"server Error"})
    }
    
    
})
app.put('/edit/:id',authenticate,authenticateRole('Seller'),upload.single('place'),async(req,res)=>{
    try{
        const {id}=req.params;
        const {area,noOfBedrooms,noOfBathrooms,hospital,collegeNearBy,rent,furnished,parking,pet,description,ratings}=req.body
        const place=req.file ? req.file.filename :null;
    
        const newData={area,noOfBedrooms,noOfBathrooms,hospital,collegeNearBy,rent,furnished,parking,pet,description,ratings}
    
        if(place){
            newData.place=place
        }
    
        const newPost=await Post.findByIdAndUpdate(id,newData)
    
        if (!newPost){
            return res.status(404).json({ msg: "Employee not found..." });
          }
        
          return res.status(200).json({ msg: "Employee updated successfully", employee: newPost });
        
        
    }catch(err){
        console.log(err.message);
        return res.status(500).json({err:"server Error"})
    }
  


})
app.delete('/delete/:id',authenticate,authenticateRole('Seller'),async(req,res)=>{
    const {id}=req.params

    if(id){
        const findPost=await Post.findByIdAndDelete(id);
        return res.status(200).json({msg:'Deleted Successfully...'})
        

    }else{
        return res.status(404).json({msg:"Not found"})
    }
})

app.post('/senddetails/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    const buyerEmail = req.user.email;
    

    const buyerFirstName=req.user.firstName

    if (!buyerEmail) {
        return res.status(400).json({ msg: 'Unauthorized...' });
    }
    
    const foundbuyerEmail=await User.findOne({email:buyerEmail});
    if(!foundbuyerEmail){
        return console.log("Not Found")
    }
    
        const buyerPhoneNumber=foundbuyerEmail.phoneNumber;

   

    try {
        // Find the seller's post by ID
        const sellerPost = await Post.findById(id);

        if (!sellerPost) {
            return res.status(400).json({ err: 'Error occurred: Post not found.' });
        }

        const sellerEmail = sellerPost.email;

        // Find the seller's details in the User collection
        const seller = await User.findOne({ email: sellerEmail });

        if (!seller) {
            return res.status(400).json({ err: 'Error occurred: Seller not found in User collection.' });
        }

        const sellerFirstName = seller.firstName;
        const sellerPhoneNumber = seller.phoneNumber;

        const mailOptions = {
            from: process.env.EMAIL_ID,
            to: buyerEmail,
            subject: 'Seller Details',
            text: `The Seller Details are:
            First Name: ${sellerFirstName},
            Email: ${sellerEmail},
            Phone Number: ${sellerPhoneNumber}`
        };
        const mailOptions2 = {
            from: process.env.EMAIL_ID,
            to: sellerEmail,
            subject: 'Buyer Details',
            text: `The Buyer Details are:
            First Name: ${buyerFirstName},
            Email: ${buyerEmail},
            Phone Number: ${buyerPhoneNumber}`
        };

        transporter.sendMail(mailOptions, (error, info) => {
            if (error) {
                console.log(error.message);
                return res.status(500).json({ msg: 'Error sending email', error });
            } else {
                res.status(200).json({ msg: 'Email sent successfully to buyer' });
            }
        });
        transporter.sendMail(mailOptions2, (error, info) => {
            if (error) {
                console.log(error.message);
                return res.status(500).json({ msg: 'Error sending email', error });
            } else {
                res.status(200).json({ msg: 'Email sent successfully to seller' });
            }
        });

    } catch (error) {
        console.log(error);
        res.status(500).json({ msg: 'Server error' });
    }
});

app.post('/logout', (req, res) => {
    res.clearCookie('token').json({ msg: "Logged out successfully" });
  });




app.listen(port , () => console.log(`Example app listening on port ${port}!`))

//mongodb+srv://hello:<password>@assignment.ef4fglb.mongodb.net/?retryWrites=true&w=majority&appName=assignment
//hello@gmail.com 123
//bavg mgvm chfh rlhy