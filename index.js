const mongoose = require('mongoose');
const express = require('express');
const bcrypt = require('bcrypt');
const User = require('./models/Register');
const Post = require('./models/Post');
const app = express();
const jwt = require('jsonwebtoken');
const cors = require('cors');
const multer = require('multer');
const CookieParser = require('cookie-parser');
const path = require('path');
const nodemailer = require('nodemailer');
const bodyParser = require('body-parser');
require('dotenv').config();

const port = process.env.PORT || 3001;

mongoose.connect(process.env.MONGODB_URL, { enableUtf8Validation: true });

app.use(CookieParser());
app.use(express.json());

const allowedOrigins = [process.env.ALLOWED_SITE1, process.env.ALLOWED_SITE2,process.env.ALLOWED_SITE3];

app.use(cors({
    credentials: true,
    origin: (origin, callback) => {
      if (allowedOrigins.includes(origin) || !origin) {
        callback(null, true);
      } else {
        callback(new Error('Not allowed by CORS'));
      }
    }
  }));
  
  app.use((req, res, next) => {
    const origin = req.headers.origin;
    if (allowedOrigins.includes(origin)) {
      res.header('Access-Control-Allow-Origin', origin);
    }
    res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,OPTIONS');
    res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
    if (req.method === 'OPTIONS') {
      return res.sendStatus(200);
    }
    next();
  });

app.get('/', (req, res) => res.send('Hello World!'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(bodyParser.json());

const otpMap = new Map();

const storage = multer.diskStorage({
    destination: function (req, file, cb) {
        cb(null, 'uploads/');
    },
    filename: function (req, file, cb) {
        cb(null, Date.now() + '-' + file.originalname);
    }
});

const upload = multer({ storage: storage });

const authenticate = (req, res, next) => {
    const authHeader = req.headers['authorization']
  const token = authHeader && authHeader.split(' ')[1]

    if (token) {
        jwt.verify(token, process.env.SECRET_KEY, (err, user) => {
            if (err) {
                return res.status(401).json({ err: "Unauthorized: Invalid token" });
            }
            req.user = user;
            next();
        });
    } else {
        return res.status(404).json({ err: "Token not found" });
    }
};

const authenticateRole = (role) => {
    return (req, res, next) => {
        if (req.user.role.toLowerCase() === role.toLowerCase()) {
            next();
        } else {
            return res.status(401).json({ err: "Unauthorized: Insufficient role" });
        }
    };
};

const transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: process.env.EMAIL_ID,
        pass: process.env.PASSWORD
    }
});

app.post('/send-otp', async (req, res) => {
    const { email } = req.body;
    const found = await User.findOne({ email });

    if (!found) {
        return res.status(400).json({ err: "Invalid Credentials" });
    }

    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    otpMap.set(email, otp);

    const mailOptions = {
        from: process.env.EMAIL_ID,
        to: found.email,
        subject: 'Your OTP Code',
        text: `Your OTP code is ${otp}`
    };

    transporter.sendMail(mailOptions, (error, info) => {
        if (error) {
            console.log(error.message);
            return res.status(500).json({ msg: 'Error sending OTP', error });
        } else {
            res.status(200).json({ msg: 'OTP sent successfully' });
        }
    });
});

app.post('/verify-otp', async (req, res) => {
    try {
        const { email, otp } = req.body;
        if (!email || !otp) {
            return res.status(400).json({ msg: 'Email and OTP are required' });
        }

        const found = await User.findOne({ email });
        const storedOtp = otpMap.get(email);
        if (storedOtp === otp) {
            otpMap.delete(email);
            const token = jwt.sign({ email: found.email, role: found.role, firstName: found.firstName }, process.env.SECRET_KEY);
            //return res.cookie("token", token, { httpOnly: true, secure: true }).status(200).json({ msg: "Login successful" });
            return res.status(200).send({token})
        } else {
            return res.status(400).json({ msg: 'Invalid OTP' });
        }
    } catch (err) {
        console.log(err.message);
        return res.status(500).send("Server Error");
    }
});

app.post('/register', async (req, res) => {
    try {
        const { firstName, lastName, email, phoneNumber, role, password } = req.body;

        const existingEmail = await User.findOne({ email });
        if (existingEmail) {
            return res.status(400).send("Email Id Already Exists");
        }

        const salt = bcrypt.genSaltSync(10);
        const hashPassword = bcrypt.hashSync(password, salt);
        const newUser = new User({ firstName, lastName, email, phoneNumber, role, password: hashPassword });

        await newUser.save();
        return res.status(200).json({ msg: "New User Created" });
    } catch (err) {
        console.log(err.message);
        return res.status(500).send("Server Error");
    }
});

app.post('/login', async (req, res) => {
    try {
        const { email, password } = req.body;

        const found = await User.findOne({ email });
        if (!found) {
            return res.status(400).json({ err: "Email Not Found" });
        }

        const checkPassword = bcrypt.compareSync(password, found.password);
        if (!checkPassword) {
            return res.status(401).json({ msg: "Invalid Credentials" });
        }

        const token = jwt.sign({ email: found.email, role: found.role, firstName: found.firstName }, process.env.SECRET_KEY);
        //return res.cookie("token", token, { httpOnly: true, secure: true }).status(200).json({ msg: "Login successful" });
        return res.status(200).send({token})
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ err: "Server Error" });
    }
});

app.post('/post', authenticate, authenticateRole('Seller'), upload.single('place'), async (req, res) => {
    try {
        const email = req.user.email;
        const { area, noOfBedrooms, noOfBathrooms, hospital, collegeNearBy, rent, furnished, parking, pet, description, ratings } = req.body;
        const foundEmail = await User.findOne({ email });
        if (!foundEmail) {
            return res.status(404).json({ err: "Email id Not Found" });
        }

        const place = req.file ? req.file.filename : null;
        const newPost = new Post({ place, area, noOfBedrooms, noOfBathrooms, hospital, collegeNearBy, email, rent, furnished, parking, pet, description, ratings });
        await newPost.save();
        return res.status(200).json({ msg: "Post Created" });
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ err: "Server Error" });
    }
});

app.get('/getpost', authenticate, async (req, res) => {
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]
  

    if (token) {
        const allPost = await Post.find({});
        if (!allPost) {
            return res.status(404).json({ msg: "No Post" });
        } else {
            return res.status(200).json({ post: allPost, role: req.user.role });
        }
    } else {
        return res.status(401).json({ err: "Unauthorized to see the post" });
    }
});

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

app.get('/profile', authenticate, async (req, res) => {
    try {
        return res.status(200).json({ role: req.user.role, email: req.user.email, firstName: req.user.firstName });
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ err: "Server Error" });
    }
});

app.put('/edit/:id', authenticate, authenticateRole('Seller'), upload.single('place'), async (req, res) => {
    try {
        const { id } = req.params;
        const { area, noOfBedrooms, noOfBathrooms, hospital, collegeNearBy, rent, furnished, parking, pet, description, ratings } = req.body;
        const place = req.file ? req.file.filename : null;

        const newData = { area, noOfBedrooms, noOfBathrooms, hospital, collegeNearBy, rent, furnished, parking, pet, description, ratings };

        if (place) {
            newData.place = place;
        }

        const newPost = await Post.findByIdAndUpdate(id, newData, { new: true });

        if (!newPost) {
            return res.status(404).json({ msg: "Post not found" });
        }

        return res.status(200).json({ msg: "Post updated successfully", post: newPost });
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ err: "Server Error" });
    }
});

app.delete('/delete/:id', authenticate, authenticateRole('Seller'), async (req, res) => {
    const { id } = req.params;

    if (id) {
        await Post.findByIdAndDelete(id);
        return res.status(200).json({ msg: 'Deleted Successfully' });
    } else {
        return res.status(404).json({ msg: "Not Found" });
    }
});

app.post('/senddetails/:id', authenticate, async (req, res) => {
    const { id } = req.params;

    const buyerEmail = req.user.email;
    const buyerFirstName = req.user.firstName;

    if (!buyerEmail) {
        return res.status(400).json({ msg: 'Unauthorized' });
    }

    const foundBuyerEmail = await User.findOne({ email: buyerEmail });
    if (!foundBuyerEmail) {
        return console.log("Not Found");
    }

    const buyerPhoneNumber = foundBuyerEmail.phoneNumber;

    try {
        const sellerPost = await Post.findById(id);
        if (!sellerPost) {
            return res.status(400).json({ err: 'Error occurred: Post not found' });
        }

        const sellerEmail = sellerPost.email;
        const seller = await User.findOne({ email: sellerEmail });

        if (!seller) {
            return res.status(400).json({ err: 'Error occurred: Seller not found in User collection' });
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

app.listen(port, () => console.log(`App listening on port ${port}!`));
