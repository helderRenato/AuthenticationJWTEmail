require('dotenv').config()
const {User} = require('../models/index')
const nodemailer = require('nodemailer')
const bcrypt = require("bcrypt")
const { Op } = require('sequelize');
const jwt = require("jsonwebtoken")

function validatePassw(passwd){
    const regex = /(?=^.{8,}$)((?=.*\d)|(?=.*\W+))(?![.\n])(?=.*[A-Z])(?=.*[a-z]).*$/
    return regex.test(passwd)
}

const transporter = nodemailer.createTransport({
    service: "gmail", 
    auth: {
        user: `${process.env.USER_EMAIL}`, 
        pass: `${process.env.USER_PASSWD}`
    }, 
    tls: {
        rejectUnauthorized: false
    }
  });

module.exports = {

    //Register the user 
    async store(req, res){
        try{
            //getting the name , email and password
            const {username, email, passw} = req.body
                    
            //Check if it is a valid password the password
            if(!validatePassw(passw)){
                return res.status(400).json("Error: The password you entered does not meet the password requirements. The password must be at least 8 characters long, including at least one uppercase letter, one lowercase letter, one digit or special character, and cannot contain a period or a newline. Please try again.")
            }
            //Check if the current name and email exists on the database 
            const users = await User.findAll({
                where: {
                    [Op.or]:[
                        {email: email}, 
                        {username: username}
                    ]
                }
            })
            if(users.length > 0){
                return res.status(400).json("This email or name is already in use")
            }
            //After all the verification we can create the user 

            //Create a hashed password 
            const hash_passw = await bcrypt.hash(passw, 10)

            // Generate a token secret key
            const token = jwt.sign({ email }, `${process.env.ACESS_TOKEN_SECRET}`, { expiresIn: '1d' });

            User.create({
                email: email, 
                password: hash_passw, 
                username: username
            }).then( async user => {
                //Send the confirmation email
                const sendEmail = {
                    from: 'noreply@something.com',
                    to: email,
                    subject: 'Confirm your email',
                    text: `Please click on the following link to confirm your email address: http://localhost:8000/confirm/${token}`,
                };
                const info = await transporter.sendMail(sendEmail);
                return res.status(201).json({ message: 'Please check your email to confirm your account' });
            }).catch(err => {
                console.log(err)
            })

           

        }catch(e){
            console.log(e)
        }
    }, 

    //Login the user and return the jwt token
    async index(req, res){
        try{
            const {email, passw} = req.body
            //verify if the email exists on our database 
            const user = await User.findOne({
                where: {
                    email: email
                }
            })

            if(!user){
                return res.status(400).json("User Not Founded")
            }

            if(!user.confirmed){
                return res.status(400).json("Confirm your email")
            }


            //verify if the password equals to the one on the database 
            if(await bcrypt.compare(passw, user.password)){
                const token = jwt.sign({ email }, `${process.env.ACESS_TOKEN_SECRET}`, { expiresIn: '1h' });
                return res.status(200).json({token})
            }else{
                return res.status(400).json("Wrong Password")
            }

        }catch(e){
            console.log(e)
        }
    }, 

    //get user data by the token
    async validate(req, res){
        const {token} = req.params
        try {
            // Verify the confirmation token
            const { email } = jwt.verify(token, `${process.env.ACESS_TOKEN_SECRET}`);
            //Update the confirmed in the database
            await User.update({ confirmed: true }, { where: { email: email } });
            return res.status(400).json("Confirmed Email")
        }catch(e){
            console.log(e)
        }
    }   
}