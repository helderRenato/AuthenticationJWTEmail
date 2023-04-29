const express = require('express')
const route = express.Router()

const UserController = require('./Controller/UserController')

//Register User on the database  
route.post("/signup", UserController.store)
//Login the user with JWT
route.post("/login", UserController.index)
//Get user data by the JWT
route.get("/confirm/:token", UserController.validate)


module.exports = route