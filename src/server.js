const express = require("express")
const app= express()
const bcrypt = require("bcryptjs");
const {prisma} = require("../db/config.js")
app.get("/",(req,res)=>{
    res.json({"ok": 200})
})
app.use(express.json())
app.post("/signup",async (req,res) => {
    const {userName , password } = req.body
    if (typeof userName !== "string" || typeof password !== "string" ||
        !userName.trim() || !password.trim() ) {
            return res.status(401).json({"error" : "invalid Credentatial"})
        }
    if (password.trim().length <= 8){
        return res.status(400).json({"error" : "password minman length is 8"})
    }
    const existinguser = await prisma.User.findUnique({
        where : {
            userName:userName.trim()
        }
    })
    if (existinguser) {
        return res.status(400).json({"msg":"Username is taken"})
    }
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    try{
    await prisma.user.create({
        data: {
            userName,
            "password":hashedPassword
        }
    })
    res.status(201).send("User Created")
    } catch(error) {
        if (error.code === "P2002") {
      return res.status(409).json({ "error": "Username already taken." });
        }
        res.status(500).json({"err": "interveral Server Error"})
    }
    
})
app.post("/login",async (req,res) => {
    const {userName , password } = req.body
    if (typeof userName !== "string" || typeof password !== "string" ||
        !userName.trim() || !password.trim() ) {
            return res.status(401).json({"error" : "invalid Credentatial"})
        }
    try{
    const user = await prisma.User.findUnique({
        where : {
            userName:userName.trim()
        }
    })
    if (!user){
       return res.status(401).json({"error":"User Not Found"})
    }
    const isPasswordValid = await bcrypt.compare(password, user.password)
    if (!isPasswordValid) {
      return res.status(401).json({ error: "Invalid credentials." });
    }

    res.status(200).json({
      message: "Login successful",
      user: {
        userName: user.userName,
      },
    });
    } catch(error) {
        res.status(500).json({"error": "interveral Server Error"})
    }
    
})
app.listen(3000, ()=>{
    console.log('servre is running')
})