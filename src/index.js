const express = require("express");
const path = require("path");
const bcrypt = require("bcrypt");
const collection = require("./config");
const jwt = require('jsonwebtoken');
const cookie = require('cookie-parser');
const dotenv = require('dotenv');
dotenv.config();
const app = express();
console.log(process.env);


const viewePath = path.join(__dirname, "../view");

// Setting view engine as ejs
app.use(express.json());
app.use(cookie());
app.use(express.urlencoded({ extended: false }));
app.set("view engine", "ejs");
app.set("views", viewePath);
app.use(express.static("public"));

app.get("/", (req, res) => {
    if (req.cookies.jwt) {
        const verify = jwt.verify( process.env.JWT_SECRET_KEY);
        res.render('home', { name: verify.name });
    } else {
        res.render("login");
    }
});

app.get("/user/validateToken", (req, res) => {
    // Tokens are generally passed in the header of the request
    // Due to security reasons.

    const tokenHeaderKey = process.env.TOKEN_HEADER_KEY;
    const jwtSecretKey = process.env.JWT_SECRET_KEY;

    try {
        const token = req.header(tokenHeaderKey);

        const verified = jwt.verify(token, jwtSecretKey);
        if (verified) {
            return res.send("Successfully Verified");
        } else {
            // Access Denied
            return res.status(401).send("Access Denied");
        }
    } catch (error) {
        // Access Denied
        return res.status(401).send("Access Denied");
    }
});

app.get("/signup", (req, res) => {
    res.render("signup");
});

app.post("/signup", async (req, res) => {
    const token = jwt.sign({ name: req.body.name }, process.env.JWT_SECRET_KEY);
    const data = {
        name: req.body.name,
        password: req.body.password,
        token: token
    };

    // Check if the user already exists
    const existingUser = await collection.findOne({ name: data.name });
    if (existingUser) {
        return res.send("User already exists. Please choose a different username.");
    }

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(data.password, saltRounds);
    data.password = hashedPassword;

    // Insert the new user into the database
    await collection.insertMany([data]);

    // Set the JWT token as a cookie
    res.cookie('jwt', token, {
        maxAge: 60000, // Set the token expiration time (adjust as needed)
        httpOnly: true
    });

    res.render("login");
});

app.post('/login', async (req, res) => {
    try {
        const check = await collection.findOne({ name: req.body.name });
        if (!check) {
            res.send('User not found');
        }
        const isPasswordMatch = await bcrypt.compare(req.body.password, check.password);
        if (isPasswordMatch) {
            res.cookie('jwt', check.token, {
                maxAge: 60000,
                httpOnly: true
            });
            res.render('home');
        } else {
            res.send('Wrong password');
        }
    } catch (error) {
        res.send('Wrong details');
    }
});

app.get('/update', (req, res) => {
    res.render('update');
});

app.post('/update', async (req, res) => {
    try {
        // Verify the user's identity using their token
        const token = req.cookies.jwt;
        const verify = jwt.verify(token, process.env.JWT_SECRET_KEY);
        const userName = verify.name;

        // Get the new password from the request
        const newPassword = req.body.newPassword;

        // Hash the new password
        const saltRounds = 10;
        const hashedPassword = await bcrypt.hash(newPassword, saltRounds);

        // Update the user's password in the database
        await collection.updateOne(
            { name: userName },
            { $set: { password: hashedPassword } }
        );

        res.send('Password updated successfully');
    } catch (error) {
        res.status(500).send('Password update failed');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is up and running on ${PORT} ...`);
});
