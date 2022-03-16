const express = require('express')
const app = express()
const crypto = require('crypto')
const urlencodedParser = express.urlencoded({extended: false});
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");

const secret = "SECRET"
const user = {
    login: "admin",
    password: "d033e22ae348aeb5660fc2140aec35850c4da997",
    credential: { id: 1, role: "admin" }
}

const authorization = (req, res, next) => {
    if (!req.cookies.access_token) {
        return res.status(403).sendFile(__dirname + '/views/403.html');
    }

    try {
        const data = jwt.verify(req.cookies.access_token, secret);
        req.userId = data.id;
        req.userRole = data.role;
        return next();
    } catch {
        return res.sendStatus(403);
    }
};

app.use(cookieParser());
app.listen(8080)

app.get('/v1/authorization', function (req, res) {
    res.sendFile(__dirname + '/views/authorization.html')
});

app.get('/', function(req, res){
    res.sendFile(__dirname + '/views/authorization.html')
});

app.post("/v1/authorization",
    urlencodedParser,
    function (req, res) {
        let hex = crypto.createHash('sha1').update(req.body.password).digest('hex')

        if (!(req.body.login === user.login && hex === user.password)) {
            return res.status(401).sendFile(__dirname + '/views/401.html')
        }

        const token = jwt.sign(user.credential, secret)
        return res
            .cookie("access_token", token, {
                httpOnly: true,
                secure: process.env.NODE_ENV === "production",
            })
            .status(200)
            .redirect("/v1/cars")
});

app.get("/v1/cars", authorization, (req, res) => {
    res.sendFile(__dirname + '/table.json')
});

app.get('*', function(req, res){
    res.status(404).sendFile(__dirname + '/views/404.html')
});