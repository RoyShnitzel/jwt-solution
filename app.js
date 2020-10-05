/* write your server code here */
const express = require("express");
const bcrypt = require("bcrypt");
const morgan = require("morgan");
const jwt = require("jsonwebtoken");
const app = express();
app.use(express.json());
app.use(morgan("tiny"));

const PRIVATEKEY = "test";
const REFRESHKEY = "refresh";

const USERS = [
  {
    email: "admin@email.com",
    name: "admin",
    password: "$2b$10$XrvT.ftIgwaweyREQv2.FepNzrDW9LLpzywyEWpfZycsxs5oC0DPi",
    isAdmin: true,
  },
];
const INFORMATION = [];

let REFRESHTOKENS = [];

app.get("/", (req, res) => {
  res.send("Hello World!");
});

app.post("/users/register", async (req, res) => {
  const user = req.body;
  const userExist = USERS.filter((savedUser) => savedUser.email === user.email);
  if (userExist.length > 0) {
    res.status(409).send("user already exists");
  } else {
    const hashedPassword = await bcrypt.hash(user.password, 10);
    user.password = hashedPassword;
    user.isAdmin = false;
    const userInformation = { name: user.name, info: `${user.name} info` };
    USERS.push(user);
    INFORMATION.push(userInformation);
    res.status(201).send({ message: "Register Success" });
  }
});

app.post("/users/login", async (req, res) => {
  console.log("enter login");
  const user = req.body;
  const emailExist = USERS.filter(
    (savedUser) => savedUser.email === user.email
  );
  if (emailExist.length > 0) {
    const passwordExist = emailExist.filter((savedUser) =>
      bcrypt.compare(user.password, savedUser.password)
    );
    if (passwordExist.length > 0) {
      const token = generateAccessToken(user);
      const refreshToken = jwt.sign(user, REFRESHKEY);
      console.log("user sendd", passwordExist);
      REFRESHTOKENS.push(refreshToken);
      res.status(200).send({
        accessToken: token,
        refreshToken: refreshToken,
        userName: passwordExist[0].name,
        isAdmin: passwordExist[0].isAdmin,
      });
    }
  } else {
    res.status(403).send("User or Password incorrect");
  }
});

app.post("/users/logout", async (req, res) => {
  const token = req.body.token;
  if (token) {
    REFRESHTOKENS = REFRESHTOKENS.filter((rToken) => rToken !== token);
    res.status(200).send({ message: "User Logged Out Successfully" });
  } else {
    res.status(400).send({ message: "Invalid Refresh Token" });
  }
});

app.post("/users/token", (req, res) => {
  console.log("enter");
  console.log(req.body.token);
  if (req.body.token === undefined) {
    return res.status(401).send("hey");
  }
  if (!REFRESHTOKENS.includes(req.body.token))
    return res.status(403).send("hey");
  jwt.verify(req.body.token, REFRESHKEY, (err, user) => {
    if (err) return res.status(403).send("hey");
    console.log(user);
    const accessToken = generateAccessToken({ name: user.name });
    res.status(200).send({ accessToken: accessToken });
  });
});

app.post("/users/validateToken", authenticateToken, (req, res) => {
  res.status(200).send({ valid: true });
});

app.get("/api/v1/information", authenticateToken, (req, res) => {
  console.log("enter information");
  const info = INFORMATION.filter((inf) => inf.name === req.user.name);
  res.status(200).send([{ user: req.user.name, info: info }]);
});

app.get("/api/v1/users", authenticateToken, (req, res) => {
  console.log("enter users");
  console.log(req.user);
  const admin = USERS.filter((user) => user.name === req.user.name);
  if (admin[0].isAdmin === true) {
    return res.status(200).send(USERS);
  }
  res.status(400).send("hey");
});

app.options("/", (req, res) => {
  const authHeader = req.headers.authorization;
  const token = authHeader && authHeader.split(" ")[1];
  if (token == null) {
    return res.status(200).send([api[0], api[1]]);
  }
  jwt.verify(token, PRIVATEKEY, (err, user) => {
    if (err) return res.status(200).send([api[1], api[0], api[2]]);
    console.log("middle", user);
    const accessLevel = USERS.filter((dataUser) => dataUser.name === user.name);
    if (accessLevel[0].isAdmin === true) {
      res.status(200).send(api);
    } else {
      res.status(200).send([api[1], api[2], api[3], api[4], api[5], api[0]]);
    }
  });
});

function authenticateToken(req, res, next) {
  console.log(req.headers);
  const authHeader = req.headers.authorization;
  console.log(authHeader);
  const token = authHeader && authHeader.split(" ")[1];
  console.log(token);
  if (token == null) {
    return res.status(401).send("Access Token Required");
  }
  jwt.verify(token, PRIVATEKEY, (err, user) => {
    if (err) return res.status(403).send("Invalid Access Token");
    console.log("middle", user);
    req.user = user;
    next();
  });
}

function generateAccessToken(user) {
  return jwt.sign(user, PRIVATEKEY, { expiresIn: "30s" });
}

const api = [
  {
    method: "post",
    path: "/users/register",
    description: "Register, required: email, user, password",
    example: {
      body: { email: "user@email.com", name: "user", password: "password" },
    },
  },
  {
    method: "post",
    path: "/users/login",
    description: "Login, required: valid email and password",
    example: { body: { email: "user@email.com", password: "password" } },
  },
  {
    method: "post",
    path: "/users/token",
    description: "Renew access token, required: valid refresh token",
    example: { headers: { token: "*Refresh Token*" } },
  },
  {
    method: "post",
    path: "/users/tokenValidate",
    description: "Access Token Validation, required: valid access token",
    example: { headers: { authorization: "Bearer *Access Token*" } },
  },
  {
    method: "get",
    path: "/api/v1/information",
    description: "Access user's information, required: valid access token",
    example: { headers: { authorization: "Bearer *Access Token*" } },
  },
  {
    method: "post",
    path: "/users/logout",
    description: "Logout, required: access token",
    example: { body: { token: "*Refresh Token*" } },
  },
  {
    method: "get",
    path: "api/v1/users",
    description: "Get users DB, required: Valid access token of admin user",
    example: { headers: { authorization: "Bearer *Access Token*" } },
  },
];

module.exports = app;
