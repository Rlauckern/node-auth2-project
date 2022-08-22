const { JWT_SECRET } = require("../secrets"); // use this secret!
const jwt = require("jsonwebtoken");
const Users = require("../users/users-model");

const restricted = (req, res, next) => {
  const token = req.headers.authorization;
  if (!token) {
    res.status(401).json({ message: "Token required" });
  } else {
    jwt.verify(token, JWT_SECRET, (err, decodedToken) => {
      if (err) {
        res.status(401).json({ message: "Token invalid" });
      } else {
        req.decodedJwt = decodedToken;
        next();
      }
    });
  }
}

const only = role_name => (req, res, next) => {
  if (role_name !== req.decodedJwt.role_name) {
    res.status(403).json({ message: "This is not for you" });
    req.decodedJwt = "";
  } else {
    next();
  }
}


const checkUsernameExists = async (req, res, next) => {
  const user = await Users.findBy({ username: req.body.username }).first();
  if (!user) {
    res.status(401).json({ message: "Invalid credentials" });
  } else {
    req.user = user;
    next();
  }
}


const validateRoleName = (req, res, next) => {
  if (
    !req.body.role_name ||
    typeof req.body.role_name !== "string" ||
    !req.body.role_name.trim()
  ) {
    req.role_name = "student";
    next();
  } else {
    if (req.body.role_name.trim() === "admin") {
      res.status(422).json({ message: "Role name can not be admin" });
      return;
    } else if (req.body.role_name.trim().length > 32) {
      res
        .status(422)
        .json({ message: "Role name can not be longer than 32 chars" });
      return;
    } else {
      req.role_name = req.body.role_name.trim();
      next();
    }
  }
}

module.exports = {
  restricted,
  checkUsernameExists,
  validateRoleName,
  only,
}