const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require('./auth-middleware');
const { JWT_SECRET } = require("../secrets"); // use this secret!
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const User = require("../users/users-model");

router.post("/register", validateRoleName, (req, res, next) => {
  const user = req.body;
  user.role_name = req.role_name;

  const hash = bcrypt.hashSync(user.password, BCRYPT_ROUNDS);
  user.password = hash;

  User.add(user)
    .then((saved) => {
      res.status(201).json(saved);
    })
    .catch((err) => {
      res.status(500).json({ message: "error adding user" });
    });
});


router.post("/login", checkUsernameExists, (req, res, next) => {
  let { username, password } = req.body;

  User.findBy({ username })
    .then(([user]) => {
      if (user && bcrypt.compareSync(password, user.password)) {
        const token = generateToken(user);

        res.status(200).json({ message: `${user.username} is back!`, token });
      } else {
        res.status(401).json({ message: "invalid credentials" });
      }
    })
    .catch((err) => {
      res.status(500).json({ message: "error loggin in" });
    });
});

function generateToken(user) {
  const payload = {
    subject: user.user_id,
    username: user.username,
    role_name: user.role_name,
  };
  return jwt.sign(payload, JWT_SECRET, { expiresIn: "1d" });
}

module.exports = router;