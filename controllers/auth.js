const User = require("../models/user");
const Admin = require("../models/admin");
var jwt = require("jsonwebtoken");

// Sign up
exports.signup = async (req, res) => {
  const { email } = req.body;

  try {
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(422).json({ error: "Email already exists" });
    }

    const newUser = new User(req.body);

    await newUser.save();

    // Create a JWT token for the user
    const token = jwt.sign({ email, role: "user" }, process.env.SECRET_USER, {
      expiresIn: "3h",
    });

    console.log(token);
    // success response with token
    res.json({ message: "User created successfully", token });
  } catch (error) {
    console.error(error);
    res.status(500).json({ error: "Internal server error" });
  }
};

// Sign In
exports.signin = async (req, res) => {
  const { email, password } = req.body;
  try {
    const user = await User.findOne({ email, password });
    if (!user) {
      return res.status(422).json({ error: "Invalid email or password" });
    } else {
      const token = jwt.sign({ email, role: "user" }, process.env.SECRET_USER, {
        expiresIn: "3h",
      });
      res.json({ message: "Logged in successfully", token });
    }
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
};

// Authenticate User
exports.authenticateJwtUser = async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (authHeader) {
    const token = authHeader.split(" ")[1];
    jwt.verify(token, process.env.SECRET_USER, (err, user) => {
      if (err) {
        return res
          .status(403)
          .json({ error: "Token Expired. Please Login again" });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: "Access Denied" });
  }
};

//  Admin Signup
exports.adminSignup = async (req, res) => {
  const { email, secret } = req.body;
  const admin = await Admin.findOne({ email });
  const newAdmin = new Admin(req.body);

  try {
    if (secret !== process.env.SECRET_KEY) {
      return res.status(422).json({ error: "Please enter valid secret key" });
    }
   else if (admin) {
      return res.status(422).json({ error: "Email already exits" });
    } else {
      await newAdmin.save();
      const token = jwt.sign(
        { email, role: "admin" },
        process.env.SECRET_ADMIN,
        { 
          expiresIn: "3h",
        }
      );
      res.json({ message: "Admin created successfully", token });
    }
  } catch (e) {
    console.log(e)
    res.status(500).json({ error: "Internal server error" });
  }
};

// Admin Sign IN
exports.adminSignin = async (req, res) => {
  // console.log(req.body)
  const { email, password } = req.body;
  try {
    const user = await Admin.findOne({ email, password });

    if (!user) {
      return res.status(422).json({ error: "Invalid email or password" });
    } else {
      const token = jwt.sign(
        { email, role: "admin" },
        process.env.SECRET_ADMIN,
        {
          expiresIn: "3h",
        }
      );
      res.json({ message: "Logged in successfully", token });
    }
  } catch (e) {
    res.status(500).json({ error: "Internal server error" });
  }
};

// Authenticate Admin
exports.authenticateJwtAdmin = async (req, res, next) => {
  const authHeader = req.headers.authorization;

  if (authHeader) {
    const token = authHeader.split(" ")[1];

    jwt.verify(token, process.env.SECRET_ADMIN, (err, user) => {
      if (err) {
        return res
          .status(403)
          .json({ error: "Token Expired. Please Login again" });
      }
      req.user = user;
      next();
    });
  } else {
    res.status(401).json({ error: "Access Denied" });
  }
};
