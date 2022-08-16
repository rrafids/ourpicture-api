const jwt = require("jsonwebtoken");
const usersRepository = require("../repositories/usersRepository");

const { JWT_SECRET } = process.env;

exports.authenticate = async (req, res, next) => {
  const authHeader = req.get("Authorization");
  let token;

  if (authHeader && authHeader.startsWith("Bearer"))
    token = authHeader.split(" ")[1];
  try {
    const decodedToken = jwt.verify(token, JWT_SECRET);

    const { getUser } = await usersRepository.findByID({
      id: decodedToken.id,
    });

    req.user = getUser;

    next();
  } catch (err) {
    return res.status(401).jsend.fail({
      code: 401,
      message: "Sesi telah kadaluarsa. Silakan login kembali",
    });
  }
};