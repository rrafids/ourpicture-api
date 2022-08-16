const PasswordChecker = require("../utils/passwordChecker");
const TokenGenerator = require("../utils/tokenGenerator");
const Cloudinary = require("../utils/cloudinary");
const bcrypt = require("bcrypt");

const usersRepository = require("../repositories/usersRepository");

const SALT_ROUND = 10;

class AuthService {
  static async login({ email, password }) {
    try {
      // Check user existence
      const { getUser } = await usersRepository.findByEmail({
        email,
      });

      if (!getUser)
        return {
          status: false,
          error: {
            code: 400,
            message: "Email belum terdaftar",
          },
          error_validation: [
            {
              msg: "Invalid value",
              param: "email",
              location: "body",
            },
          ],
        };

      // Validate Password
      const validatePassword = await PasswordChecker.validate(
        password,
        getUser.password
      );

      if (!validatePassword.status) {
        return {
          status: false,
          error: {
            code: validatePassword.error.code,
            message: validatePassword.error.message,
          },
          error_validation: [
            {
              msg: "Invalid value",
              param: "password",
              location: "body",
            },
          ],
        };
      }

      // Generate Token
      const getToken = await TokenGenerator.generateJWT({
        id: getUser.id,
        email: getUser.email,
      });

      return {
        status: true,
        error: null,
        error_validation: [],
        token: getToken,
      };
    } catch (err) {
      return {
        status: false,
        error: {
          code: 500,
          message: err.message,
        },
        error_validation: [],
      };
    }
  }

  static async register({
    email, username, name, profile_picture: profilePicture, password
  }) {
    try {
      // Check email existence
      const { getUser: getUserByEmail } = await usersRepository.findByEmail(
        { email }
      );

      if (getUserByEmail)
        return {
          status: false,
          error: {
            code: 400,
            message: "Email sudah terdaftar",
          },
          error_validation: [
            {
              msg: "Invalid value",
              param: "email",
              location: "body",
            },
          ],
        };

      // Check username existence
      const { getUser: getUserByUsername } = await usersRepository.findByUsername(
        { username }
      );

      if (getUserByUsername)
        return {
          status: false,
          error: {
            code: 400,
            message: "Username sudah terdaftar",
          },
          error_validation: [
            {
              msg: "Invalid value",
              param: "username",
              location: "body",
            },
          ],
        };

      // Encrypt Password
      password = await bcrypt.hash(password, SALT_ROUND);

      // Upload profile picture to Cloudify
      const { url } = await Cloudinary.upload(profilePicture)

      // Insert user to database
      const { createdUser } = await usersRepository.create({
        email,
        username,
        name,
        profilePicture: url,
        password
      });

      return {
        status: true,
        error: null,
        createdUser
      };
    } catch (err) {
      return {
        status: false,
        error: {
          code: 500,
          message: err.message,
        },
      };
    }
  }
}

module.exports = AuthService;
