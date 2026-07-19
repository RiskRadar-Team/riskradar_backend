import UserModel from "../models/userModel.js";
import ApiError from "../utils/ApiError.js";
import { hashPassword } from "../utils/password.js";

class AdminService {
  static async createAdmin(userData) {
    const { full_name, email, password } = userData;

    //check if email already exist
    const existingUser = await UserModel.findByEmail(email);
    if (existingUser) {
      throw new ApiError(409, "An admin with this email already exist.");
    }
    //hash_password
    const hashedPassword = await hashPassword(password);
    //create user
    const user = await UserModel.create(
      full_name,
      email,
      hashedPassword,
      "ADMIN",
    );

    delete user.password;
    return user;
  }
}
export default AdminService;
