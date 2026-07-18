import bcrypt from "bcrypt";

/**
 * Hash Password
 * @param {string} password
 * @returns {Promise<string>}
 */
export const hashPassword = async (password) => {
  const saltRounds = Number(process.env.BCRYPT_SALT_ROUNDS) || 12;

  return bcrypt.hash(password, saltRounds);
};

/**
 * Compare Password
 * @param {string} password
 * @param {string} hashedPassword
 * @returns {Promise<boolean>}
 */
export const comparePassword = async (password, hashedPassword) => {
  return bcrypt.compare(password, hashedPassword);
};
