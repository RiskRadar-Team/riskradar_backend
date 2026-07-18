import ApiError from "../utils/ApiError.js";

/**
 * Role-Based Authorization Middleware
 *
 * Example:
 * authorize("ADMIN")
 * authorize("ADMIN")
 */
const authorize = (...roles) => {
  return (request, response, next) => {
    //note: authMiddleware should run before authorize()
    if (!request.user) {
      throw new ApiError(401, "Authentication required.");
    }

    // Check role
    if (!roles.includes(request.user.role)) {
      throw new ApiError(
        403,
        "You do not have permission to perform this action.",
      );
    }

    next();
  };
};

export default authorize;
