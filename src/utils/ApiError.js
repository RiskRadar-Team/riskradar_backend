class ApiError extends Error {
  /** Note stack means- The stack (or stack trace) is one of
   * the most important debugging tools in JavaScript.
   * It tells us where an error happened and
   * the sequence of function calls that led to it. */
  constructor(statusCode, message, errors = [], stack = "") {
    /** calling constructor of built-in Error class */
    super(message);
    this.statusCode = statusCode;
    this.success = false;
    this.errors = errors;
    if (stack) {
      this.stack = stack;
    } else {
      Error.captureStackTrace(this, this.constructor);
    }
  }
}

export default ApiError;
