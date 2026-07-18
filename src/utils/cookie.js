const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production",
  sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
  maxAge: Number(process.env.REFRESH_TOKEN_EXPIRES_MS),
};

export const createTokenCookie = (response, refreshToken) => {
  response.cookie("refreshToken", refreshToken, COOKIE_OPTIONS);
};

export const destroyTokenCookie = (response) => {
  response.clearCookie("refreshToken", {
    httpOnly: COOKIE_OPTIONS.httpOnly,
    secure: COOKIE_OPTIONS.secure,
    sameSite: COOKIE_OPTIONS.sameSite,
  });
};
