export const cookieExtractor = req => {
  let token = null;
  if (req && req.cookies) {
    console.log(req.cookies);
    token = req.cookies.token;
  }
  return token;
};
