import jwt from "jsonwebtoken";

const userAuth = async (req, res, next) => {
  const token = req.cookies.token;
  if (!token) {
    return res.json({ success: false, message: "Unauthorized, Login Again." });
  }
  try {
    const tokenDecoded = jwt.verify(token, process.env.JWT_SECRET);
    if (tokenDecoded.id) {
      req.body.userId = tokenDecoded.id;
    } else {
      return res.json({ success: false, message: "Unauthorized, Login Again" });
    }
    next();
  } catch (error) {
    console.log(error);
    return res.status(401).json({ message: "Unauthorized" });
  }
};

export default userAuth;
