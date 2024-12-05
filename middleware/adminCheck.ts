import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import type { JwtPayload } from "jsonwebtoken";

const adminCheck = (req: any, res: Response, next: NextFunction) => {
  const token = req.header("authorization")?.replace("Bearer ", "");

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  try {
    // Verify and decode the token
    const decoded = jwt.verify(token, process.env.JWT_SECRET!) as JwtPayload;
    req.user = decoded;

    // Check if the user's role is admin
    if (decoded.role !== "ADMIN") {
      return res.status(403).json({ error: "Forbidden: Admins only" });
    }

    // Proceed to the next middleware or route handler
    req.user = decoded; // Attach user information to request object if needed
    next();
  } catch (error) {
    if (error.name === "JsonWebTokenError") {
      return res.status(401).json({ error: "Invalid token" });
    } else if (error.name === "TokenExpiredError") {
      return res.status(401).json({ error: "Token expired" });
    } else {
      return res.status(500).json({ error: "Internal server error" });
    }
  }
};

export { adminCheck };
