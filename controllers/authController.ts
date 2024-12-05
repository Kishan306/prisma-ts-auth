import { Request, Response } from "express";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { PrismaClient } from "@prisma/client";
const prisma = new PrismaClient();

const signup = async (req: Request, res: Response) => {
  const { username, email, password } = req.body;

  try {
    const existingUser = await prisma.user.findFirst({
      where: {
        email: email,
      },
    });

    if (existingUser) {
      return res.status(400).json({ error: "Email already in use" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const createdUser = await prisma.user.create({
      data: {
        username: username,
        email: email,
        password: hashedPassword,
      },
    });

    const token = jwt.sign(
      {
        id: createdUser.id,
        email: createdUser.email,
        role: createdUser.role || "user", // Default role if not present
      },
      process.env.JWT_SECRET!,
      { expiresIn: "1h" } // Token expiration time
    );

    res.status(201).json({ message: "User created successfully", token });
  } catch (error) {
    return res.status(500).json({ error: "Internal server error" });
  }
};

const login = async (req: Request, res: Response) => {
  const { email, password } = req.body;

  try {
    // Find user by email
    const user = await prisma.user.findFirst({
      where: {
        email: email.trim(),
      },
    });

    if (!user) {
      return res.status(400).json({ error: "No user with this email" });
    }

    // Compare the provided password with the hashed password
    const isPasswordValid = await bcrypt.compare(
        password.trim(),
        user.password
    );

    if (!isPasswordValid) {
      return res.status(400).json({ error: "Invalid email or password" });
    }

    // Create JWT token
    const token = jwt.sign(
      {
        id: user.id,
        email: user.email,
        role: user.role || "user", // Default role if not present
      },
      process.env.JWT_SECRET!,
      { expiresIn: "1h" } // Token expiration time
    );

    // Send response with token
    res.status(200).json({ message: "Login successful", token });
  } catch (err) {
    res.status(500).json({ error: "Internal Server Error" });
  }
};

export { signup, login };
