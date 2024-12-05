import Joi from "joi";
import { Request, Response, NextFunction } from "express";

const usernameSchema = Joi.string().alphanum().min(3).max(15).required();

const emailSchema = Joi.string().email().required();

const passwordSchema = Joi.string()
  .pattern(
    /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,20}$/
  )
  .required();

export const validateSignup = (req: Request, res: Response, next: NextFunction) => {
  const { username, email, password } = req.body;

  const { error: usernameError } = usernameSchema.validate(username);
  if (usernameError) return res.status(400).json({ error: "Invalid username" });

  const { error: emailError } = emailSchema.validate(email);
  if (emailError) return res.status(400).json({ error: "Invalid email" });

  const { error: passwordError } = passwordSchema.validate(password);
  if (passwordError)
    return res
      .status(400)
      .json({
        error:
          "Password must contain at least one uppercase, one lowercase, one number, one special character and should be of length 8-20",
      });

  next();
};

export const validateLogin = (req: Request, res: Response, next: NextFunction) => {
  const { email, password } = req.body;

  const { error: emailError } = emailSchema.validate(email);
  if (emailError) return res.status(400).json({ error: "Invalid email" });

  const { error: passwordError } = passwordSchema.validate(password);
  if (passwordError) return res.status(400).json({ error: "Invalid password" });

  next();
};