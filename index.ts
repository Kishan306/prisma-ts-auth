import express from 'express';
import 'dotenv/config'
const app = express();
import { login, signup } from './controllers/authController';
import { validateLogin, validateSignup } from './middleware/userValidation';
import { adminCheck } from './middleware/adminCheck';

const port = process.env.PORT || 4000;

app.use(express.json());

app.get('/api/protected', adminCheck, (req, res) =>{
    res.send("This is a protected route")
})

app.post('/api/users/signup', validateSignup, signup);
app.post('/api/users/login', validateLogin, login);

app.listen(port, ()=>{
    console.log(`Server is running on http://localhost:${port}`)
})