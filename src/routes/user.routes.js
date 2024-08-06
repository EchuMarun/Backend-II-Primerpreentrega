import { Router } from 'express';
import passport from 'passport';
import userDao from '../dao/user.dao.js';
import { comparePassword } from '../utils/hashPassword.js';
import { createToken } from '../utils/jwt.js';

const router = Router();

router.post('/register', passport.authenticate('register'), async (req, res) => {
  res.status(201).json({ status: 'success', message: req.user });
});

router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const userExist = await userDao.findUser({ email: email });
    if (!userExist || !comparePassword(userExist.password, password)) {
      return res.status(401).json({ status: 'error', message: 'user o password incorrect' });
    }
    const token = createToken(userExist);
    res.cookie('token', token, { httpOnly: true });
    res.status(200).json({ status: 'success', payload: userExist, token });
  } catch (error) {
    res.status(500).json({ status: 'error', message: 'internal server error' });
  }
});

export default router;
