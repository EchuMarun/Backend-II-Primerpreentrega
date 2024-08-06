import passport from 'passport';
import local from 'passport-local';
import jwt, { ExtractJwt } from 'passport-jwt';
import envsConfig from './envs.config.js';
import userDao from '../dao/user.dao.js';
import CartManager from '../dao/cart.dao.js';
import { comparePassword, hashPassword } from '../utils/hashPassword.js';
import { cookieExtractor } from '../utils/cookieExtractor.js';

const LocalStrategy = local.Strategy;
const JWTStrategy = jwt.Strategy;

const cartManager = new CartManager();

export const initializedPassport = () => {
  passport.use(
    'register',
    new LocalStrategy({ passReqToCallback: true, usernameField: 'email' }, async (req, username, password, done) => {
      try {
        const { first_name, last_name, age } = req.body;
        const userExist = await userDao.findUser({ email: username });
        if (userExist) return done(null, false, { message: 'user already exist' });

        const cart = await cartManager.createCart();
        const newUser = {
          first_name,
          last_name,
          email: username,
          password: hashPassword(password),
          cart_id: cart._id,
          age,
        };
        const createdUser = await userDao.addUser(newUser);
        return done(null, createdUser);
      } catch (error) {
        done(error);
      }
    })
  );

  passport.use(
    'login',
    new LocalStrategy({ usernameField: 'email' }, async (username, password, done) => {
      try {
        const userExist = await userDao.findUser({ email: username });
        if (!userExist || !comparePassword(userExist.password, password)) {
          return done(null, false, { message: 'user o password incorrect' });
        }
        return done(null, userExist);
      } catch (error) {
        done(error);
      }
    })
  );

  passport.use(
    'jwt',
    new JWTStrategy(
      { jwtFromRequest: ExtractJwt.fromExtractors([cookieExtractor]), secretOrKey: envsConfig.JWT_CODE_SECRET },
      async (jwt_payload, done) => {
        try {
          const user = await userDao.findUser({ email: jwt_payload.email });
          if (user) {
            return done(null, user);
          } else {
            return done(null, false);
          }
        } catch (error) {
          done(error);
        }
      }
    )
  );

  passport.serializeUser((user, done) => {
    done(null, user._id);
  });
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await userDao.findUser({ _id: id });
      done(null, user);
    } catch (error) {
      done(error);
    }
  });
};
