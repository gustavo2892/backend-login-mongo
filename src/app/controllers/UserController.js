import * as Yup from 'yup';

import User from '../schemas/User';

class UserController {
  async store(req, res) {
    const schema = Yup.object().shape({
      name: Yup.string().required(),
      email: Yup.string()
        .email()
        .required(),
      provider: Yup.boolean().required(),
      password: Yup.string()
        .required()
        .min(6),
    });

    if (!(await schema.isValid(req.body))) {
      return res.status(400).json({ error: 'Validation fails' });
    }

    const userExists = await User.findOne({ email: req.body.email });

    if (userExists) {
      return res.status(400).json({ error: 'User already exists' });
    }

    const { id, name, email, provider } = await User.create(req.body);

    return res.json({
      id,
      name,
      email,
      provider,
    });
  }

  async update(req, res) {
    const schema = Yup.object().shape({
      name: Yup.string(),
      email: Yup.string().email(),
      provider: Yup.boolean(),
      oldPassword: Yup.string().min(6),
      password: Yup.string()
        .min(6)
        .when('oldPassword', (oldPassword, field) =>
          oldPassword ? field.required() : field
        ),
      confirmPassword: Yup.string().when('password', (password, field) =>
        password ? field.required().oneOf([Yup.ref('password')]) : field
      ),
    });

    if (!(await schema.isValid(req.body))) {
      return res.status(400).json({ error: 'Validation fails' });
    }

    const { oldPassword } = req.body;

    const user = await User.findById(req.userId);

    if (req.body.email && req.body.email !== user.email) {
      const userExists = await User.findOne({ email: req.body.email });

      if (userExists) {
        return res.status(400).json({ error: 'User already exists' });
      }
    }

    if (oldPassword && !(await user.comparePassword(oldPassword))) {
      return res.status(401).json({ error: 'Password does not match' });
    }

    await User.findByIdAndUpdate(req.userId, req.body);

    const { id, name, provider, email } = await User.findById(req.userId);

    return res.json({
      id,
      name,
      email,
      provider,
    });
  }
}

export default new UserController();
