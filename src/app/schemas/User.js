import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';

const UserSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
    },
    email: {
      type: String,
      unique: true,
      required: true,
    },
    password: {
      type: String,
      required: true,
    },
    provider: {
      type: Boolean,
      required: true,
    },
  },
  {
    timestamps: true,
  }
);

UserSchema.methods.comparePassword = async function(password) {
  const checkPassword = await bcrypt.compare(password, this.password);

  return checkPassword;
};

UserSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(8);
  const hash = await bcrypt.hash(this.password, salt);
  if (hash) {
    this.password = hash;
    return next();
  }

  return next();
});

export default mongoose.model('User', UserSchema);
