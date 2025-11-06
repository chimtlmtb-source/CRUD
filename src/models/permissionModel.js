import mongoose from 'mongoose';

const permissionSchema = new mongoose.Schema({
  resource: { type: String, required: true },
  action: { type: String, required: true }, // read, create, update, delete
  possession: { type: String, default: 'any' }, // own, any
  description: String,
});

export default mongoose.model('Permission', permissionSchema);
