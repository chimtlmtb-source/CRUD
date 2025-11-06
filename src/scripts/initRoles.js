import mongoose from 'mongoose';
import dotenv from 'dotenv';
import Role from '../models/roleModel.js';
import { connectDB } from '../config/db.js';

dotenv.config();
await connectDB();

const roles = [
  {
    name: 'ADMIN',
    permissions: [
      { resource: 'user', action: 'create', possession: 'any' },
      { resource: 'user', action: 'read', possession: 'any' },
      { resource: 'user', action: 'update', possession: 'any' },
      { resource: 'user', action: 'delete', possession: 'any' },
    ],
  },
  {
    name: 'SELLER',
    permissions: [
      { resource: 'product', action: 'create', possession: 'own' },
      { resource: 'product', action: 'read', possession: 'any' },
    ],
  },
  {
    name: 'BUYER',
    permissions: [{ resource: 'product', action: 'read', possession: 'any' }],
  },
];

await Role.deleteMany();
await Role.insertMany(roles);
console.log('Roles initialized');
await mongoose.connection.close();
