import express from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import { connectDB } from './config/db.js';
import { initRBAC } from './services/rbacService.js';
import authRoutes from './routes/authRoutes.js';
import adminRoutes from './routes/adminRoutes.js';

dotenv.config();

const app = express();
app.use(cors());
app.use(express.json());

const startServer = async () => {
  await connectDB();
  await initRBAC();

  app.use('/api/auth', authRoutes);
  app.use('/api/admin', adminRoutes);

  app.get('/', (_, res) => res.json({ message: ' API running!' }));
};

startServer();

export default app;
