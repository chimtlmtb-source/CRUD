import express from 'express';
import { authorize } from '../middleware/authorizeMiddleware.js';
import { getAllUsers, deleteUser } from '../controllers/adminController.js';

const router = express.Router();

router.get('/dashboard', authorize(['ADMIN', 'SELLER']), (req, res) => {
  res.json({
    message: `Welcome ${req.user.role}, this is the Admin Dashboard!`,
  });
});

router.get('/users', authorize(['ADMIN']), getAllUsers);

router.delete('/users/:id', authorize(['ADMIN']), deleteUser);

export default router;
