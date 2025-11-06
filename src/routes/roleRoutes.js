import express from 'express';
import {
  getUsers,
  getUserById,
  createUser,
  updateUser,
  deleteUser,
} from '../controllers/userController.js';
import { verifyToken } from '../middleware/authMiddleware.js';
import { authorizeMiddleware } from '../middleware/authorizeMiddleware.js';

const router = express.Router();

router.use(verifyToken);

router.get('/', authorizeMiddleware('user', 'readAny'), getUsers);

router.get('/:id', authorizeMiddleware('user', 'readOwn'), getUserById);

router.post('/', authorizeMiddleware('user', 'createAny'), createUser);

router.put('/:id', authorizeMiddleware('user', 'updateOwn'), updateUser);

router.delete('/:id', authorizeMiddleware('user', 'deleteAny'), deleteUser);

export default router;
