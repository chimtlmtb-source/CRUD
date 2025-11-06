// src/middleware/authorizeMiddleware.js
import { getAccessControl } from '../services/rbacService.js';

export const authorize = (action, resource) => {
  return (req, res, next) => {
    try {
      const ac = getAccessControl();
      const role = req.user?.role?.name || req.user?.role || 'guest';
      const permission = ac.can(role).execute(action).on(resource);

      if (!permission.granted) {
        return res
          .status(403)
          .json({ message: 'Forbidden: insufficient permissions' });
      }

      next();
    } catch (error) {
      console.error('Authorization error:', error);
      res.status(500).json({ message: 'Authorization error' });
    }
  };
};
