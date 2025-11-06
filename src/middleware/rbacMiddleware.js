import Role from '../models/roleModel.js';

export const rbacMiddleware = (resource, action) => {
  return async (req, res, next) => {
    try {
      if (!req.user?.role)
        return res.status(401).json({ message: 'Unauthorized' });
      const roleDoc = await Role.findOne({ name: req.user.role });
      if (!roleDoc) return res.status(403).json({ message: 'Role not found' });

      const allowed = roleDoc.permissions.some(
        (p) =>
          p.resource === resource && (p.action === action || p.action === '*'),
      );
      if (!allowed)
        return res.status(403).json({
          message: `Forbidden: Missing ${action} permission on ${resource}`,
        });
      next();
    } catch (err) {
      res
        .status(500)
        .json({ message: 'RBAC check failed', error: err.message });
    }
  };
};
