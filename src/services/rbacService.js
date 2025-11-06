// src/services/rbacService.js
import AccessControl from 'accesscontrol';
import Role from '../models/roleModel.js';
import Permission from '../models/permissionModel.js';

const ac = new AccessControl();

export const initRBAC = async () => {
  try {
    const roles = await Role.find().populate('permissions');
    ac.setGrants({});

    for (const role of roles) {
      if (Array.isArray(role.permissions)) {
        for (const perm of role.permissions) {
          ac.grant(role.name).execute(perm.action).on(perm.resource);
        }
      }
    }

    console.log('RBAC initialized from DB');
  } catch (err) {
    console.error('Error initializing RBAC:', err.message);
  }
};

export const getAccessControl = () => ac;
