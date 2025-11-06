// src/utils/seedRoles.js
import Role from '../models/roleModel.js';
import Permission from '../models/permissionModel.js';

export const seedRoles = async () => {
  try {
    const permissions = await Permission.find();

    const find = (res, act, pos = 'any') =>
      permissions.find(
        (p) => p.resource === res && p.action === act && p.possession === pos,
      )?._id;

    const rolesData = [
      {
        name: 'ADMIN',
        permissions: permissions.map((p) => p._id),
      },
      {
        name: 'SELLER',
        permissions: [
          find('product', 'create'),
          find('product', 'read'),
          find('product', 'update'),
        ].filter(Boolean),
      },
      {
        name: 'BUYER',
        permissions: [find('product', 'read')].filter(Boolean),
      },
    ];

    for (const data of rolesData) {
      const existing = await Role.findOne({ name: data.name });
      if (!existing) {
        await Role.create(data);
        console.log(`Role "${data.name}" created`);
      }
    }

    console.log('Roles seeded successfully');
  } catch (err) {
    console.error('Error seeding roles:', err);
  }
};
