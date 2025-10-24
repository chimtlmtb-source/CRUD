import express from "express";
const router = express.Router();

// Bộ nhớ tạm (RAM)
let users = [{ id: 1, name: "Linh Chi", email: "linhchi@example.com" }];

// GET all users
router.get("/", (req, res) => {
  res.json(users);
});

// GET user by id
router.get("/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ message: "User not found" });
  res.json(user);
});

// POST create
router.post("/", (req, res) => {
  const { name, email } = req.body;
  if (!name || !email)
    return res.status(400).json({ message: "Name and email required" });
  const newUser = { id: Date.now(), name, email };
  users.push(newUser);
  res.status(201).json(newUser);
});

// PUT update
router.put("/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const user = users.find((u) => u.id === id);
  if (!user) return res.status(404).json({ message: "User not found" });
  const { name, email } = req.body;
  if (name) user.name = name;
  if (email) user.email = email;
  res.json(user);
});

// DELETE
router.delete("/:id", (req, res) => {
  const id = parseInt(req.params.id);
  const exists = users.some((u) => u.id === id);
  if (!exists) return res.status(404).json({ message: "User not found" });
  users = users.filter((u) => u.id !== id);
  res.json({ message: `User ${id} deleted` });
});

export default router;
