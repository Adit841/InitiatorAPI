const bcrypt = require("bcryptjs");

const users = [
  {
    userId: "u1",
    email: "alice@test.com",
    name: "Alice",
    phone: "9111111111",
    passwordHash: bcrypt.hashSync("test1234", 8),
    internalNotes: "flagged for review",
    role: "user",
  },
  {
    userId: "u2",
    email: "bob@test.com",
    name: "Bob",
    phone: "9222222222",
    passwordHash: bcrypt.hashSync("test1234", 8),
    internalNotes: "none",
    role: "user",
  },
];

const orders = [
  { orderId: "o1", userId: "u1", item: "Laptop", amount: 899, address: "12 MG Road" },
  { orderId: "o2", userId: "u2", item: "Phone", amount: 499, address: "45 Park Street" },
];

module.exports = { users, orders };
