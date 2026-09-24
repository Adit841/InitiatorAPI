const bcrypt = require("bcryptjs");

const users = [
  {
    userId: "u1",
    email: "aditya@test.com",
    name: "Aditya",
    phone: "9111111111",
    passwordHash: bcrypt.hashSync("test1234", 8),
    internalNotes: "flagged for review",
    role: "user",
  },
  {
    userId: "u2",
    email: "aman@test.com",
    name: "aman",
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
