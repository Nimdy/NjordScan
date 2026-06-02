import mysql from "mysql2/promise";

// Single shared pool for the whole app. Connection string lives in DATABASE_URL.
const pool = mysql.createPool(
  process.env.DATABASE_URL || "mysql://root@localhost:3306/shopdash"
);

export const db = {
  async query(sql: string): Promise<any[]> {
    const [rows] = await pool.query(sql);
    return rows as any[];
  },
};
