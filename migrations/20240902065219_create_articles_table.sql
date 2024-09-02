-- Add migration script here

CREATE TABLE articles (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  content TEXT NOT NULL,
  created_by INTEGER,
  FOREIGN KEY (created_by) REFERENCES users(id) ON DELETE CASCADE
)
