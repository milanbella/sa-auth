USE sa_auth;

INSERT INTO user (id, username, email, password_hash)
VALUES
  ('11111111-1111-1111-1111-111111111111', 'alice', 'alice@example.com', '$2a$10$N9qo8uLOickgx2ZMRZoMyeIjZ3rrodpJxE.CkhRyF3.w31NbFeoDy'),
  ('22222222-2222-2222-2222-222222222222', 'bob', 'bob@example.com', '$2a$10$u1YzBlFf8gPzyy9dZYkTf.OgqS0bkkCm1cW0XkybkADVY6vwxKF82'),
  ('33333333-3333-3333-3333-333333333333', 'carol', 'carol@example.com', '$2a$10$7b7bKmQ1OtSWT8gJtIhXHu3l6cNCxYwgd0CQpZK0s8AjtKoa6Hg2W');
