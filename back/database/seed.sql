USE sa_auth;

INSERT INTO user (id, email, password_hash)
VALUES
  ('11111111-1111-1111-1111-111111111111', 'alice@example.com', '$2y$10$examplehashforalice___________'),
  ('22222222-2222-2222-2222-222222222222', 'bob@example.com', '$2y$10$examplehashforbob______________'),
  ('33333333-3333-3333-3333-333333333333', 'carol@example.com', '$2y$10$examplehashforcarol____________');
