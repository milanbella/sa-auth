CREATE USER IF NOT EXISTS 'sa_auth'@'localhost' IDENTIFIED BY 'sa_auth';
GRANT ALL PRIVILEGES ON sa_auth.* TO 'sa_auth'@'localhost';
