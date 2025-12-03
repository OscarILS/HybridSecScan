-- Código SQL vulnerable para pruebas SAST
-- Contiene malas prácticas de seguridad

-- VULNERABILIDAD 1: Usuarios con privilegios excesivos
CREATE USER 'webapp'@'%' IDENTIFIED BY 'password123';
GRANT ALL PRIVILEGES ON *.* TO 'webapp'@'%';

-- VULNERABILIDAD 2: Contraseña débil
CREATE USER 'admin'@'localhost' IDENTIFIED BY '12345';

-- VULNERABILIDAD 3: Información sensible en comentarios
-- Usuario de backup: backup_user, Contraseña: BackupPass@2024

-- VULNERABILIDAD 4: No usar prepared statements (vulnerable a SQL injection)
-- SELECT * FROM users WHERE id = ' . $_GET['id'] . '

-- VULNERABILIDAD 5: No encriptar datos sensibles
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255),
    password VARCHAR(255), -- Guardado en plaintext
    email VARCHAR(255),
    credit_card VARCHAR(20), -- Datos sensibles sin encriptación
    ssn VARCHAR(11) -- Número de seguro sin encriptación
);

-- VULNERABILIDAD 6: Sin índices en campos críticos
CREATE TABLE logs (
    id INT,
    user_id INT,
    action VARCHAR(255),
    timestamp DATETIME
);

-- VULNERABILIDAD 7: Permisos demasiado abiertos
GRANT SELECT, INSERT, UPDATE, DELETE, CREATE, DROP, ALTER 
ON vulnerable_db.* TO 'developer'@'%' IDENTIFIED BY 'dev123';

-- VULNERABILIDAD 8: No usar transacciones
INSERT INTO users (username, password) VALUES ('admin', 'pass123');
INSERT INTO users (username, password) VALUES ('user', 'pass456');
-- Si falla en medio, datos inconsistentes

-- VULNERABILIDAD 9: Sin validación en triggers
CREATE TRIGGER update_user_timestamp
AFTER UPDATE ON users
FOR EACH ROW
BEGIN
    UPDATE users SET updated_at = NOW() WHERE id = NEW.id;
END;

-- VULNERABILIDAD 10: Datos en sesiones sin seguridad
CREATE TABLE sessions (
    session_id VARCHAR(255),
    user_id INT,
    session_data TEXT -- Datos sin encriptación
);
