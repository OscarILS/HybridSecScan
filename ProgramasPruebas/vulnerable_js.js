/**
 * Código JavaScript vulnerable para pruebas SAST
 * Contiene vulnerabilidades comunes
 */

// VULNERABILIDAD 1: Eval en JavaScript
function evaluateUserInput(userCode) {
  return eval(userCode); // Muy peligroso
}

// VULNERABILIDAD 2: No sanitizar HTML
function displayUserComment(comment) {
  document.getElementById('comments').innerHTML = comment; // XSS vulnerability
}

// VULNERABILIDAD 3: Credenciales hardcodeadas
const API_KEY = "sk-1234567890abcdefghijklmnop";
const DB_PASSWORD = "admin_password_123";
const JWT_SECRET = "your-secret-key-exposed";

// VULNERABILIDAD 4: Usar Math.random() para seguridad
function generateSecurityToken() {
  return Math.random().toString(36).substr(2, 9);
}

// VULNERABILIDAD 5: JSON.parse sin validación
function parseUserData(jsonString) {
  return JSON.parse(jsonString); // Puede fallar o ser malicioso
}

// VULNERABILIDAD 6: fetch sin validación de URL
async function fetchData(userUrl) {
  const response = await fetch(userUrl); // SSRF vulnerability
  return response.json();
}

// VULNERABILIDAD 7: Function constructor (similar a eval)
function createFunction(funcString) {
  return new Function(funcString); // Inyección de código
}

// VULNERABILIDAD 8: No usar Content Security Policy
function loadExternalScript(src) {
  const script = document.createElement('script');
  script.src = src; // No valida origen
  document.head.appendChild(script);
}

// VULNERABILIDAD 9: localStorage para datos sensibles
function saveUserToken(token) {
  localStorage.setItem('authToken', token); // Vulnerable a XSS
}

// VULNERABILIDAD 10: No hashear antes de send
function sendPassword(password) {
  fetch('/api/login', {
    method: 'POST',
    body: JSON.stringify({ password: password }) // Sin encriptar
  });
}

// VULNERABILIDAD 11: Expresión regular ReDoS
function validateEmail(email) {
  const regex = /^([a-zA-Z0-9]+)*@[a-zA-Z0-9]+(\.[a-zA-Z0-9]+)*$/;
  return regex.test(email); // Puede causar DoS
}

// VULNERABILIDAD 12: Comentario con información sensible
// TODO: Cambiar esta contraseña: "production_db_pass_2024"

module.exports = {
  evaluateUserInput,
  displayUserComment,
  generateSecurityToken,
  parseUserData,
  fetchData
};
