const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');

const app = express();
const port = 3000;

app.use(express.json());

// Configuração do banco de dados MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: 'sua_senha',
    database: 'devstream'
});

// Conectar ao banco de dados
db.connect(err => {
    if (err) throw err;
    console.log('Conectado ao banco de dados!');
});

// Rota de login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    // Verificar se o usuário existe no banco de dados
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) throw err;
        if (result.length === 0) {
            return res.status(400).json({ message: 'Usuário não encontrado' });
        }

        const user = result[0];

        // Comparar a senha enviada com a armazenada
        bcrypt.compare(password, user.password, (err, match) => {
            if (err) throw err;

            if (match) {
                // Gerar token JWT
                const token = jwt.sign({ id: user.id, email: user.email }, 'seu_segredo_jwt', { expiresIn: '1h' });
                return res.json({ message: 'Login bem-sucedido', token });
            } else {
                return res.status(400).json({ message: 'Senha incorreta' });
            }
        });
    });
});

// Rota para registrar um novo usuário
app.post('/register', (req, res) => {
    const { email, password } = req.body;

    // Verificar se o usuário já existe
    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) throw err;
        if (result.length > 0) {
            return res.status(400).json({ message: 'Usuário já existe' });
        }

        // Criptografar a senha
        bcrypt.hash(password, 10, (err, hash) => {
            if (err) throw err;

            // Inserir o usuário no banco de dados
            db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash], (err, result) => {
                if (err) throw err;
                res.json({ message: 'Usuário registrado com sucesso' });
            });
        });
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});