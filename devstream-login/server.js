const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const mysql = require('mysql');
require('dotenv').config();

const app = express();
const port = 3000;

app.use(express.json());

// Configuração do banco de dados MySQL
const db = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: process.env.DB_PASSWORD,
    database: 'devstream'
});

// Conectar ao banco de dados
db.connect(err => {
    if (err) {
        console.error('Erro ao conectar ao banco de dados:', err);
        return;
    }
    console.log('Conectado ao banco de dados!');
});

// Rota de login
app.post('/login', (req, res) => {
    const { email, password } = req.body;

    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios' });
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Erro na consulta ao banco de dados:', err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
        }
        if (result.length === 0) {
            return res.status(400).json({ message: 'Usuário não encontrado' });
        }

        const user = result[0];

        bcrypt.compare(password, user.password, (err, match) => {
            if (err) {
                console.error('Erro ao comparar senha:', err);
                return res.status(500).json({ message: 'Erro interno do servidor' });
            }

            if (match) {
                const token = jwt.sign({ id: user.id, email: user.email }, process.env.JWT_SECRET, { expiresIn: '1h' });
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

    if (!email || !password) {
        return res.status(400).json({ message: 'Email e senha são obrigatórios' });
    }

    db.query('SELECT * FROM users WHERE email = ?', [email], (err, result) => {
        if (err) {
            console.error('Erro na consulta ao banco de dados:', err);
            return res.status(500).json({ message: 'Erro interno do servidor' });
        }
        if (result.length > 0) {
            return res.status(400).json({ message: 'Usuário já existe' });
        }

        bcrypt.hash(password, 10, (err, hash) => {
            if (err) {
                console.error('Erro ao criptografar a senha:', err);
                return res.status(500).json({ message: 'Erro interno do servidor' });
            }

            db.query('INSERT INTO users (email, password) VALUES (?, ?)', [email, hash], (err, result) => {
                if (err) {
                    console.error('Erro ao inserir usuário no banco de dados:', err);
                    return res.status(500).json({ message: 'Erro interno do servidor' });
                }
                res.json({ message: 'Usuário registrado com sucesso' });
            });
        });
    });
});

app.listen(port, () => {
    console.log(`Servidor rodando na porta ${port}`);
});
