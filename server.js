const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cors = require('cors');
require('dotenv').config();

const app = express();
app.use(express.json());
app.use(cors({ origin: '*' }));

// Conexão com o banco Neon (PostgreSQL)
const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: { rejectUnauthorized: false }
});

const JWT_SECRET = process.env.JWT_SECRET || 'seu_segredo_super_seguro';

// --- MIDDLEWARE DE AUTENTICAÇÃO (PROTEÇÃO DE ROTAS) ---
const verificarToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ erro: 'Acesso negado. Token não fornecido.' });
  }

  try {
    const verificado = jwt.verify(token, JWT_SECRET);
    req.usuarioLogado = verificado; // Salva os dados do token (ex: id do usuário) na requisição
    next();
  } catch (error) {
    res.status(400).json({ erro: 'Token inválido ou expirado.' });
  }
};

// --- ROTA 1: CADASTRO DE USUÁRIO ---
app.post('/auth/register', async (req, res) => {
  const { nome, email, senha } = req.body;

  try {
    const usuarioExiste = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (usuarioExiste.rows.length > 0) {
      return res.status(400).json({ erro: 'Este e-mail já está cadastrado.' });
    }

    const salt = await bcrypt.genSalt(10);
    const senhaCriptografada = await bcrypt.hash(senha, salt);

    const novoUsuario = await pool.query(
      'INSERT INTO usuarios (nome, email, senha) VALUES ($1, $2, $3) RETURNING id, nome, email',
      [nome, email, senhaCriptografada]
    );

    res.status(201).json({ mensagem: 'Usuário cadastrado com sucesso!', usuario: novoUsuario.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro no servidor ao cadastrar.' });
  }
});

// --- ROTA 2: LOGIN DO USUÁRIO ---
app.post('/auth/login', async (req, res) => {
  const { email, senha } = req.body;

  try {
    const resultado = await pool.query('SELECT * FROM usuarios WHERE email = $1', [email]);
    if (resultado.rows.length === 0) {
      return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const usuario = resultado.rows[0];

    const senhaValida = await bcrypt.compare(senha, usuario.senha);
    if (!senhaValida) {
      return res.status(400).json({ erro: 'E-mail ou senha incorretos.' });
    }

    // Gera o token JWT incluindo o ID do usuário
    const token = jwt.sign({ id: usuario.id, email: usuario.email }, JWT_SECRET, { expiresIn: '1d' });

    res.json({
      mensagem: 'Login realizado com sucesso!',
      token,
      usuario: { id: usuario.id, nome: usuario.nome, email: usuario.email }
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro no servidor ao fazer login.' });
  }
});

// --- ROTA 3: EDIÇÃO DE REGISTRO (NOVA) ---
// O ":id" na URL indica qual usuário será editado. O middleware "verificarToken" protege a rota.
app.put('/usuarios/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const { nome, email, senha } = req.body;

  // Segurança: Garante que o usuário logado só pode editar a si mesmo
  if (parseInt(id) !== req.usuarioLogado.id) {
    return res.status(403).json({ erro: 'Você não tem permissão para editar este perfil.' });
  }

  try {
    // 1. Busca os dados atuais do usuário para saber o que mudar
    const usuarioAtual = await pool.query('SELECT * FROM usuarios WHERE id = $1', [id]);
    if (usuarioAtual.rows.length === 0) {
      return res.status(404).json({ erro: 'Usuário não encontrado.' });
    }

    // 2. Se o e-mail mudou, verifica se o novo e-mail já pertence a outra pessoa
    if (email && email !== usuarioAtual.rows[0].email) {
      const emailExiste = await pool.query('SELECT * FROM usuarios WHERE email = $1 AND id != $2', [email, id]);
      if (emailExiste.rows.length > 0) {
        return res.status(400).json({ erro: 'Este e-mail já está em uso por outro usuário.' });
      }
    }

    // 3. Define os novos valores (se não forem enviados no body, mantém os atuais)
    const novoNome = nome || usuarioAtual.rows[0].nome;
    const novoEmail = email || usuarioAtual.rows[0].email;
    
    let novaSenhaCriptografada = usuarioAtual.rows[0].senha;
    if (senha) {
      const salt = await bcrypt.genSalt(10);
      novaSenhaCriptografada = await bcrypt.hash(senha, salt);
    }

    // 4. Executa a atualização no banco de dados
    const usuarioAtualizado = await pool.query(
      'UPDATE usuarios SET nome = $1, email = $2, senha = $3 WHERE id = $4 RETURNING id, nome, email',
      [novoNome, novoEmail, novaSenhaCriptografada, id]
    );

    res.json({
      mensagem: 'Dados atualizados com sucesso!',
      usuario: usuarioAtualizado.rows[0]
    });

  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro no servidor ao atualizar dados.' });
  }
});

// Inicialização do servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
