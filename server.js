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

// --- ROTA 1: CADASTRO DE USUÁRIO ---
app.post('/auth/cadastro', async (req, res) => {
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

    const token = jwt.sign({ id: usuario.id }, process.env.JWT_SECRET, { expiresIn: '7d' });

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

// --- MIDDLEWARE: VERIFICA SE O USUÁRIO ESTÁ LOGADO ---
const verificarToken = (req, res, next) => {
  const token = req.header('Authorization')?.replace('Bearer ', '');

  if (!token) {
    return res.status(401).json({ erro: 'Acesso negado. Faça login para continuar.' });
  }

  try {
    const verificado = jwt.verify(token, process.env.JWT_SECRET);
    req.usuarioLogadoId = verificado.id;
    next();
  } catch (error) {
    res.status(400).json({ erro: 'Token inválido ou expirado.' });
  }
};

// --- ROTA PROTEGIDA: CADASTRAR UMA RECEITA OU DESPESA ---
app.post('/api/transacoes', verificarToken, async (req, res) => {
  const { categoria_id, tipo, valor, descricao, data_transacao } = req.body;
  const usuario_id = req.usuarioLogadoId;

  try {
    const novaTransacao = await pool.query(
      `INSERT INTO transacoes (usuario_id, categoria_id, tipo, valor, descricao, data_transacao) 
       VALUES ($1, $2, $3, $4, $5, $6) 
       RETURNING *`,
      [usuario_id, categoria_id, tipo, valor, descricao, data_transacao]
    );

    res.status(201).json({ mensagem: 'Lançamento realizado!', transacao: novaTransacao.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao salvar a transação no banco.' });
  }
});

// --- ROTA PROTEGIDA: LISTAR TRANSAÇÕES DO USUÁRIO LOGADO ---
app.get('/api/transacoes', verificarToken, async (req, res) => {
  const usuario_id = req.usuarioLogadoId;

  try {
    const transacoes = await pool.query(
      `SELECT t.*, c.nome AS categoria_nome, c.icone AS categoria_icone 
       FROM transacoes t
       JOIN categorias c ON t.categoria_id = c.id
       WHERE t.usuario_id = $1
       ORDER BY t.data_transacao DESC`,
      [usuario_id]
    );

    res.json(transacoes.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao buscar transações.' });
  }
});

// --- ROTA PROTEGIDA: BUSCAR UMA TRANSAÇÃO PELO ID ---
app.get('/api/transacoes/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.usuarioLogadoId;

  try {
    const resultado = await pool.query(
      `SELECT t.*, c.nome AS categoria_nome 
       FROM transacoes t
       JOIN categorias c ON t.categoria_id = c.id
       WHERE t.id = $1 AND t.usuario_id = $2`,
      [id, usuario_id]
    );

    if (resultado.rows.length === 0) {
      return res.status(404).json({ erro: 'Lançamento não encontrado ou não pertence a você.' });
    }

    res.json(resultado.rows[0]);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao buscar o lançamento.' });
  }
});

// --- ROTA PROTEGIDA: ATUALIZAR UMA TRANSAÇÃO ---
app.put('/api/transacoes/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.usuarioLogadoId;
  const { categoria_id, tipo, valor, descricao, data_transacao } = req.body;

  try {
    const resultado = await pool.query(
      `UPDATE transacoes 
       SET categoria_id = $1, tipo = $2, valor = $3, descricao = $4, data_transacao = $5
       WHERE id = $6 AND usuario_id = $7
       RETURNING *`,
      [categoria_id, tipo, valor, descricao, data_transacao, id, usuario_id]
    );

    if (resultado.rowCount === 0) {
      return res.status(404).json({ erro: 'Lançamento não encontrado ou não pertence a você.' });
    }

    res.json({ mensagem: 'Lançamento atualizado com sucesso!', transacao: resultado.rows[0] });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao atualizar o lançamento.' });
  }
});

// --- ROTA PROTEGIDA: EXCLUIR UMA TRANSAÇÃO ---
app.delete('/api/transacoes/:id', verificarToken, async (req, res) => {
  const { id } = req.params;
  const usuario_id = req.usuarioLogadoId;

  try {
    const resultado = await pool.query(
      'DELETE FROM transacoes WHERE id = $1 AND usuario_id = $2',
      [id, usuario_id]
    );

    if (resultado.rowCount === 0) {
      return res.status(404).json({ erro: 'Lançamento não encontrado ou não pertence a você.' });
    }

    res.json({ mensagem: 'Lançamento excluído com sucesso!' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao excluir o lançamento.' });
  }
});

// --- ROTA PROTEGIDA: LISTAR TODAS AS CATEGORIAS DISPONÍVEIS ---
app.get('/api/categorias', verificarToken, async (req, res) => {
  try {
    const categorias = await pool.query('SELECT * FROM categorias ORDER BY nome ASC');
    res.json(categorias.rows);
  } catch (error) {
    console.error(error);
    res.status(500).json({ erro: 'Erro ao buscar categorias.' });
  }
});

// Inicia o servidor
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));
