import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { PrismaClient } from "@prisma/client";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import nodemailer from "nodemailer";
import { addMonths, format, isBefore, parse } from "date-fns";
import { ptBR } from "date-fns/locale";

// === CONFIGURAÇÕES ===
dotenv.config();
const app = express();
const prisma = new PrismaClient();

app.use(cors());
app.use(express.json());

// === MIDDLEWARES DE AUTENTICAÇÃO ===
function ensureAuthenticated(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader) return res.status(401).json({ erro: "Token não fornecido" });

  const [, token] = authHeader.split(" ");
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ erro: "Token inválido" });
  }
}

function ensureAdmin(req, res, next) {
  if (req.user.role !== "admin") {
    return res.status(403).json({ erro: "Acesso restrito a administradores" });
  }
  next();
}

// === ROTAS AUTH ===

// Registro com verificação de e-mail
app.post("/api/auth/register", async (req, res) => {
  const { nome, email, senha } = req.body;
  try {
    const senhaHash = await bcrypt.hash(senha, 10);
    const tokenVerificacao = crypto.randomBytes(32).toString("hex");

    const novoUsuario = await prisma.usuario.create({
      data: { nome, email, senha: senhaHash, role: "cliente", tokenVerificacao }
    });

    const link = `${process.env.FRONT_URL}/verificar-email/${tokenVerificacao}`;

    const transporter = nodemailer.createTransport({
      service: "gmail",
      auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
    });

    await transporter.sendMail({
      to: email,
      subject: "Verifique seu e-mail",
      html: `<p>Olá, ${nome}!</p><p>Ative sua conta clicando abaixo:</p><a href="${link}">${link}</a>`,
    });

    res.status(201).json({ msg: "Usuário criado. Verifique seu e-mail." });
  } catch (err) {
    res.status(400).json({ erro: "Erro ao cadastrar. E-mail já existe?" });
  }
});

// Verificar e-mail
app.get("/api/auth/verificar-email/:token", async (req, res) => {
  const { token } = req.params;
  const usuario = await prisma.usuario.findFirst({ where: { tokenVerificacao: token } });
  if (!usuario) return res.status(400).json({ erro: "Token inválido" });

  await prisma.usuario.update({
    where: { id: usuario.id },
    data: { emailVerificado: true, tokenVerificacao: null },
  });

  res.json({ msg: "E-mail verificado com sucesso." });
});

// Login
app.post("/api/auth/login", async (req, res) => {
  const { email, senha } = req.body;
  const usuario = await prisma.usuario.findUnique({ where: { email } });

  if (!usuario || !(await bcrypt.compare(senha, usuario.senha))) {
    return res.status(401).json({ erro: "Credenciais inválidas" });
  }
  if (!usuario.emailVerificado) {
    return res.status(403).json({ erro: "Verifique seu e-mail antes de acessar." });
  }

  const token = jwt.sign(
    { id: usuario.id, email: usuario.email, role: usuario.role },
    process.env.JWT_SECRET
  );

  res.json({ token, role: usuario.role, user: { id: usuario.id, nome: usuario.nome, email: usuario.email } });
});

// Recuperação de senha
app.post("/api/auth/forgot-password", async (req, res) => {
  const { email } = req.body;
  const usuario = await prisma.usuario.findUnique({ where: { email } });
  if (!usuario) return res.status(404).json({ erro: "Email não encontrado" });

  const token = crypto.randomBytes(32).toString("hex");
  const expiracao = new Date(Date.now() + 60 * 60 * 1000);

  await prisma.usuario.update({
    where: { email },
    data: { tokenRecuperacao: token, tokenExpira: expiracao },
  });

  const link = `${process.env.FRONT_URL}/resetar-senha/${token}`;
  const transporter = nodemailer.createTransport({
    service: "gmail",
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
  });

  await transporter.sendMail({
    to: email,
    subject: "Redefinição de senha",
    html: `<p>Clique no link para redefinir sua senha:</p><a href="${link}">${link}</a>`,
  });

  res.json({ msg: "E-mail de recuperação enviado." });
});

// Reset de senha
app.post("/api/auth/reset-password", async (req, res) => {
  const { token, novaSenha } = req.body;
  const usuario = await prisma.usuario.findFirst({
    where: { tokenRecuperacao: token, tokenExpira: { gte: new Date() } },
  });
  if (!usuario) return res.status(400).json({ erro: "Token inválido ou expirado" });

  const senhaHash = await bcrypt.hash(novaSenha, 10);
  await prisma.usuario.update({
    where: { id: usuario.id },
    data: { senha: senhaHash, tokenRecuperacao: null, tokenExpira: null },
  });

  res.json({ msg: "Senha redefinida com sucesso." });
});

// === ROTAS PRODUTOAPLICACAO (admin + público) ===

// Listar produtos ativos
app.get("/api/produtos", async (req, res) => {
  const produtos = await prisma.produtoAplicacao.findMany({ where: { ativo: true } });
  res.json(produtos);
});

// Criar produto
app.post("/api/produtos", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { nome, descricao, taxaMensal, prazoMeses } = req.body;
  const produto = await prisma.produtoAplicacao.create({
    data: { nome, descricao, taxaMensal: Number(taxaMensal), prazoMeses: Number(prazoMeses), ativo: true },
  });
  res.status(201).json(produto);
});

// Atualizar produto
app.put("/api/produtos/:id", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { id } = req.params;
  const data = req.body;
  const atualizado = await prisma.produtoAplicacao.update({ where: { id: Number(id) }, data });
  res.json(atualizado);
});

// Alternar ativo
app.patch("/api/produtos/:id/toggle", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { id } = req.params;
  const atual = await prisma.produtoAplicacao.findUnique({ where: { id: Number(id) } });
  const upd = await prisma.produtoAplicacao.update({ where: { id: Number(id) }, data: { ativo: !atual.ativo } });
  res.json(upd);
});

// === ROTAS APLICAÇÃO (usuário) ===

// Criar aplicação
app.post("/api/aplicacoes", ensureAuthenticated, async (req, res) => {
  const { produtoId, valorAplicado } = req.body;
  const produto = await prisma.produtoAplicacao.findUnique({ where: { id: Number(produtoId) } });
  if (!produto || !produto.ativo) return res.status(400).json({ erro: "Produto indisponível" });

  const inicio = new Date();
  const fim = addMonths(inicio, produto.prazoMeses);

  const aplicacao = await prisma.aplicacao.create({
    data: {
      usuarioId: req.user.id,
      produtoId: produto.id,
      valorAplicado: Number(valorAplicado),
      dataInicio: inicio,
      dataFim: fim,
      status: "ativa",
    },
    include: { produto: true },
  });

  res.status(201).json(aplicacao);
});

// Listar aplicações do usuário
app.get("/api/aplicacoes", ensureAuthenticated, async (req, res) => {
  const apps = await prisma.aplicacao.findMany({ where: { usuarioId: req.user.id }, include: { produto: true } });
  const enriquecido = apps.map((a) => {
    const fator = Math.pow(1 + a.produto.taxaMensal, a.produto.prazoMeses);
    const valorResgate = a.valorAplicado * fator;
    return { ...a, valorResgatePrevisto: valorResgate, rendimentoPrevisto: valorResgate - a.valorAplicado };
  });
  res.json(enriquecido);
});

// Obter um produto específico por ID (público)
app.get("/api/produtos/:id", async (req, res) => {
  try {
    const id = Number(req.params.id);
    const produto = await prisma.produtoAplicacao.findUnique({
      where: { id },
    });

    if (!produto) {
      return res.status(404).json({ erro: "Produto não encontrado" });
    }

    res.json(produto);
  } catch (err) {
    console.error("Erro ao buscar produto:", err);
    res.status(500).json({ erro: "Erro ao buscar produto" });
  }
});


// Alterar status (admin)
app.patch("/api/aplicacoes/:id/status", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;
  const upd = await prisma.aplicacao.update({ where: { id: Number(id) }, data: { status } });
  res.json(upd);
});

// Projeção mensal do usuário
app.get("/api/projecao/mensal", ensureAuthenticated, async (req, res) => {
  const apps = await prisma.aplicacao.findMany({
    where: { usuarioId: req.user.id },
    include: { produto: true }
  });

  const buckets = {};
  for (const a of apps) {
    for (let m = 0; m <= a.produto.prazoMeses; m++) {
      const dataMes = addMonths(a.dataInicio, m);
      if (isBefore(a.dataFim, dataMes)) break;

      const valor = a.valorAplicado + (a.valorAplicado * a.produto.taxaMensal * m);

      const key = format(dataMes, "MMM/yyyy", { locale: ptBR });
      buckets[key] = (buckets[key] || 0) + valor;
    }
  }

  const lista = Object.entries(buckets).map(([mes, valor]) => ({ mes, valor }));
  res.json({ projecaoMensal: lista });
});


// === DASHBOARD ADMIN ===
app.get("/api/admin/dashboard", ensureAuthenticated, ensureAdmin, async (req, res) => {
  const usuarios = await prisma.usuario.count();
  const produtos = await prisma.produtoAplicacao.count();
  const aplicacoes = await prisma.aplicacao.count();
  const soma = await prisma.aplicacao.aggregate({ _sum: { valorAplicado: true } });
  res.json({ usuarios, produtos, aplicacoes, totalAplicado: soma._sum.valorAplicado || 0 });
});

// === ROOT ===
app.get("/", (req, res) => {
  res.send("✅ API Maximum rodando!");
});

// === START ===
const PORT = process.env.PORT || 3001;
app.listen(PORT, () => console.log(`Servidor rodando na porta ${PORT}`));


