const dotenv = require("dotenv").config();
const express = require('express')
const mongoose = require('mongoose')
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken')

const app = express()

// Configuração do Json
app.use(express.json())

// Models
const User = require('./models/User')

// ROTA ABERTA - ROTA PÚBLICA
app.get('/', (req, res) => {
    res.status(200).json({
        msg: 'Bem vindo a API'
    })
})

// ROTA PRIVADA - INFORMAÇÕES DO USUÁRIO PELO ID
app.get("/user/:id", checarToken, async (req, res) => {

const id = req.params.id

// CHECAR SE O USUÁRIO EXISTE
const usuario = await User.findById(id, '-senha') //Para não ver a senha do usuário

if(!usuario){
    return res.status(404).json({msg: "Usuário não encontrado!"})
}

res.status(200).json({ usuario })

})

function checarToken(req, res, next){

const authHeader = req.headers['authorization']
const token = authHeader && authHeader.split(" ") [1]

if(!token){
    return res.status(401).jason({msg: "Acesso negado!"})
}

try {
    
const secret = process.env.SECRET
jwt.verify(token, secret)
next()

}
 catch (error) {
    res.status(400).json({msg: "Token inválido!"})
}

}





// Registrar usuários
app.post('/auth/register', async (req, res) => {

    const {
        nome,
        email,
        senha,
        confirmarSenha
    } = req.body;

    // validações
    if (!nome) {
        return res.status(422).json({
            msg: "O nome é obrigatório!"
        })
    }

    if (!email) {
        return res.status(422).json({
            msg: "O email é obrigatório!"
        })
    }

    if (!senha) {
        return res.status(422).json({
            msg: "A senha é obrigatório!"
        })
    }

    if (!confirmarSenha) {
        return res.status(422).json({
            msg: "A confirmação de senha é obrigatório!"
        })
    }

    if (senha !== confirmarSenha) {
        return res.status(422).json({
            msg: "As senhas são diferentes!"
        })
    }

    // Verificar se o usuário existe
    const usuarioExistente = await User.findOne({
        email: email
    })

    if (usuarioExistente) {
        return res.status(422).json({
            msg: "Por favor utilize outro email!"
        })
    }
    // Criando Senha
    const salt = await bcrypt.genSalt(12) //CRIANDO DIFICULDADE NA SENHA 
    const senhaHash = await bcrypt.hash(senha, salt)

    // Criando usuário
    const usuario = new User({
        nome,
        email,
        senha: senhaHash,
    })

    try {
        await usuario.save()

        res.status(201).json({
            msg: "Usuário criado com sucesso!"
        })

    } catch (error) {
        console.log(error)
        res.status(500).json({
            msg: "Aconteceu um erro no servidor, tente novamente mais tarde!"
        })

    }

})

// ROTA DE LOGIN
app.post("/auth/login", async (req, res) => {

    const {email, senha} = req.body 
    
     if (!email) {
        return res.status(422).json({
            msg: "O email é obrigatório!"
        })
    }

    if (!senha) {
        return res.status(422).json({
            msg: "A senha é obrigatório!"
        })}

        // VERIFICAR SE O USUÁRIO ESTA CADASTRADO NO BANCO DE DADOS
        const usuario = await User.findOne({
        email: email
    })

    if (!usuario) {
        return res.status(404).json({
            msg: "Usuário não encontrado!"
        })
    }

    // VERIFICA SE AS SENHAS SÃO IGUAIS
    const checarSenha = await bcrypt.compare(senha, usuario.senha)

    if(!checarSenha){
        return res.status(422).json({msg: "Senha inválida!"})
    }
    
    try {
        const secret = process.env.SECRET

        const token = jwt.sign({
            id: usuario._id,
        },
        secret,

        )

        res.status(200).json({msg: "Autenticação feita com sucesso!", token})
    } 
    catch (error) {
        console.log(error)
        res.status(500).json({msg: "Aconteceu um erro no servidor, tente novamente mais tarde"})
    }

})

  


// Credenciais
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS


mongoose.connect(`mongodb+srv://${dbUser}:${dbPassword}@zero21.pbjqfa7.mongodb.net/?retryWrites=true&w=majority`)
    .then(() => {
        app.listen(3000)
        console.log("Conectou ao banco!")
    })

    .catch((err) => console.log(err))