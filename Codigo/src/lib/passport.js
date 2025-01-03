const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;
const bcrypt = require('bcrypt');
//Autenticacion de manera local

const pool = require('../database');//Llamamos a la base

const cloudinary = require('cloudinary').v2;
cloudinary.config({
    cloud_name: 'drwpai0vu',
    api_key: '942431336444345',
    api_secret: '2F20lvuOg14-P-2zBCqBZsY8S20'
});

const fs = require('fs-extra');



passport.use('local.signin', new LocalStrategy({
    usernameField: 'email',
    passwordField: 'password',
    passReqToCallback: true
}, async (req, email, password, done) => {
    var today = new Date();
    const loginDate = today.getFullYear() + "-" + (today.getMonth() + 1) + "-" + today.getDate();
    const loginHour = today.getHours() + ':' + today.getMinutes() + ':' + today.getSeconds();
    const userLogin = loginDate + ' ' + loginHour;

    const rows = await pool.query('SELECT * FROM PERSONA WHERE PERSONA_EMAIL = ?', [email]);

    if (rows.length > 0) {
        const user = rows[0];
        const isPasswordValid = await bcrypt.compare(password, user.PERSONA_CONTRASENA);

        if (isPasswordValid) {
            await pool.query('UPDATE PERSONA SET PERSONA_LOGIN = ? WHERE PERSONA_EMAIL = ?', [userLogin, email]);
            done(null, user, req.flash('success', 'Bienvenido ' + user.PERSONA_NOMBRE));
        } else {
            done(null, false, req.flash('message', 'Contraseña incorrecta'));
        }
    } else {
        done(null, false, req.flash('message', 'El usuario ' + email + ' no existe'));
    }
}));

//SINGUP
passport.use('local.signup', new LocalStrategy({
    usernameField: 'PERSONA_EMAIL',
    passwordField: 'PERSONA_CONTRASENA',
    passReqToCallback: true // Permite ingresar más datos
}, async (req, PERSONA_EMAIL, PERSONA_CONTRASENA, done) => {
    var today = new Date();
    const loginDate = today.getFullYear() + "-" + (today.getMonth() + 1) + "-" + today.getDate();
    const loginHour = today.getHours() + ':' + today.getMinutes() + ':' + today.getSeconds();
    const userLogin = loginDate + ' ' + loginHour;
    const { DIRECCION_ID, ROL_ID, PERSONA_NOMBRE, PERSONA_TELEFONO, PERSONA_ESTADO, PERSONA_LOGIN, PERSONA_IMAGEN, PERSONA_URL } = req.body;
    const rows = await pool.query('SELECT * FROM PERSONA WHERE PERSONA_EMAIL = ?', [PERSONA_EMAIL]);

    if (rows.length > 0) {
        done(null, false, req.flash('message', 'El correo ' + PERSONA_EMAIL + ' ya existe'));
    } else {
        const newUser = {
            DIRECCION_ID,
            ROL_ID,
            PERSONA_NOMBRE,
            PERSONA_TELEFONO,
            PERSONA_EMAIL,
            PERSONA_CONTRASENA,
            PERSONA_ESTADO,
            PERSONA_LOGIN,
            PERSONA_IMAGEN,
            PERSONA_URL,
        }

        newUser.ROL_ID = 2;
        // 
        newUser.PERSONA_ESTADO = 'ACTIVO';
        newUser.PERSONA_LOGIN = new Date;

        try {
            if (req.file.path) {
                const cloudImage = await cloudinary.uploader.upload(req.file.path); // Permite guardar las imagenes en cloudinary
                newUser.PERSONA_IMAGEN = cloudImage.public_id;
                newUser.PERSONA_URL = cloudImage.secure_url;
                await fs.unlink(req.file.path); // Elimina las imagenes, para que no guarden de manera local
            }
        } catch {
            const cloudImage = [];
            cloudImage.public_id = 'user_cd82yj.png';
            cloudImage.secure_url = 'https://res.cloudinary.com/drwpai0vu/image/upload/v1617070591/user_cd82yj.png';
            newUser.PERSONA_IMAGEN = cloudImage.public_id;
            newUser.PERSONA_URL = cloudImage.secure_url;
        }

        // Encriptar la contraseña antes de guardarla en la base de datos
        const saltRounds = 10; // El número de saltos que se utilizarán en el algoritmo de hashing
        try {
            const hashedPassword = await bcrypt.hash(PERSONA_CONTRASENA, saltRounds);
            newUser.PERSONA_CONTRASENA = hashedPassword;

            // Continuar con el resto del código para guardar el usuario en la base de datos
            const result = await pool.query('INSERT INTO PERSONA SET ?', [newUser]);
            console.log(result);
            newUser.PERSONA_ID = result.insertId;
            return done(null, newUser);

        } catch (error) {
            console.error('Error al encriptar la contraseña:', error);
            return done(null, false, req.flash('message', 'Error al crear la cuenta'));
        }
    }
}));




passport.serializeUser((user, done) => {//Esto permite almacenar en sesion
    done(null, user.PERSONA_ID);
});

passport.deserializeUser(async (PERSONA_ID, done) => {
    const rows = await pool.query('SELECT * FROM PERSONA WHERE PERSONA_ID = ?', [PERSONA_ID]);
    done(null, rows[0]);
});