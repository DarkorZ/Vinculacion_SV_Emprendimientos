const express = require('express');
const morgan = require('morgan');
const path = require('path');//Une dos directorios
const exphbs = require('express-handlebars');
const session = require('express-session');
const passport = require('passport');
const flash = require('connect-flash');
const MySQLStore = require('express-mysql-session')(session);
const multer = require('multer');
const { v4: uuidv4 } = require('uuid');

const { database } = require('./keys');//llamamos a keys el objeto database

//Initializations
const app = express();
require('./lib/passport');//Llamamos al modulo passport, para la autenticacion

// settings
app.set('port', process.env.PORT || 3004);
app.set('views', path.join(__dirname, 'views'));

app.engine('.hbs', exphbs({//Configuramos el engine
    defaultLayout: 'main',
    layoutsDir: path.join(app.get('views'), 'layouts'),
    partialsDir: path.join(app.get('views'), 'partials'),//Para reutilizar codigo
    extname: '.hbs',//Configurar extencion de los archivos, en ves de handlebars son hbs
    helpers: require('./lib/handlebars')
}));
app.set('view engine', '.hbs') //Utilizamos el engine

// Middlewares
app.use(morgan("dev"));
app.use(express.urlencoded({ extended: true }));//Para poder aceptar desde los formularios los datos que envian los usuarios, extended: false acepta solo datos string
app.use(express.json());//Pra enviar y recivir json

app.use(session({
    secret: 'tienda virtual',
    resave: false,
    saveUninitialized: false,
    store: new MySQLStore(database) //Permite guardar la seccion dentro de la base de datos
}));
app.use(flash());
app.use(passport.initialize());//Inicilaizamos passport
app.use(passport.session());

// Agregar imagenes
const storage = multer.diskStorage({
    destination: path.join(__dirname, 'public/img/uploads'),
    //destination: path.join('public/images/upload'),
    filename: (req, file, cb, filename) => {
        cb(null, uuidv4() + path.extname(file.originalname));
    }
})

app.use(multer({
    storage,
    fileFilter: (req, file, cb) => {    
        if (file.size > 2000000) {//Tamaño maximo del archivo
            cb("Peso maximo de la imagen es de 2 MB");
        }else if (file.mimetype !== "image/png" && file.mimetype !== "image/jpg" && file.mimetype !== "image/jpeg") {
            cb('Error: El archivo debe ser una imagen valida');
        } else {
            return cb(null, true);
        }
    }
}).single('SUBIR_IMAGEN'));

// Global Variables
app.use((req, res, next) => {
    app.locals.success = req.flash('success');//llamamos al mensaje de la variable success
    app.locals.message = req.flash('message');
    app.locals.user = req.user;
    next();
});

// Routes
app.use(require('./routes/index'));
app.use(require('./routes/authentication'));
app.use(require('./routes/about'));
app.use(require('./routes/store'));
app.use('/administrator', require('./routes/administrator'));
app.use('/products', require('./routes/products'));
app.use('/detail', require('./routes/detail'));

// Public
app.use(express.static(path.join(__dirname, 'public')));
// app.use(express.static(path.join(__dirname, 'public/img/uploads')));
//app.use(express.static(path.join(__dirname, 'public/img/uploads')));

app.use((req, res, next) => {
    res.status(404).send('Page Not Found(Pagina no encontrada) No puede ser');
});

app.use((req, res, next) => {
    res.status(500).send('Something Broke!(Algo salio mal) hay no');
});

// Starting the server
app.listen(app.get('port'), () => {
    console.log('Server on port', app.get('port'));
})