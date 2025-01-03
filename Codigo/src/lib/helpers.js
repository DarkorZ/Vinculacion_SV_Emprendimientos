const bcrypt = require('bcryptjs');

const helpers = {};//Va a tener multiples objetos que despues se pueden reutilizar

helpers.encryptPassword = async (password) => {//Recibimos la contraseña en texto plano, y lo encripta
    const salt = await bcrypt.genSalt(10);//Permite generar un hash, lo generamos 10 veces
    const hash = await bcrypt.hash(password, salt);//Cifra la contraseña y 
    return hash;//Devolvemos el cifrado
};

helpers.matchPassword = async (password, savedPassword) => {//Compara la contraseña encryptada
    try {
        return await bcrypt.compare(password, savedPassword);//Compara con lo que tengo guardado con lo que el usuario esta tratando de loguearse, y retorna el resultado
    } catch (e) {
        console.log(e);
        //Prodriamos enviar el error por un middleware ó por request.flash
    }
};

module.exports = helpers;