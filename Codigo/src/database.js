const mysql = require('mysql');
const { promisify } = require('util');//Permite convertir codigo de callbacks a codigo de promesas

const { database } = require('./keys');

const pool = mysql.createPool(database);

pool.getConnection((err, connection) => {
    if (err) {
        if (err.code === 'PROTOCOL_CONNECTION_LOST') {
            console.error('DATABASE CONNECTION WAS CLOSED');
        }
        if (err.code === 'ER_CON_COUNT_ERROR') {
            console.error('DATABASE HAS TO MANY CONNECTIONS');
        }
        if (err.code === 'ECONNREFUSED') {
            console.error('DATABASE CONNECTION WAS REFUSE');
        }
    }

    if (connection) connection.release();
    console.log('DB is Connected');
    return;

});

//Promisify Pool Querys
pool.query = promisify(pool.query);//Transforma a promesas y almacena cada ves que hace las consultas a BD

module.exports = pool;