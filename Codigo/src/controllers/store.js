const pool = require('../database');
const Cart = require('../models/cart');

module.exports = {

    getAllProducts: async (req, res) => {

        const category = await pool.query('SELECT * FROM CATEGORIA');

        try {
            const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND PERSONA.PERSONA_ID NOT IN ( ? )', [req.user.PERSONA_ID]);
            res.render('store/shop', { products, category });
        } catch {
            const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA)');
            res.render('store/shop', { products, category });
        }
    },

    getSearchProducts: async (req, res) => {
        const { buscar } = req.query;

        const category = await pool.query('SELECT * FROM CATEGORIA');

        try {
            if (buscar) {
                const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND PRODUCTO.PRODUCTO_NOMBRE = ? AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND PERSONA.PERSONA_ID NOT IN ( ? )', [buscar, req.user.PERSONA_ID]);

                const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND PRODUCTO.PRODUCTO_NOMBRE = ? AND PERSONA.PERSONA_ID NOT IN ( ? )', [buscar, req.user.PERSONA_ID]);

                res.render('store/shop', { products, category, offer });
            } else {
                res.render('store/shop', { category });
            }
        } catch {
            if (buscar) {
                const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND PRODUCTO_NOMBRE = ?', [buscar]);

                const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND PRODUCTO.PRODUCTO_NOMBRE = ?', [buscar]);

                res.render('store/shop', { products, offer, category });
            } else {
                res.render('store/shop', { category, offer });
            }
        }
    },

    getPlaceProducts: async (req, res) => {
        const { DIRECCION_ID } = req.query;

        const category = await pool.query('SELECT * FROM CATEGORIA');

        try {
            if (DIRECCION_ID !== '0') {
                const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND DIRECCION.DIRECCION_ID = ? AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND PERSONA.PERSONA_ID NOT IN ( ? )', [DIRECCION_ID, req.user.PERSONA_ID]);

                const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND DIRECCION.DIRECCION_ID = ? AND PERSONA.PERSONA_ID NOT IN ( ? )', [DIRECCION_ID, req.user.PERSONA_ID]);

                res.render('store/shop', { products, offer, category });
            } else {
                res.render('store/shop', { category });
            }
        } catch {
            if (DIRECCION_ID !== '0') {
                const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND DIRECCION.DIRECCION_ID = ?', [DIRECCION_ID]);

                const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND DIRECCION.DIRECCION_ID = ?', [DIRECCION_ID]);

                res.render('store/shop', { products, offer, category });
            } else {
                res.render('store/shop', { category });
            }
        }

    },

    getCategoryProducts: async (req, res) => {
        const { CATEGORIA_ID } = req.query;
        console.log('CATEGORIA_ID: ' + CATEGORIA_ID);

        const category = await pool.query('SELECT * FROM CATEGORIA');

        try {
            if (CATEGORIA_ID) {
                const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND CATEGORIA.CATEGORIA_ID = ? AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND PERSONA.PERSONA_ID NOT IN ( ? )', [CATEGORIA_ID, req.user.PERSONA_ID]);

                const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND CATEGORIA.CATEGORIA_ID = ? AND PERSONA.PERSONA_ID NOT IN ( ? )', [CATEGORIA_ID, req.user.PERSONA_ID]);

                res.render('store/shop', { products, offer, category });
            } else {
                res.render('store/shop', { category });
            }
        } catch {
            if (CATEGORIA_ID) {
                const products = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND PRODUCTO.PRODUCTO_ID NOT IN ( SELECT OFERTA.PRODUCTO_ID FROM OFERTA) AND CATEGORIA.CATEGORIA_ID = ?', [CATEGORIA_ID]);

                const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND CATEGORIA.CATEGORIA_ID = ?', [CATEGORIA_ID]);

                res.render('store/shop', { products, offer, category });
            } else {
                res.render('store/shop', { category });
            }
        }
    },

    getOfferProducts: async (req, res) => {
        const category = await pool.query('SELECT * FROM CATEGORIA');

        try {
            const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID AND PERSONA.PERSONA_ID NOT IN ( ? )', [req.user.PERSONA_ID]);
            res.render('store/offer', { offer, category });
        } catch {
            const offer = await pool.query('SELECT * FROM PRODUCTO, CATEGORIA, PRESENTACION, PERSONA, DIRECCION, MEDIDA, OFERTA WHERE CATEGORIA.CATEGORIA_ID = PRODUCTO.CATEGORIA_ID AND PRESENTACION.PRESENTACION_ID = PRODUCTO.PRESENTACION_ID AND MEDIDA.MEDIDA_ID = PRODUCTO.MEDIDA_ID AND PERSONA.PERSONA_ID = PRODUCTO.PERSONA_ID AND PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID AND OFERTA.PRODUCTO_ID = PRODUCTO.PRODUCTO_ID');
            res.render('store/offer', { offer, category });
        }

    },

    addToCart: async (req, res) => {
        const { PRODUCTO_ID } = req.body;

        const add = await pool.query('SELECT * FROM PRODUCTO LEFT JOIN CATEGORIA ON PRODUCTO.CATEGORIA_ID = CATEGORIA.CATEGORIA_ID LEFT JOIN MEDIDA ON PRODUCTO.MEDIDA_ID = MEDIDA.MEDIDA_ID LEFT JOIN PRESENTACION ON PRODUCTO.PRESENTACION_ID = PRESENTACION.PRESENTACION_ID LEFT JOIN PERSONA ON PRODUCTO.PERSONA_ID = PERSONA.PERSONA_ID LEFT JOIN DIRECCION ON PERSONA.DIRECCION_ID = DIRECCION.DIRECCION_ID LEFT JOIN OFERTA ON PRODUCTO.PRODUCTO_ID = OFERTA.PRODUCTO_ID WHERE PRODUCTO.PRODUCTO_ID = ?', [PRODUCTO_ID]);
        const addedProduct = add[0];

        const addId = await pool.query('SELECT * FROM PRODUCTO WHERE PRODUCTO.PRODUCTO_ID = ?', [PRODUCTO_ID]);
        const productsId = addId[0];

        try {
            if (req.user.PERSONA_ID) {
                const idUser = req.user.PERSONA_ID;
                Cart.save(productsId, addedProduct, idUser);
            }
        } catch {
            req.flash('message', 'Primero Debe Iniciar Seción Para Comprar');
        }

        res.redirect('/shop');
    },

    getCart: async (req, res) => {
        const idUser = req.user.PERSONA_ID;

        const products = Cart.getCart(idUser);

        var total = products.reduce((sum, value) => (typeof value.PRODUCTO_PRECIO == "number" ? sum + value.PRODUCTO_PRECIO : sum), 0);// Sumar total productos

        var totalPrice = total.toFixed(2);

        res.render('store/cart', { products, totalPrice });
    },

    maxInCart: async (req, res) => {
        const idUser = req.user.PERSONA_ID;
        const { PRODUCTO_ID } = req.body;
        Cart.maxCart(idUser, PRODUCTO_ID);
        res.redirect('/cart');
    },

    minInCart: async (req, res) => {
        const idUser = req.user.PERSONA_ID;
        const { PRODUCTO_ID } = req.body;
        Cart.minCart(idUser, PRODUCTO_ID);
        res.redirect('/cart');
    },

    deleteInCart: async (req, res) => {
        const idUser = req.user.PERSONA_ID;
        const { PRODUCTO_ID } = req.body;
        Cart.delete(idUser, PRODUCTO_ID);
        res.redirect('/cart');
    },

    deleteCart: async (req, res) => {
        const idUser = req.user.PERSONA_ID;
        Cart.deleteCart(idUser)
        res.redirect('/');
    },

    buyCart: async (req, res) => {
        const userId = req.user.PERSONA_ID;
        let boolBuy = [];
        var today = new Date();
        console.log(today)
        const sellDate = today.getDate() + "-" + (today.getMonth() + 1) + "-" + today.getFullYear();
        console.log(sellDate)
        const products = Cart.getCart(userId);
        var total = products.reduce((sum, value) => (typeof value.PRODUCTO_PRECIO == "number" ? sum + value.PRODUCTO_PRECIO : sum), 0);// Sumar total productos
        var totalPrice = total.toFixed(2);

        const { PAGO_ID, VENTA_FECHA } = req.body;

        for (const i in products) { //Recorrer indices de productos comprados
            console.log(products[i]);
        }

        for (let i of products) {

            const addId = await pool.query('SELECT * FROM PRODUCTO WHERE PRODUCTO.PRODUCTO_ID = ?', [i.PRODUCTO_ID]);
            const productsId = addId[0];

            if (i.PRODUCTO_CANTIDAD <= productsId.PRODUCTO_CANTIDAD) {
                // boolBuy.push({ idUser: userId, ESTADO: true });
            } else {
                boolBuy.push({ idUser: userId, ESTADO: false });
            }

        }

        const isExisting = boolBuy.find(element => element.idUser == userId && element.ESTADO == false);

        if (isExisting) {
            req.flash('message', 'No se pudo realizar su compra, porque uno de los productos que deseaba comprar ya no se encuenta en stock o no posee la cantidad que usted desea comprar, por favor eliminelo de su lista de compra o modifique su cantidad');
            res.redirect('/cart/errorbuy');
        } else {
            const newSell = {
                PERSONA_ID: req.user.PERSONA_ID,
                PAGO_ID,
                VENTA_FECHA,
                VENTA_TOTAL: totalPrice
            }

            newSell.VENTA_FECHA = sellDate;

            if (!newSell.PAGO_ID) {
                newSell.PAGO_ID = '1';
            }

            console.log(newSell);

            await pool.query('INSERT INTO VENTA set ?', [newSell]);

            const row = await pool.query('SELECT MAX(VENTA_ID) AS ID FROM VENTA, PERSONA WHERE VENTA.PERSONA_ID = PERSONA.PERSONA_ID AND PERSONA.PERSONA_ID = ?', [req.user.PERSONA_ID]);
            console.log('row:', row);
            let lastSell; // definiimos el lastsell fuera del bloque IF para que este disoible en toda la funcion
            if (row.length > 0) {
                const lastId = row[0];
                lastSell = lastId.ID; //YA QUE AQUI SE DEFINIA DE MALA mANERA
                console.log('lastSell:', lastSell);
            } else {
                console.error('No se encontró un VENTA_ID para el usuario:', req.user.PERSONA_ID);
            }
            //const lastId = row[0];
            //const lastSell = lastId.id; el problema por el cual el venta_id pasaba undefined
            console.log('lastSellNUEVO:', lastSell);
            if(lastSell){ //Andiadimos una sentencia if para que ejecute el detailSell solamente si tenemos un lastSell
            for (let i of products) {
                const detailSell = {
                    VENTA_ID: lastSell,
                    PRODUCTO_ID: i.PRODUCTO_ID,
                    DETALLE_NOMBREPRODUCTO: i.PRODUCTO_NOMBRE,
                    DETALLE_OFERTA: i.OFERTA_DESCRIPCION,
                    DETALLE_CANTIDAD: i.PRODUCTO_CANTIDAD,
                    DETALLE_PRECIOUNITARIO: i.PRECIO_UNITARIO,
                    DETALLE_PRECIOTOTAL: i.PRODUCTO_PRECIO,
                    DETALLE_PRODUCTOR: i.PERSONA_ID,
                    DETALLE_DIRECCION: i.DIRECCION
                    
                }

                console.log(detailSell);

                await pool.query('INSERT INTO DETALLE_VENTA SET ?', [detailSell]);
            }

        } else {
            console.error('No se obtivo un VENTA_ID valido');
        }

            // Aplicar un update al producto comprado, restando su stock
            for (let i of products) {
                const addId = await pool.query('SELECT * FROM PRODUCTO WHERE PRODUCTO.PRODUCTO_ID = ?', [i.PRODUCTO_ID]);
                const productsId = addId[0];

                const stock = productsId.PRODUCTO_CANTIDAD - i.PRODUCTO_CANTIDAD

                await pool.query('UPDATE PRODUCTO SET PRODUCTO_CANTIDAD = ? WHERE PRODUCTO.PRODUCTO_ID = ?', [stock, i.PRODUCTO_ID]);
            }

            req.flash('success', 'Compra exitosa, por favor revise su factura');
            res.redirect('/detail/buy');
        }


    },

    errorCart: async (req, res) => {
        const userId = req.user.PERSONA_ID;
        let stockProduct = [];

        const products = Cart.getCart(userId);

        for (let i of products) {

            const addId = await pool.query('SELECT * FROM PRODUCTO WHERE PRODUCTO.PRODUCTO_ID = ?', [i.PRODUCTO_ID]);
            const productsId = addId[0];

            if (i.PRODUCTO_CANTIDAD <= productsId.PRODUCTO_CANTIDAD) {
                // boolBuy.push({ idUser: userId, ESTADO: true });
            } else {
                stockProduct.push({
                    idUser: userId,
                    PRODUCTO_NOMBRE: productsId.PRODUCTO_NOMBRE,
                    PRODUCTO_CANTIDAD: productsId.PRODUCTO_CANTIDAD,
                    CANTIDAD_ACTUAL: i.PRODUCTO_CANTIDAD
                });
            }
        }

        var productStock = stockProduct.filter(function (userProduct) { return userProduct.idUser == userId; });

        res.render('store/errorbuy', { productStock });
    }
};