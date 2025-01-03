let cart = [];

module.exports = class Cart {

    static save(idProduct, product, idUser) {

        const userBuy = idUser,
            productId = idProduct.PRODUCTO_ID,
            productCategoria = product.CATEGORIA_NOMBRE,
            productPresentacion = product.PRESENTACION_NOMBRE,
            productMedida = product. MEDIDA_NOMBRE,
            productNombre = product.PRODUCTO_NOMBRE,
            productDescripcion = product.PRODUCTO_DESCRIPCION,
            productCantidad = product.PRODUCTO_CANTIDAD,
            productPrecio = product.PRODUCTO_PRECIO,
            productOferta = product.OFERTA_DESCRIPCION,
            productCaducidad = product.PRODUCTO_FECHALIMITE.toLocaleDateString(),
            productIDProductor = product.PERSONA_ID,
            productProductor = product.PERSONA_NOMBRE,
            productTelefono = product.PERSONA_TELEFONO,
            productParroquia = product.PARROQUIA,
            productEmail = product.PERSONA_EMAIL;

        // console.log('userBuy: ' + userBuy);
        // console.log('productId: ' + productId);
        // console.log('productCategoria: ' + productCategoria);
        // console.log('productPresentacion: ' + productPresentacion);
        // console.log('productMedida: ' + productMedida);
        // console.log('productNombre: ' + productNombre);
        // console.log('productDescripcion: ' + productDescripcion);
        // console.log('productPrecio: ' + productPrecio);
        // console.log('productOferta: ' + productOferta);
        // console.log('productCaducidad: ' + productCaducidad);
        // console.log('productProductor: ' + productProductor);
        // console.log('productTelefono: ' + productTelefono);
        // console.log('productParroquia: ' + productParroquia);

        const existingProductIndex = cart.find(element => element.idUser == userBuy && element.PRODUCTO_ID == productId);

        if (existingProductIndex) {
            console.log('Producto ya existente');
        } else {
            cart.push({
                idUser: userBuy,
                PRODUCTO_ID: productId,
                CATEGORIA_NOMBRE: productCategoria,
                PRESENTACION_NOMBRE: productPresentacion,
                MEDIDA_NOMBRE: productMedida,
                PRODUCTO_NOMBRE: productNombre,
                PRODUCTO_DESCRIPCION: productDescripcion,

                PRODUCTO_CANTIDAD: 1, //Base de compra, va a hacer siempre 1
                CANTIDAD_TOTAL: productCantidad, //Stock de producto ofertado
                PRECIO_UNITARIO: productPrecio, //Precio del producto
                PRODUCTO_PRECIO: productPrecio, //Precio total, cantidad * precio unitario

                OFERTA_DESCRIPCION: productOferta,
                PRODUCTO_FECHALIMITE: productCaducidad,
                PERSONA_ID: productIDProductor,
                PERSONA_NOMBRE: productProductor,
                PERSONA_TELEFONO: productTelefono,
                DIRECCION: productParroquia,
                PERSONA_EMAIL: productEmail
            });
        }
    }

    static minCart(userId, productId) {
        const isExisting = cart.findIndex(element => element.idUser == userId && element.PRODUCTO_ID == productId);
        if (isExisting >= 0) {
            const exsitingProduct = cart[isExisting];
            if (exsitingProduct.PRODUCTO_CANTIDAD > 1) {
                exsitingProduct.PRODUCTO_CANTIDAD -= 1;
                exsitingProduct.PRODUCTO_PRECIO = exsitingProduct.PRECIO_UNITARIO * exsitingProduct.PRODUCTO_CANTIDAD;
            }
        }
    }

    static maxCart(userId, productId) {
        const isExisting = cart.findIndex(element => element.idUser == userId && element.PRODUCTO_ID == productId);
        if (isExisting >= 0) {
            const exsitingProduct = cart[isExisting];
            if (exsitingProduct.PRODUCTO_CANTIDAD < exsitingProduct.CANTIDAD_TOTAL) {
                exsitingProduct.PRODUCTO_CANTIDAD += 1;
                exsitingProduct.PRODUCTO_PRECIO = exsitingProduct.PRECIO_UNITARIO * exsitingProduct.PRODUCTO_CANTIDAD;
            }
        }
    }

    static getCart(userId) {
        var products = cart.filter(function (userProduct) { return userProduct.idUser == userId; });
        return products;
    }

    static delete(userId, productId) {
        const isExisting = cart.findIndex(element => element.idUser == userId && element.PRODUCTO_ID == productId);
        if (isExisting >= 0) {
            cart.splice(isExisting, 1);
        }
    }

    static deleteCart(userId) {
        for (let i of cart) {
            var isExisting = cart.findIndex(element => element.idUser == userId && element.PRODUCTO_ID == i.PRODUCTO_ID);
            console.log('Indice: ' + isExisting);
            // cart.splice(isExisting, 1);
        }
    }
}