const express = require('express');
const router = express.Router();

const { isLoggedIn } = require('../lib/auth');

const {
    getAllProducts,
    getSearchProducts,
    getPlaceProducts,
    getCategoryProducts,
    getOfferProducts,
    addToCart,
    getCart,
    maxInCart,
    minInCart,
    deleteInCart,    
    deleteCart,
    buyCart,
    errorCart
} = require('../controllers/store');

router.get('/shop', getAllProducts);
router.get('/shop/search', getSearchProducts);
router.get('/shop/place', getPlaceProducts);
router.get('/shop/category', getCategoryProducts);
router.get('/shop/offer', getOfferProducts);
router.post('/shop', addToCart);
router.get('/cart', isLoggedIn, getCart);
router.post('/cart/max', isLoggedIn, maxInCart);
router.post('/cart/min', isLoggedIn, minInCart);
router.post('/cart', isLoggedIn, deleteInCart);

router.post('/cart/delete', isLoggedIn, deleteCart);
router.post('/cart/buy', isLoggedIn, buyCart);
router.get('/cart/errorbuy', isLoggedIn, errorCart);

module.exports = router;