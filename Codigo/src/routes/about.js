const express = require('express');
const router = express.Router();

router.get('/info', (req, res) => {
    res.render('about/info');
});

module.exports = router;
