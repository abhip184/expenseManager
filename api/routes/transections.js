const express = require('express')
const router = express.Router();
const transectionController = require ('../controllers/transectionController')
const checkAuth = require('../middleware/check-auth')

router.get('/:id',checkAuth,transectionController.getTransectionsByAccount)
router.post('/', checkAuth,transectionController.addTransection)
router.get('/balance/:id',checkAuth, transectionController.getAccountBalance)
router.patch('/:id',checkAuth,transectionController.editTransection)
router.delete('/:id',transectionController.deleteTransection)


module.exports = router;