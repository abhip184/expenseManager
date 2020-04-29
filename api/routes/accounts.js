const express = require('express')
const router = express.Router();
const accountController = require ('../controllers/accountController')
const checkAuth = require('../middleware/check-auth')


router.get('/',checkAuth,accountController.getAccountsByUserId)
router.post("/",checkAuth,accountController.addAccount)
router.patch("/addFriend/:id",accountController.addFriend)
router.patch("/:id",checkAuth,checkAuth,accountController.editAccount)
router.delete("/:id",checkAuth,accountController.deleteAccount)

module.exports = router;
