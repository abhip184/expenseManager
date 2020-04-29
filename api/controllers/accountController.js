const mongoose = require('mongoose');
const Account = require('../models/account');
const User = require('../models/user');
const Transection = require('../models/transection');

exports.addAccount = async (req, res, next) => {
    //checking if name of account is already taken by current user
    var account = await Account.find({
        accountName: req.body.accountName,
        owner: req.userAuth.id
    })
        .catch(err => {
            console.log(err);
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        });

    if (account.length >= 1) {
        return res.status(400).json({
            errorInfo:"Bad Request",
            message: "Account name exists"
        })
    }

    // creating account model
    const acc = new Account({
        _id: new mongoose.Types.ObjectId(),
        accountName: req.body.accountName,
        currentBalance: req.body.currentBalance,
        owner: req.userAuth.id
    });

    // save account
    var result = await acc.save()
        .catch(err => {
            console.log(err)
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        });

    // creating initial transection 
    const transection = new Transection({
        _id: new mongoose.Types.ObjectId(),
        to: result.owner,
        amount: result.currentBalance,
        type: "income",
        toAccount: result._id,
    });

    //save initial transection
    await transection.save()
        .catch(err => {
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        });;

    //if no error send account updated
    return res.status(201).json({
        message: "Account created !"
    })
}


exports.editAccount = async (req, res) => {
    //Getting Data from Body
    const id = req.params.id;
    const updateOps = {}
    console.log(req.body.data)
    var newdata = JSON.parse(req.body.data)
    for (const ops of newdata) {
        updateOps[ops.propName] = ops.value;
    }
    console.log(updateOps)

    //Updating Account Name
    var result = await Account.update({
        _id: id
    }, {
            $set: updateOps
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })

    console.log(result)
    res.status(200).json({
        message: "Account updated",
    })
}
exports.addFriend = async (req, res) => {
    const id = req.params.id;
    console.log(req.body.friendEmail)

    //check if friend's email exists or not
    var user = await User.find({ email: req.body.friendEmail })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })

    if (user.length <= 0) {
        return res.status(400).json({
            errorInfo:"Bad request",
            message: "Email not exists"
        })
    }

    // adding friends email to array of invites
    var result = await Account.findOneAndUpdate({
        _id: id
    }, {
            $push: {
                invites: req.body.friendEmail
            }
        })
        .catch(err => {
            console.log(err);
            res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })


    console.log(result)
    return res.status(200).json({
        message: "Friend Added",
    })

}
exports.getAccountsByUserId = async (req, res, next) => {

    const userId = req.userAuth.id;

    //checking if user is accessing own account or not 
    var ownAccounts = await Account.find({
        owner: userId
    }).sort({ 'createdAt': -1 }).populate('owner', 'email')
        .catch(err => {
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })

 
    const email = req.userAuth.email


    var friendAccounts = await Account.find({
        invites: email
    }).populate('owner')
        .catch(err => {
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })

    // rendering both accounts to dashboard
    return res.render('dashboard', {
        data: ownAccounts,
        friend: friendAccounts
    })

}

exports.deleteAccount = async (req, res, next) => {

    const accountId = req.params.id;

    await Account.remove({ _id: accountId })
        .catch(err => {
            console.log(err)
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })

    await Transection.remove({ $or: [{ toAccount: accountId }, { fromAccount: accountId }] })
        .catch(err => {
            console.log(err)
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })


    return res.status(200).json({
        message: "Account removed"
    })
}