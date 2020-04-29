const mongoose = require('mongoose');
const Transection = require('../models/transection');
const Account = require('../models/account')

exports.getAccountBalance = async (req, res, next) => {
    const id = req.params.id
    var incomeAmount, expenseAmount;

    //toAccount holds only incomes and fromAccount holds only expenses diffrence of them is current balance

    //finding income
    const totalIncome = await Transection.aggregate([
        { $match: { toAccount: new mongoose.Types.ObjectId(id) }, },
        { $group: { _id: { income: "$toAccount" }, subtotal: { $sum: "$amount" } } },
    ]).catch(err => {
        console.log(err);
        return res.status(500).json({
            error:err,
            message: "Server Error"
        })
    })

    //finding expense
    const totalExpense = await Transection.aggregate([
        { $match: { fromAccount: new mongoose.Types.ObjectId(id) }, },
        { $group: { _id: { income: "$fromAccount" }, subtotal: { $sum: "$amount" } } },
    ]).catch(err => {
        console.log(err);
        return res.status(500).json({
            error:err,
            message: "Server Error"
        })
    })

    //protecting from null or undefined values
    if (totalIncome.length <= 0) {
        incomeAmount = 0;
    }
    else {
        incomeAmount = totalIncome[0].subtotal
    }
    if (totalExpense.length <= 0) {
        expenseAmount = 0
    }
    else {
        expenseAmount = totalExpense[0].subtotal
    }

    const currentBalance = incomeAmount - expenseAmount;

    console.log(currentBalance + "currentBalance ")

    //updating new balance to account
    await Account.findOneAndUpdate({ _id: id }, { $set: { currentBalance: currentBalance } }, { new: true })
        .catch(err => {
            console.log(err)
            return res.status(500).json({
                message: "Error occured While updating balance",
                error: err
            })
        })


    return res.status(200).json({
        balance: currentBalance,
        accountId: id
    })

}

exports.addTransection = async (req, res, next) => {

//decide modal based on transection type 
    var transection
    if (req.body.type == "income") {
        transection = new Transection({
            _id: new mongoose.Types.ObjectId(),
            to: req.userAuth.id,
            amount: req.body.amount,
            type: req.body.type,
            category: req.body.category,
            toAccount: req.body.accountId,
        });
    }
    else if (req.body.type == "expense") {
        transection = new Transection({
            _id: new mongoose.Types.ObjectId(),
            from: req.userAuth.id,
            amount: req.body.amount,
            type: req.body.type,
            category: req.body.category,
            fromAccount: req.body.accountId,
        });
    }
    else {
        transection = new Transection({
            _id: new mongoose.Types.ObjectId(),
            to: req.body.to,
            from: req.userAuth.id,
            amount: req.body.amount,
            type: req.body.type,
            category: req.body.category,
            toAccount: req.body.toAccount,
            fromAccount: req.body.fromAccount,

        });
        console.log(req.body.fromAccount)
    }

    var result = await transection.save().catch(err => {
        console.log(err)
        return res.status(500).json({
            error: err,
            message: "Error occured while saving transection"
        })
    })
}

exports.editTransection = (req, res) => {
    const id = req.params.id;
    var newdata = JSON.parse(req.body.data)
    console.log(newdata)
    const updateOps = {}

    for (const ops of newdata) {
        updateOps[ops.propName] = ops.value;
    }
    console.log(updateOps)

    Transection.update({ _id: id }, { $set: updateOps })
        .exec()
        .then(result => {
            console.log(result)
           return res.status(200).json({
                message: "Transection updated",
            })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({
                error:err,
                message: "Server Error"
            })
        })
}


exports.getTransectionsByAccount = async (req, res, next) => {
    var id = req.params.id;
    console.log(id)
    var account = await Account.findOne({ _id: id }).populate('owner')
    .catch(err => {
        console.log(err);
        return res.status(500).json({
            message:err
        })
    })
    var accountsForOwner = await Account.find({ owner: req.userAuth.id })
    .catch(err => {
        console.log(err);
        return res.status(500).json({
            message:err
        })
    })

    Transection.find({
        $or: [
            { toAccount: new mongoose.Types.ObjectId(id) },
            { fromAccount: new mongoose.Types.ObjectId(id) }
        ]
    },
    ).sort({ 'atDate': -1 }).populate('toAccount')
        .populate('fromAccount')
        .populate('to')
        .populate('from')
        .exec()
        .then(transections => {
            var owner = false;
            if (account.owner._id == req.userAuth.id) {
                owner = true
            }
            console.log("owner")
            console.log(owner)
            console.log(transections)
            res.render('viewAccount', {
                data: transections,
                owner: owner,
                ownerInfo: account,
                accountId: id,
                currentUser: req.userAuth.id,
                accountsForOwner: accountsForOwner
            })
        })
        .catch(err => {
            console.log(err);
            return res.status(500).json({
                message: err
            })
        })

}


exports.deleteTransection = async (req, res, next) => {
    const id = req.params.id;
    const result = await Transection.remove({ _id: id }).catch(err => {
        return res.status(500).json({
            error: err,
            message: "Error occurred while deleting transection"
        })
    })
    return res.status(200).json({
        result: result,
        message: "Transection deleted"
    })
}