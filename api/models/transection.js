const mongoose = require('mongoose');

const transectionSchema = mongoose.Schema({
    _id:mongoose.Schema.Types.ObjectId,
    from:{type: mongoose.Schema.Types.ObjectId, ref:'User'},
    to: {type: mongoose.Schema.Types.ObjectId, ref:'User'},
    amount :{type: Number, required :true},
    type:{type: String, required :true},
    category:{type: String, default:"General"},
    fromAccount:{type: mongoose.Schema.Types.ObjectId, ref:'Account'},
    toAccount:{type: mongoose.Schema.Types.ObjectId, ref:'Account',},
    atDate:{ type : Date, default: Date.now }
}).post('save', function(docs) {
    console.log(docs)
  })

module.exports = mongoose.model('Transection',transectionSchema);