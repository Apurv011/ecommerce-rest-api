const mongoose = require('mongoose');

const productSchema = mongoose.Schema({
  _id: mongoose.Schema.Types.ObjectId,
  name: { type: String, required: true },
  price: { type: Number, required: true },
  colour: { type: String, required: true },
  shape: { type: String, required: true },
  materialType: { type: String, required: true },
  productImage: { type: String }
});

module.exports = mongoose.model('Product', productSchema);
