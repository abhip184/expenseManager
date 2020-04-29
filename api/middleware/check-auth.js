const jwt = require('jsonwebtoken');
module.exports = (req, res, next) => {
    try{
    var token = req.cookies.token
    const decoded = jwt.verify(token, process.env.jwtkey);
    req.userAuth = decoded;
    console.log(decoded)
    next()
    }
    catch(err)
    {
        return res.status(401).json({
            message: 'Auth failed',
            error:err,    
        })
    }
}