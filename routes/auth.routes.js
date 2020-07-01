const {Router, response} = require('express')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const config = require('config')
const {check, validationResult} = require('express-validator')
const User = require('../models/User')
const router = Router()


// /api/auth/register
router.post(
    '/register',
    [
        check('email', 'Invalid email').isEmail(),
        check('password', 'Minimal length is 6 symbols').isLength({ min: 6 })
    ],
    async(req, res) => {
        try {

            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    errors: errors.array(), 
                    message: 'Invalid data on registration' 
                })
            }
            const {email, password} = req.body

            const candidate = await User.findOne({ email })

            if (candidate) {
                return res.status(400).json({ message: 'User with this email is already been here' })
            }

            const hashedPassword = await bcrypt.hash(password, 12)
            const user = new User({ email, password: hashedPassword })

            await user.save()

            res.status(201).json({ message: 'User created' })

        } catch (e) {
            res.status(500).json({ message: 'Sometsing went wrong, try again'})
        }
})

// /api/auth/login
router.post(
    '/login', 
    [
        check('email', 'Enter correct email').isEmail(),
        check('password', 'Enter password').exists()
    ],
    async(req, res) => {
        try {
            const errors = validationResult(req)

            if (!errors.isEmpty()) {
                return res.status(400).json({ 
                    errors: errors.array(), 
                    message: 'Invalid data on login in system' 
                })
            }
            
            const {email, password} = req.body

            const user = await User.findOne({ email })

            if (!user) {
                return res.status(400).json({ message: 'Can\'t find user' })
            }

            const isMatch = await bcrypt.compare(password, user.password)

            if(!isMatch) {
                return res.status(400).json({ message: 'Invalid password try again' })
            }

            const token = jwt.sign(
                { userId: user.id },
                config.get('jwtSecret'),
                { expiresIn: '1h' }
            )

            res.json({token, userId: user.id })

        } catch (e) {
            res.status(500).json({ message: 'Sometsing went wrong, try again'})
        }
})

module.exports = router