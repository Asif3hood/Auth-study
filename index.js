const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const authRouter = require('./routes/authRoute');
const helmet = require('helmet');



const app = express();

// 1) MIDDLEWARES
app.use(helmet());
app.use(cors());
app.use(express.json());

// 2) ROUTE
app.use('/api/auth', authRouter);

// 3) MONGO DB CONNECTION
mongoose
    .connect('mongodb+srv://ansari884098:1Ui5NhLLwnS8lnEh@cluster0.hs2vpia.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0', {
        useNewUrlParser: true,
        useUnifiedTopology: true,
    })
    .then(() => console.log('Connected to MongoDB!'))
    .catch((error) => console.error('Failed to connect MongoDB:', error));

// 4) GLOBAL ERROR HANDLER
app.use((err, req, res, next) => {
    err.statusCode = err.statusCode || 500;
    err.status = err.status || 'error';

    res.status(err.statusCode).json({
        status: err.status,
        message: err.message,
    });
});

// 5) SERVER
const PORT = 3000;
app.listen(PORT, () => {
    console.log(`App running on port ${PORT}`);
});
